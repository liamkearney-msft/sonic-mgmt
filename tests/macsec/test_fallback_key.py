"""MACsec fallback-CAK and key-rotation tests.

A MACsec port can run **two MKA participants** at once -- a *primary* CKN and a
*fallback* CKN -- that share one SecY (one transmit SC and one hardware receive
SC per peer SCI).  Exactly one participant is the *principal*: it drives the
controlled port and installs SAKs; the standby negotiates warm in the
background so failover is instant.  When the primary CA loses its last live
peer the principal repoints to the fallback with **no datapath interruption**
(the swap touches no hardware -- SCs/SAs are shared per-port state), and CAK
rotation (add new CKN as fallback -> wait live -> delete old CKN) is hitless.

Behaviour under test is defined in the fallback-CAK design; the observability
surface is ``wpa_cli ... macsec_mka_list`` (see
``tests/common/macsec/macsec_helper.get_mka_participants``).

Scope: this module focuses on the symmetric two-CKN cases that the existing
single-profile harness can provision on a live link -- T1 (both participants
up), T2 (primary->fallback failover), T3 (revertive fail-back / key-server vs
follower), T6 (hitless CAK rotation), T7 (receive-SC refcount lifecycle) and the
T9 guards / baseline regression.  The asymmetric cold-start (T4) and crossed-CKN
(T5) cases require per-end profile provisioning that the current fixtures do not
express and are intentionally left out until an asymmetric-profile fixture
exists.

Two trigger styles are covered:

* ``TestMacsecFallbackConfigDb`` drives everything through **CONFIG_DB**
  (``config macsec profile add`` for provisioning, direct ``MACSEC_PROFILE``
  field updates for fallback add/remove and CAK rotation).  This is the
  production path -- macsecmgrd translates the CONFIG_DB change into the
  underlying wpa_supplicant sequence -- and is the coverage intended for master.
* ``TestMacsecFallbackKey`` / ``TestMacsecKeyRotation`` drive the same behaviour
  directly through the wpa_supplicant control interface (``macsec_add_mka`` /
  ``macsec_del_mka`` / ``macsec_rekey``).  These exercise the control-plane API
  explicitly and are useful for validating the feature in its early phases; they
  are not expected to land on master.

The fallback CA always inherits the cipher suite (and therefore the key lengths)
of the configured profile -- mixed key lengths within one profile are not
supported.
"""
import logging
import re
import secrets
import time

import pytest
from passlib.hash import cisco_type7

from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_helper import (
    get_appl_db,
    get_ipnetns_prefix,
    get_mka_participants,
    get_participant_by_ckn,
    get_principal_ckn,
    is_key_server,
    wait_for_ckn_live,
    macsec_add_mka,
    macsec_del_mka,
    macsec_rekey,
    get_rx_sc_count,
)
from tests.common.macsec.macsec_config_helper import (
    setup_macsec_configuration,
    delete_macsec_profile,
    update_macsec_profile,
    generate_macsec_fallback_keys,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]

# Packet-loss tolerance (percent) during a principal swap / rekey. Matches the
# continuity tolerance used by the existing rekey test in test_controlplane.py.
LOSS_TOLERANCE = 1.0


def _raw_cak(type7_cak):
    """Recover the raw CAK hex from its cisco_type7 CONFIG_DB encoding.

    macsecmgrd decodes the type7-encoded CAK before handing it to
    wpa_supplicant, so any CAK we pass directly through ``wpa_cli`` (e.g. when
    re-adding a participant during a test) must be the decoded raw value.
    """
    return cisco_type7.decode(type7_cak)


def _select_sonic_ctrl_link(ctrl_links, upstream_links):
    """Return one ``(dut_port, nbr)`` control link whose neighbor is a SONiC
    host (fallback/mka_list are not supported by EOS neighbors) and that has an
    upstream IP we can ping for continuity measurement. Return ``(None, None)``
    when no such link exists.
    """
    for dut_port, nbr in ctrl_links.items():
        if isinstance(nbr["host"], EosHost):
            continue
        if dut_port not in upstream_links:
            continue
        return dut_port, nbr
    return None, None


def _start_bg_ping(duthost, dut_port, dst_ip, duration, tmp_file):
    """Launch a detached background ping across the MACsec link.

    The ping runs for ``duration`` seconds at 10 pps; running it under nohup
    keeps it alive past the SSH session so a long continuity window does not
    trip the Ansible SSH timeout (same approach as test_rekey_by_period).
    """
    duthost.shell(
        "bash -c 'sudo nohup {} ping {} -q -w {} -i 0.1 > {} &'".format(
            get_ipnetns_prefix(duthost, dut_port), dst_ip, duration, tmp_file))


def _read_ping_loss(duthost, tmp_file):
    output = duthost.command("cat {}".format(tmp_file))["stdout_lines"]
    duthost.command("rm -f {}".format(tmp_file))
    return float(re.search(r"([\d\.]+)% packet loss", output[-2]).group(1))


def _wait_principal_ckn(host, port, expected_ckn, timeout=60):
    expected = expected_ckn.lower()
    return wait_until(timeout, 2, 0,
                      lambda: get_principal_ckn(host, port) == expected)


def _wait_principal_ckn_track_max_cas(host, port, expected_ckn, timeout=60):
    """Wait for ``expected_ckn`` to become principal while recording the peak
    number of CAs seen on the KaY. The rotation redesign guarantees at most two
    coexisting CAs, so the returned max lets callers assert a transient third CA
    never leaked during the swap. Returns ``(reached, max_ca_count)``.
    """
    expected = expected_ckn.lower()
    peak = [0]

    def _check():
        peak[0] = max(peak[0], len(get_mka_participants(host, port)))
        return get_principal_ckn(host, port) == expected

    reached = wait_until(timeout, 2, 0, _check)
    return reached, peak[0]


@pytest.fixture(scope="class")
def fallback_setup(duthost, ctrl_links, upstream_links, profile_name,
                   default_priority, cipher_suite, primary_cak, primary_ckn,
                   policy, send_sci, rekey_period, tbinfo, wait_mka_establish):
    """Provision a dedicated two-CKN profile (primary + fallback) on a single
    SONiC control link, wait for both participants to negotiate, and tear the
    profile back down to the baseline on exit.

    Provisioning is done through CONFIG_DB (``config macsec profile add`` with
    the ``fallback_*`` fields); the fallback CA inherits the profile cipher
    suite so both CKNs use identical key lengths. Shared by the CONFIG_DB and
    the control-interface test classes (class-scoped, so each class gets its own
    fresh two-CKN link).
    """
    dut_port, nbr = _select_sonic_ctrl_link(ctrl_links, upstream_links)
    if dut_port is None:
        pytest.skip("No SONiC control link with an upstream IP is available "
                    "for fallback-key testing")

    ctrl_link = {dut_port: nbr}
    fb_profile = profile_name + "_FB"
    fb_cak, fb_ckn = generate_macsec_fallback_keys(cipher_suite, exclude_ckn=primary_ckn)

    setup_macsec_configuration(
        duthost, ctrl_link, fb_profile, default_priority, cipher_suite,
        primary_cak, primary_ckn, policy, send_sci, rekey_period, tbinfo,
        fallback_cak=fb_cak, fallback_ckn=fb_ckn)

    # Both the primary and the fallback participant must negotiate a live
    # peer before the two-CKN invariants can be asserted.
    assert wait_for_ckn_live(duthost, dut_port, primary_ckn, timeout=120), \
        "Primary CKN never reached live_peers>=1 after two-CKN setup"
    assert wait_for_ckn_live(duthost, dut_port, fb_ckn, timeout=120), \
        "Fallback CKN never reached live_peers>=1 after two-CKN setup"

    principal = get_participant_by_ckn(duthost, dut_port, get_principal_ckn(duthost, dut_port))
    dut_is_key_server = str(principal.get("is_key_server", "no")).lower() == "yes"

    ctx = {
        "dut_port": dut_port,
        "nbr": nbr,
        "upstream_ip": upstream_links[dut_port]["local_ipv4_addr"],
        "profile_name": fb_profile,
        "cipher_suite": cipher_suite,
        "primary_ckn": primary_ckn.lower(),
        "primary_cak": primary_cak,
        "primary_cak_raw": _raw_cak(primary_cak),
        "fallback_ckn": fb_ckn.lower(),
        "fallback_cak": fb_cak,
        "fallback_cak_raw": _raw_cak(fb_cak),
        "dut_is_key_server": dut_is_key_server,
    }
    try:
        yield ctx
    finally:
        # Revert the link to the baseline single-CA module profile and drop
        # the temporary two-CKN profile from both ends.
        setup_macsec_configuration(
            duthost, ctrl_link, profile_name, default_priority, cipher_suite,
            primary_cak, primary_ckn, policy, send_sci, rekey_period, tbinfo)
        delete_macsec_profile(duthost, fb_profile)
        delete_macsec_profile(nbr["host"], fb_profile)


def _restore_two_ca(duthost, ctx):
    """Best-effort restore of the steady two-CKN state (both CAs live, principal
    back on the primary) so class-scoped tests stay independent.
    """
    dut_port = ctx["dut_port"]
    nbr = ctx["nbr"]
    # Re-add whichever CA may have been removed on the peer during a test.
    if get_participant_by_ckn(nbr["host"], nbr["port"], ctx["primary_ckn"]) is None:
        macsec_add_mka(nbr["host"], nbr["port"], ctx["primary_ckn"],
                       ctx["primary_cak_raw"], module_ignore_errors=True)
    if get_participant_by_ckn(nbr["host"], nbr["port"], ctx["fallback_ckn"]) is None:
        macsec_add_mka(nbr["host"], nbr["port"], ctx["fallback_ckn"],
                       ctx["fallback_cak_raw"], fallback=True, module_ignore_errors=True)
    wait_for_ckn_live(duthost, dut_port, ctx["primary_ckn"], timeout=120)
    wait_for_ckn_live(duthost, dut_port, ctx["fallback_ckn"], timeout=120)


class TestMacsecFallbackKey():
    """T1/T2/T3/T7/T9 -- two-CKN (primary + fallback) behaviour on one link,
    driven directly through the wpa_supplicant control interface (early-phase
    validation; not intended for master).
    """

    def test_two_participants_up(self, duthost, fallback_setup):
        """T1 -- two participants come up; exactly one principal; the standby is
        the fallback; both eventually have a live peer; datapath is up.
        """
        dut_port = fallback_setup["dut_port"]
        nbr = fallback_setup["nbr"]
        participants = get_mka_participants(duthost, dut_port)
        assert len(participants) >= 2, \
            "Expected two MKA participants, found {}".format(len(participants))

        principals = [p for p in participants if str(p.get("is_principal")).lower() == "yes"]
        assert len(principals) == 1, \
            "Expected exactly one principal while CAs are live, found {}".format(len(principals))

        ckns = {p.get("ckn", "").lower() for p in participants}
        assert fallback_setup["primary_ckn"] in ckns
        assert fallback_setup["fallback_ckn"] in ckns

        # The non-principal participant must advertise is_fallback=yes.
        standby = [p for p in participants if str(p.get("is_principal")).lower() != "yes"]
        assert all(str(p.get("is_fallback")).lower() == "yes" for p in standby), \
            "Non-principal participant is not flagged is_fallback=yes"

        for p in participants:
            assert int(p.get("live_peers", 0)) >= 1, \
                "Participant {} has no live peer".format(p.get("ckn"))

        # Datapath is up: the DUT has installed egress+ingress SAs on the port.
        _, _, ingress_sc, egress_sa, ingress_sa = get_appl_db(
            duthost, dut_port, nbr["host"], nbr["port"])
        assert ingress_sc and egress_sa and ingress_sa, \
            "MACsec datapath not fully established on {}".format(dut_port)

    def test_primary_to_fallback_failover(self, duthost, fallback_setup):
        """T2 -- breaking the primary CA on the peer moves the principal to the
        fallback CKN with <= tolerance loss and without recreating the shared
        receive SC.
        """
        dut_port = fallback_setup["dut_port"]
        nbr = fallback_setup["nbr"]
        up_ip = fallback_setup["upstream_ip"]

        assert _wait_principal_ckn(duthost, dut_port, fallback_setup["primary_ckn"]), \
            "Principal did not start on the primary CKN"

        rx_before = get_rx_sc_count(duthost, dut_port)

        tmp_file = "/tmp/macsec_failover_ping.txt"
        window = 30
        try:
            _start_bg_ping(duthost, dut_port, up_ip, window, tmp_file)

            # Break only the primary CA by removing the primary participant on
            # the peer; the DUT's primary then loses its last live peer.
            macsec_del_mka(nbr["host"], nbr["port"], fallback_setup["primary_ckn"])

            assert _wait_principal_ckn(duthost, dut_port, fallback_setup["fallback_ckn"]), \
                "Principal did not fail over to the fallback CKN"

            # The shared receive SC must survive the swap (VS-only visibility).
            rx_after = get_rx_sc_count(duthost, dut_port)
            if rx_before is not None and rx_after is not None:
                assert rx_after == rx_before, \
                    "Receive SC count changed on failover ({} -> {})".format(rx_before, rx_after)

            time.sleep(window)
            loss = _read_ping_loss(duthost, tmp_file)
            assert loss <= LOSS_TOLERANCE, \
                "Failover packet loss {}% exceeds tolerance".format(loss)
        finally:
            _restore_two_ca(duthost, fallback_setup)

    def test_revertive_failback_to_primary(self, duthost, fallback_setup):
        """T3 / T8 -- after restoring the primary, the key server reverts the
        principal to the primary CKN; a follower simply tracks the key server.
        """
        dut_port = fallback_setup["dut_port"]
        nbr = fallback_setup["nbr"]

        assert _wait_principal_ckn(duthost, dut_port, fallback_setup["primary_ckn"]), \
            "Principal did not start on the primary CKN"

        rx_before = get_rx_sc_count(duthost, dut_port)
        try:
            # Failover first.
            macsec_del_mka(nbr["host"], nbr["port"], fallback_setup["primary_ckn"])
            assert _wait_principal_ckn(duthost, dut_port, fallback_setup["fallback_ckn"]), \
                "Principal did not fail over to the fallback CKN"

            # Restore the primary CA on the peer.
            macsec_add_mka(nbr["host"], nbr["port"], fallback_setup["primary_ckn"],
                           fallback_setup["primary_cak_raw"])
            assert wait_for_ckn_live(duthost, dut_port, fallback_setup["primary_ckn"], timeout=120), \
                "Primary CKN did not regain a live peer after restore"

            if fallback_setup["dut_is_key_server"]:
                # Revertive fail-back is the key server's responsibility.
                assert _wait_principal_ckn(duthost, dut_port, fallback_setup["primary_ckn"]), \
                    "Key-server DUT did not revert the principal to the primary CKN"
            else:
                # A follower tracks whichever CA the key server distributes on;
                # it must settle on a single principal without oscillating.
                assert get_principal_ckn(duthost, dut_port) is not None, \
                    "Follower DUT has no principal after fail-back"

            rx_after = get_rx_sc_count(duthost, dut_port)
            if rx_before is not None and rx_after is not None:
                assert rx_after == rx_before, \
                    "Receive SC count changed on fail-back ({} -> {})".format(rx_before, rx_after)
        finally:
            _restore_two_ca(duthost, fallback_setup)

    def test_delete_nonprincipal_preserves_sc(self, duthost, fallback_setup):
        """T7 -- deleting the non-principal CA must not delete the shared
        receive SC; the surviving CA keeps its datapath.
        """
        dut_port = fallback_setup["dut_port"]
        nbr = fallback_setup["nbr"]

        principal_ckn = get_principal_ckn(duthost, dut_port)
        assert principal_ckn is not None
        # Identify a non-principal CKN to delete on the DUT.
        nonprincipal = None
        for ckn in (fallback_setup["primary_ckn"], fallback_setup["fallback_ckn"]):
            if ckn != principal_ckn:
                nonprincipal = ckn
                break
        assert nonprincipal is not None, "Could not find a non-principal CA to delete"

        rx_before = get_rx_sc_count(duthost, dut_port)
        try:
            macsec_del_mka(duthost, dut_port, nonprincipal)

            # The principal is unchanged and the datapath is intact.
            assert _wait_principal_ckn(duthost, dut_port, principal_ckn), \
                "Principal changed after deleting a non-principal CA"
            assert get_participant_by_ckn(duthost, dut_port, nonprincipal) is None, \
                "Non-principal CA still present after macsec_del_mka"

            rx_after = get_rx_sc_count(duthost, dut_port)
            if rx_before is not None and rx_after is not None:
                assert rx_after == rx_before, \
                    "Shared receive SC changed when deleting a non-principal CA " \
                    "({} -> {})".format(rx_before, rx_after)

            _, _, ingress_sc, egress_sa, ingress_sa = get_appl_db(
                duthost, dut_port, nbr["host"], nbr["port"])
            assert ingress_sc and egress_sa and ingress_sa, \
                "Datapath torn down after deleting a non-principal CA"
        finally:
            _restore_two_ca(duthost, fallback_setup)

    def test_reject_duplicate_ckn(self, duthost, fallback_setup):
        """T9 -- adding a participant whose CKN already exists is rejected."""
        dut_port = fallback_setup["dut_port"]
        dup_ckn = get_principal_ckn(duthost, dut_port)
        # A duplicate CKN with an arbitrary CAK must be refused by wpa_supplicant.
        result = macsec_add_mka(duthost, dut_port, dup_ckn,
                                secrets.token_hex(16), module_ignore_errors=True)
        combined = (result.get("stdout", "") + result.get("stderr", "")).upper()
        assert result["rc"] != 0 or "FAIL" in combined, \
            "Duplicate CKN was not rejected by macsec_add_mka"
        # The participant set must be unchanged (still exactly one entry for CKN).
        matches = [p for p in get_mka_participants(duthost, dut_port)
                   if p.get("ckn", "").lower() == dup_ckn]
        assert len(matches) == 1, \
            "Duplicate CKN created a second participant entry"


class TestMacsecFallbackConfigDb():
    """Fallback provisioning, fallback removal, and hitless CAK rotation driven
    entirely through **CONFIG_DB** -- the production path, where macsecmgrd
    turns a ``MACSEC_PROFILE`` change into the underlying wpa_supplicant
    sequence. This is the coverage intended for master.

    It reuses the shared ``fallback_setup`` fixture, whose two-CKN profile is
    already provisioned via ``config macsec profile add`` (CONFIG_DB), then
    mutates the profile row in CONFIG_DB to add/remove the fallback and to
    rotate the primary CAK.
    """

    def test_configdb_two_participants_up(self, duthost, fallback_setup):
        """T1 (CONFIG_DB) -- a MACSEC_PROFILE carrying the fallback fields brings
        up two participants with exactly one principal; the standby is flagged
        is_fallback and both CKNs have a live peer.
        """
        dut_port = fallback_setup["dut_port"]
        participants = get_mka_participants(duthost, dut_port)
        assert len(participants) >= 2, \
            "CONFIG_DB fallback profile did not bring up two participants, found {}".format(
                len(participants))

        principals = [p for p in participants if str(p.get("is_principal")).lower() == "yes"]
        assert len(principals) == 1, \
            "Expected exactly one principal, found {}".format(len(principals))

        standby = [p for p in participants if str(p.get("is_principal")).lower() != "yes"]
        assert all(str(p.get("is_fallback")).lower() == "yes" for p in standby), \
            "Non-principal participant is not flagged is_fallback=yes"

        ckns = {p.get("ckn", "").lower() for p in participants}
        assert fallback_setup["primary_ckn"] in ckns
        assert fallback_setup["fallback_ckn"] in ckns
        for p in participants:
            assert int(p.get("live_peers", 0)) >= 1, \
                "Participant {} has no live peer".format(p.get("ckn"))

    @pytest.mark.xfail(
        reason="Fallback removal via the sanctioned 'config macsec profile "
               "update <profile> --remove_fallback' CLI is validated against the "
               "batched macsec-fallback-cak -testing image (swss macsecmgr "
               "hotUpdate fallback-removal fix + docker-macsec CLI 1f96f1599). "
               "Held xfail(strict=False) until that image is on the testbed; "
               "flips to XPASS there.",
        strict=False,
    )
    def test_remove_fallback_via_configdb(self, duthost, fallback_setup):
        """T7 (CONFIG_DB) -- removing the fallback with ``config macsec profile
        update <profile> --remove_fallback`` deletes the standby participant
        without disturbing the principal or the shared receive SC (macsecmgrd
        issues macsec_del_mka for the old fallback CKN -- buildimage HLD
        section 4). This is the sanctioned replacement for the raw
        fallback_cak/fallback_ckn CONFIG_DB HDEL.
        """
        dut_port = fallback_setup["dut_port"]
        nbr = fallback_setup["nbr"]
        profile = fallback_setup["profile_name"]
        fb_ckn = fallback_setup["fallback_ckn"]

        # We remove the fallback, so make sure the principal is the primary CA.
        assert _wait_principal_ckn(duthost, dut_port, fallback_setup["primary_ckn"]), \
            "Principal did not start on the primary CKN"
        rx_before = get_rx_sc_count(duthost, dut_port)
        try:
            # Remove the fallback on both ends via the sanctioned CLI -> macsecmgrd
            # deletes the standby CA.
            update_macsec_profile(duthost, profile, remove_fallback=True)
            update_macsec_profile(nbr["host"], profile, remove_fallback=True)

            assert wait_until(
                120, 2, 0,
                lambda: get_participant_by_ckn(duthost, dut_port, fb_ckn) is None), \
                "Fallback participant was not removed after clearing CONFIG_DB fields"

            # Principal unchanged, datapath intact, shared receive SC preserved.
            assert _wait_principal_ckn(duthost, dut_port, fallback_setup["primary_ckn"]), \
                "Principal changed after removing the fallback via CONFIG_DB"
            rx_after = get_rx_sc_count(duthost, dut_port)
            if rx_before is not None and rx_after is not None:
                assert rx_after == rx_before, \
                    "Receive SC count changed when removing the fallback ({} -> {})".format(
                        rx_before, rx_after)
            _, _, ingress_sc, egress_sa, ingress_sa = get_appl_db(
                duthost, dut_port, nbr["host"], nbr["port"])
            assert ingress_sc and egress_sa and ingress_sa, \
                "Datapath torn down after removing the fallback via CONFIG_DB"
        finally:
            # Restore the fallback on both ends and wait for the standby to
            # renegotiate a live peer.
            update_macsec_profile(
                duthost, profile,
                fallback_cak=fallback_setup["fallback_cak"], fallback_ckn=fb_ckn)
            update_macsec_profile(
                nbr["host"], profile,
                fallback_cak=fallback_setup["fallback_cak"], fallback_ckn=fb_ckn)
            wait_for_ckn_live(duthost, dut_port, fb_ckn, timeout=120)

    def test_cak_rotation_via_configdb(self, duthost, fallback_setup):
        """T6 (CONFIG_DB) -- rotating the primary CAK/CKN with ``config macsec
        profile update <profile> --primary_cak <cak> --primary_ckn <ckn>``
        completes hitlessly: macsecmgrd stages the new key onto the warm fallback
        slot, waits for it to converge, then retires the old primary (buildimage
        HLD section 5). The principal ends on the new CKN with <= tolerance loss
        and the shared receive SC is preserved. The redesign requires a fallback
        CA to already be live before a primary rotation is accepted.
        """
        dut_port = fallback_setup["dut_port"]
        nbr = fallback_setup["nbr"]
        profile = fallback_setup["profile_name"]
        orig_ckn = fallback_setup["primary_ckn"]
        orig_cak = fallback_setup["primary_cak"]

        assert _wait_principal_ckn(duthost, dut_port, orig_ckn), \
            "Principal did not start on the primary CKN"
        # The redesign refuses an in-place primary rotation unless a fallback CA
        # is already established; make sure the standby is live before rotating.
        assert wait_for_ckn_live(duthost, dut_port, fallback_setup["fallback_ckn"], timeout=120), \
            "Fallback CA is not live; primary rotation would be refused"

        # New primary key pair, inheriting the profile cipher suite; keep it
        # distinct from both existing CKNs on the link.
        while True:
            new_cak, new_ckn = generate_macsec_fallback_keys(
                fallback_setup["cipher_suite"], exclude_ckn=orig_ckn)
            if new_ckn.lower() != fallback_setup["fallback_ckn"]:
                break

        rx_before = get_rx_sc_count(duthost, dut_port)
        tmp_file = "/tmp/macsec_configdb_rotation_ping.txt"
        window = 60
        try:
            _start_bg_ping(duthost, dut_port, fallback_setup["upstream_ip"], window, tmp_file)

            # Stage the new primary on the neighbor first and give it a moment to
            # come up before the DUT rotates, so both ends carry the new CKN
            # before either side promotes to it and retires the old CKN. Firing
            # both ends simultaneously lets one end delete the old CA before the
            # other end's new CA is live end-to-end, which drops traffic.
            update_macsec_profile(nbr["host"], profile, primary_cak=new_cak, primary_ckn=new_ckn)
            time.sleep(15)
            update_macsec_profile(duthost, profile, primary_cak=new_cak, primary_ckn=new_ckn)

            reached, max_cas = _wait_principal_ckn_track_max_cas(
                duthost, dut_port, new_ckn, timeout=180)
            assert reached, \
                "Principal did not end on the new CKN after CONFIG_DB rotation"
            # The redesign caps coexistence at two CAs (old primary + staged new
            # primary); a third would be a regression of the remove-first flow.
            assert max_cas <= 2, \
                "KaY held more than two CAs during rotation (peak {})".format(max_cas)

            rx_after = get_rx_sc_count(duthost, dut_port)
            if rx_before is not None and rx_after is not None:
                assert rx_after == rx_before, \
                    "Receive SC count changed during CONFIG_DB CAK rotation ({} -> {})".format(
                        rx_before, rx_after)

            time.sleep(window)
            loss = _read_ping_loss(duthost, tmp_file)
            assert loss <= LOSS_TOLERANCE, \
                "CONFIG_DB CAK rotation packet loss {}% exceeds tolerance".format(loss)
        finally:
            # Rotate the primary back to the original key on both ends so the
            # shared fixture's teardown sees the expected baseline.
            update_macsec_profile(duthost, profile, primary_cak=orig_cak, primary_ckn=orig_ckn)
            update_macsec_profile(nbr["host"], profile, primary_cak=orig_cak, primary_ckn=orig_ckn)
            wait_for_ckn_live(duthost, dut_port, orig_ckn, timeout=180)


class TestMacsecKeyRotation():
    """On-demand SAK rekey and hitless CAK rotation (T6) on a single-CA link,
    driven directly through the wpa_supplicant control interface (early-phase
    validation; not intended for master).
    """

    @pytest.fixture(scope="class")
    def rotation_link(self, duthost, ctrl_links, upstream_links, wait_mka_establish):
        dut_port, nbr = _select_sonic_ctrl_link(ctrl_links, upstream_links)
        if dut_port is None:
            pytest.skip("No SONiC control link with an upstream IP is available "
                        "for key-rotation testing")
        return {"dut_port": dut_port, "nbr": nbr,
                "up_ip": upstream_links[dut_port]["local_ipv4_addr"]}

    def test_baseline_no_fallback_regression(self, duthost, rotation_link):
        """T9 baseline -- a single-CA profile behaves as before: exactly one
        participant, principal, no fallback flag.
        """
        dut_port = rotation_link["dut_port"]
        participants = get_mka_participants(duthost, dut_port)
        assert len(participants) == 1, \
            "Baseline single-CA link should have exactly one participant, found {}".format(
                len(participants))
        p = participants[0]
        assert str(p.get("is_principal")).lower() == "yes", \
            "Baseline participant is not the principal"
        assert str(p.get("is_fallback")).lower() == "no", \
            "Baseline participant is unexpectedly flagged as fallback"
        assert int(p.get("live_peers", 0)) >= 1, "Baseline participant has no live peer"

    def test_rekey_on_demand(self, duthost, rotation_link):
        """On-demand ``macsec_rekey`` refreshes the SAK under the current
        principal CKN with <= tolerance loss and without a CKN change.

        Only the elected MKA key server distributes SAKs, so the rekey must be
        issued on whichever end owns the key-server role -- issuing it on a
        follower is a no-op. We observe the resulting SAK rotation on the DUT
        regardless of which end triggered it.
        """
        dut_port = rotation_link["dut_port"]
        nbr = rotation_link["nbr"]
        principal_before = get_principal_ckn(duthost, dut_port)

        # Pick the key-server end to drive the rekey from.
        if is_key_server(duthost, dut_port):
            rekey_host, rekey_port = duthost, dut_port
        elif is_key_server(nbr["host"], nbr["port"]):
            rekey_host, rekey_port = nbr["host"], nbr["port"]
        else:
            pytest.skip("Neither end reports the MKA key-server role on this "
                        "link; cannot drive an on-demand rekey")

        _, _, _, egr_sa_before, ing_sa_before = get_appl_db(
            duthost, dut_port, nbr["host"], nbr["port"])

        tmp_file = "/tmp/macsec_rekey_ping.txt"
        window = 20
        _start_bg_ping(duthost, dut_port, rotation_link["up_ip"], window, tmp_file)
        macsec_rekey(rekey_host, rekey_port)

        def _sa_changed():
            _, _, _, egr_sa_now, ing_sa_now = get_appl_db(
                duthost, dut_port, nbr["host"], nbr["port"])
            return egr_sa_now != egr_sa_before and ing_sa_now != ing_sa_before

        assert wait_until(window, 2, 0, _sa_changed), \
            "SAK did not rotate after macsec_rekey"
        # The rekey must not change the principal CKN.
        assert get_principal_ckn(duthost, dut_port) == principal_before, \
            "Principal CKN changed during an on-demand SAK rekey"

        time.sleep(window)
        loss = _read_ping_loss(duthost, tmp_file)
        assert loss <= LOSS_TOLERANCE, \
            "On-demand rekey packet loss {}% exceeds tolerance".format(loss)

    def test_hitless_cak_rotation(self, duthost, rotation_link, primary_cak, primary_ckn):
        """T6 -- add a new CKN as fallback on both ends, wait for it to go live,
        then delete the old CKN. The principal ends on the new CKN with <=
        tolerance loss; the receive SC is never deleted; one participant remains.
        """
        dut_port = rotation_link["dut_port"]
        nbr = rotation_link["nbr"]

        old_ckn = get_principal_ckn(duthost, dut_port)
        assert old_ckn is not None, "No principal CKN on the rotation link"
        if old_ckn != primary_ckn.lower():
            pytest.skip("Rotation link is not running the module primary CKN; "
                        "cannot safely restore it afterwards")
        old_cak_raw = _raw_cak(primary_cak)
        new_ckn = secrets.token_hex(16)
        new_cak = secrets.token_hex(16)

        rx_before = get_rx_sc_count(duthost, dut_port)
        tmp_file = "/tmp/macsec_rotation_ping.txt"
        window = 30
        try:
            _start_bg_ping(duthost, dut_port, rotation_link["up_ip"], window, tmp_file)

            # Add the new CKN as a fallback participant on both ends so it can
            # negotiate warm before we retire the old CKN.
            macsec_add_mka(nbr["host"], nbr["port"], new_ckn, new_cak, fallback=True)
            macsec_add_mka(duthost, dut_port, new_ckn, new_cak, fallback=True)

            assert wait_for_ckn_live(duthost, dut_port, new_ckn, timeout=120), \
                "New CKN never reached live_peers>=1 during rotation"
            assert wait_for_ckn_live(nbr["host"], nbr["port"], new_ckn, timeout=120), \
                "Peer's new CKN never reached live_peers>=1 during rotation"

            # Retire the old CKN on both ends; CP hands off to the survivor.
            macsec_del_mka(duthost, dut_port, old_ckn)
            macsec_del_mka(nbr["host"], nbr["port"], old_ckn)

            assert _wait_principal_ckn(duthost, dut_port, new_ckn), \
                "Principal did not end on the new CKN after rotation"
            remaining = get_mka_participants(duthost, dut_port)
            assert len(remaining) == 1, \
                "Expected exactly one participant after rotation, found {}".format(len(remaining))
            assert remaining[0].get("ckn", "").lower() == new_ckn.lower()

            rx_after = get_rx_sc_count(duthost, dut_port)
            if rx_before is not None and rx_after is not None:
                assert rx_after == rx_before, \
                    "Receive SC count changed during CAK rotation ({} -> {})".format(
                        rx_before, rx_after)

            time.sleep(window)
            loss = _read_ping_loss(duthost, tmp_file)
            assert loss <= LOSS_TOLERANCE, \
                "CAK rotation packet loss {}% exceeds tolerance".format(loss)
        finally:
            # Restore the baseline CA: re-add the original CKN on both ends and
            # drop the temporary new CKN so later modules see the module profile.
            if get_participant_by_ckn(nbr["host"], nbr["port"], old_ckn) is None:
                macsec_add_mka(nbr["host"], nbr["port"], old_ckn, old_cak_raw,
                               module_ignore_errors=True)
            if get_participant_by_ckn(duthost, dut_port, old_ckn) is None:
                macsec_add_mka(duthost, dut_port, old_ckn, old_cak_raw,
                               module_ignore_errors=True)
            wait_for_ckn_live(duthost, dut_port, old_ckn, timeout=120)
            macsec_del_mka(duthost, dut_port, new_ckn, module_ignore_errors=True)
            macsec_del_mka(nbr["host"], nbr["port"], new_ckn, module_ignore_errors=True)
