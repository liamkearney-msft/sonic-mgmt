"""MACsec key rotation, driven through ``config macsec profile update``.

Two things rotate on a live MACsec link, at very different rates:

* the **SAK**, refreshed by MKA itself every ``rekey_period`` seconds. Nobody
  configures a SAK; the operator only arms the timer.
* the **CAK**, the pre-shared key an operator rolls over. That is
  ``config macsec profile update``, which replaces one of the profile's two
  CAs and leaves the other one live to carry traffic while it does.

Both are supposed to be hitless, and both are measured here the same way: a
continuous ping across the link under test, with the rotation triggered inside
the measurement window.

Everything runs through config commands. CONFIG_DB is written once when the
testbed is deployed; after that the CLI is the only supported way to change a
profile, and it is also the only thing that enforces the rules a rollover has
to obey -- which is why the rejection cases below are tested against the CLI
rather than asserted about CONFIG_DB.
"""
import logging
import time

import pytest

from tests.common.macsec.macsec_config_helper import rotate_macsec_profile_key
from tests.common.macsec.macsec_helper import (
    get_mka_participants,
    get_participant_by_ckn,
    get_principal_ckn,
    getns_prefix,
    wait_for_ckn_live,
)
from tests.common.utilities import wait_until
from tests.macsec.macsec_key_helpers import (
    LOSS_TOLERANCE,
    REKEY_INTERVAL_MAX,
    REKEY_PERIOD,
    make_dedicated_link,
    read_ping_loss,
    restore_baseline_link,
    sa_saks,
    start_bg_ping,
    wait_principal_ckn,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


def _dut_is_key_server(duthost, dut_port):
    """True when the DUT holds the key server role on ``dut_port``.

    The role is read off the participant that currently owns the port, since
    that is the one whose election result decides who distributes SAKs.
    """
    for participant in get_mka_participants(duthost, dut_port):
        if str(participant.get("is_principal")).lower() == "yes":
            return str(participant.get("is_key_server")).lower() == "yes"
    return False


@pytest.fixture(scope="module")
def rotation_link(duthost, ctrl_links, upstream_links, get_port_profile,
                  default_priority, cipher_suite, policy, send_sci,
                  rekey_period, wait_mka_establish):
    """One control link on a dedicated profile carrying a primary and a fallback.

    The fallback is not incidental: ``config macsec profile update`` refuses to
    rotate the primary key of a profile that is in use and has no standby CA,
    because there would be nothing protecting the port while the primary is
    replaced. A rotation scenario therefore only exists in the two-CA shape.
    """
    link = make_dedicated_link(
        duthost, ctrl_links, upstream_links, get_port_profile, default_priority,
        cipher_suite, policy, send_sci, rekey_period, with_fallback=True)

    assert link.settled(), \
        "Link {} did not settle on its dedicated two-CA profile".format(link.dut_port)
    assert link.wait_cas_live(), \
        "Both CAs of the dedicated profile did not negotiate a live peer"

    try:
        yield link
    finally:
        restore_baseline_link(link)


@pytest.fixture(scope="class")
def armed_rekey_link(duthost, rotation_link):
    """``rotation_link``, rekeying itself every ``REKEY_PERIOD`` seconds.

    wpa_supplicant reads the rekey period when the CA starts, so writing a new
    period to a profile that is already applied does nothing -- macsecmgrd
    hot-updates the profile without disturbing the running session. Arming it
    therefore means replacing the profile wholesale, which is the config-command
    sequence that restarts the CA as a side effect.

    The period is restored the same way on the way out, otherwise every later
    test on this link would keep rekeying underneath itself.
    """
    # Only the key server generates and distributes a SAK, so the periodic
    # refresh is driven by whichever end won the election. Some EOS releases
    # reject `mka session rekey-period` outright, which means a peer holding
    # the role cannot be armed at all and no refresh would ever be observed.
    # Skipping is honest here; asserting would report a device limitation as a
    # SONiC failure.
    if not _dut_is_key_server(duthost, rotation_link.dut_port):
        pytest.skip(
            "DUT is not the key server on {}; the periodic SAK refresh is "
            "driven by the peer, which cannot be armed".format(
                rotation_link.dut_port))

    original = rotation_link.shape["rekey_period"]
    rotation_link.apply_shape(rekey_period=REKEY_PERIOD)
    assert rotation_link.settled(), \
        "Link did not settle after arming a {}s rekey period".format(REKEY_PERIOD)
    try:
        yield rotation_link
    finally:
        rotation_link.apply_shape(rekey_period=original)
        if not rotation_link.settled():
            logger.error("Link did not settle after restoring rekey_period=%s",
                         original)


def _rotate_both_ends(link, old_ckn, new_ckn, new_cak):
    """Roll one CA over on both ends of the link.

    Both ends have to be given the new key for the CA to re-form, and the
    profile's other CA carries traffic in between, so this is what a hitless
    rollover looks like from the operator's side.
    """
    for host, _, _ in link.hosts:
        rotate_macsec_profile_key(host, link.profile_name, old_ckn, new_ckn, new_cak)


def _measure_rotation(link, old_ckn, new_ckn, new_cak, tmp_file, window=30):
    """Roll a CA over inside a continuity window and return the packet loss."""
    assert link.settled(), \
        "Link never returned to clean forwarding before the measurement window"
    start_bg_ping(link.duthost, link.dut_port, link.upstream_ip, window, tmp_file)
    _rotate_both_ends(link, old_ckn, new_ckn, new_cak)
    assert wait_for_ckn_live(link.duthost, link.dut_port, new_ckn, timeout=window), \
        "Rotated CA {} did not negotiate a live peer inside the window".format(new_ckn)
    time.sleep(window)
    return read_ping_loss(link.duthost, tmp_file)


class TestMacsecKeyRotation():
    """Rolling a CAK over on a live link, and the rules the CLI enforces."""

    def test_hitless_primary_cak_rotation(self, duthost, rotation_link):
        """Rolling the primary key over does not cost traffic.

        The whole point of the two-CA design is that a primary rollover is a
        routine operation: the fallback carries the port while the primary CA
        is torn down and rebuilt on the new key, so the link should lose no
        more than the continuity tolerance and end up principal on the new CKN.
        """
        dut_port = rotation_link.dut_port
        old_ckn = rotation_link.shape["primary_ckn"]
        old_cak = rotation_link.shape["primary_cak"]
        fb_ckn = rotation_link.shape["fallback_ckn"]
        new_cak, new_ckn = rotation_link.new_key_pair()

        try:
            loss = _measure_rotation(rotation_link, old_ckn, new_ckn, new_cak,
                                     "/tmp/macsec_primary_rotation_ping.txt")
            rotation_link.shape.update(primary_cak=new_cak, primary_ckn=new_ckn)

            assert wait_principal_ckn(duthost, dut_port, new_ckn, timeout=180), \
                "Principal did not end on the new primary CKN"
            # The rollover must touch one CA and one only.
            assert get_participant_by_ckn(duthost, dut_port, fb_ckn) is not None, \
                "Rotating the primary key removed the fallback CA"
            assert get_participant_by_ckn(duthost, dut_port, old_ckn) is None, \
                "Old primary CA is still present after the rollover"
            assert loss <= LOSS_TOLERANCE, \
                "Primary CAK rotation packet loss {}% exceeds tolerance".format(loss)
        finally:
            _rotate_both_ends(rotation_link, new_ckn, old_ckn, old_cak)
            rotation_link.shape.update(primary_cak=old_cak, primary_ckn=old_ckn)
            rotation_link.wait_cas_live()

    def test_hitless_fallback_cak_rotation(self, duthost, rotation_link):
        """Rolling the standby key over leaves the principal untouched.

        The fallback key ages like any other pre-shared key and has to be
        replaceable while the link is up. Because it is not the CA protecting
        traffic, this rollover should be invisible: same principal, same SAs,
        no loss.
        """
        dut_port = rotation_link.dut_port
        primary_ckn = rotation_link.shape["primary_ckn"]
        old_ckn = rotation_link.shape["fallback_ckn"]
        old_cak = rotation_link.shape["fallback_cak"]
        new_cak, new_ckn = rotation_link.new_key_pair()

        assert wait_principal_ckn(duthost, dut_port, primary_ckn), \
            "Principal did not start on the primary CA"

        try:
            loss = _measure_rotation(rotation_link, old_ckn, new_ckn, new_cak,
                                     "/tmp/macsec_fallback_rotation_ping.txt")
            rotation_link.shape.update(fallback_cak=new_cak, fallback_ckn=new_ckn)

            assert get_principal_ckn(duthost, dut_port) == primary_ckn.lower(), \
                "Principal changed while the fallback key was rotated"
            standby = get_participant_by_ckn(duthost, dut_port, new_ckn)
            assert standby is not None, "Rotated fallback CA is not present"
            assert str(standby.get("is_fallback")).lower() == "yes", \
                "Rotated CA did not keep the fallback role"
            assert get_participant_by_ckn(duthost, dut_port, old_ckn) is None, \
                "Old fallback CA is still present after the rollover"
            assert loss <= LOSS_TOLERANCE, \
                "Fallback CAK rotation packet loss {}% exceeds tolerance".format(loss)
        finally:
            _rotate_both_ends(rotation_link, new_ckn, old_ckn, old_cak)
            rotation_link.shape.update(fallback_cak=old_cak, fallback_ckn=old_ckn)
            rotation_link.wait_cas_live()

    def test_rotation_rejects_unsafe_keys(self, duthost, rotation_link):
        """The CLI refuses the rollovers that would drop a link.

        Each of these is a plausible operator slip that silently costs traffic
        if it goes through, so the command has to reject it before anything
        reaches CONFIG_DB:

        * re-using the old CKN -- a CA is keyed by its name, so the running
          session would keep the old CAK;
        * re-using the fallback's CKN -- that promotes the standby instead of
          rotating the primary, leaving the port on a single CA;
        * naming a CKN the profile does not have -- a request to add a key,
          which this command deliberately does not do.
        """
        primary_ckn = rotation_link.shape["primary_ckn"]
        fb_ckn = rotation_link.shape["fallback_ckn"]
        new_cak, new_ckn = rotation_link.new_key_pair()
        _, unknown_ckn = rotation_link.new_key_pair(new_ckn)

        cases = [
            (primary_ckn, primary_ckn, "different from the old_ckn"),
            (primary_ckn, fb_ckn, "different from the fallback_ckn"),
            (unknown_ckn, new_ckn, "cannot be rotated"),
        ]
        for old, new, expected in cases:
            result = duthost.command(
                "config macsec {} profile update {} --old_ckn {} --new_ckn {} "
                "--new_cak {}".format(
                    getns_prefix(duthost, rotation_link.dut_port),
                    rotation_link.profile_name, old, new, new_cak),
                module_ignore_errors=True)
            output = "{}\n{}".format(result.get("stdout", ""), result.get("stderr", ""))
            assert result["rc"] != 0, \
                "Rotation --old_ckn {} --new_ckn {} was accepted".format(old, new)
            assert expected in output, \
                "Rotation was rejected, but not for the expected reason: {}".format(
                    output.strip())

        # Every rejection has to be a no-op.
        assert rotation_link.wait_cas_live(timeout=60), \
            "A rejected rotation disturbed the link"
        assert wait_principal_ckn(duthost, rotation_link.dut_port, primary_ckn), \
            "A rejected rotation changed the principal CA"

    def test_primary_rotation_without_fallback_is_rejected(self, duthost, rotation_link):
        """A primary rollover with no standby CA to fall back on is refused.

        macsecmgrd retires the running CA before installing its replacement, so
        on a profile with no fallback there is a window where the port has no
        key at all. The CLI refuses rather than leaving a live port unprotected,
        and names the port that would have been hit.
        """
        dut_port = rotation_link.dut_port
        fb_cak = rotation_link.shape["fallback_cak"]
        fb_ckn = rotation_link.shape["fallback_ckn"]
        primary_ckn = rotation_link.shape["primary_ckn"]
        new_cak, new_ckn = rotation_link.new_key_pair()

        try:
            rotation_link.apply_shape(fallback_cak=None, fallback_ckn=None)
            assert rotation_link.settled(), \
                "Link did not settle on the single-CA profile"

            result = duthost.command(
                "config macsec {} profile update {} --old_ckn {} --new_ckn {} "
                "--new_cak {}".format(
                    getns_prefix(duthost, dut_port), rotation_link.profile_name,
                    primary_ckn, new_ckn, new_cak),
                module_ignore_errors=True)
            output = "{}\n{}".format(result.get("stdout", ""), result.get("stderr", ""))

            assert result["rc"] != 0, \
                "Rotating the only CA of a profile bound to {} was accepted".format(
                    dut_port)
            assert "no fallback key" in output, \
                "Rotation was rejected, but not for the missing fallback: {}".format(
                    output.strip())
            assert dut_port in output, \
                "Rejection did not name the port that would have been left " \
                "unprotected: {}".format(output.strip())
            assert wait_principal_ckn(duthost, dut_port, primary_ckn), \
                "A rejected rotation changed the principal CA"
        finally:
            rotation_link.apply_shape(fallback_cak=fb_cak, fallback_ckn=fb_ckn)
            rotation_link.settled()
            rotation_link.wait_cas_live()


class TestMacsecSakRekey():
    """The SAK refresh MKA runs on its own, once a rekey period is armed."""

    def test_baseline_single_ca_has_no_fallback(self, duthost, ctrl_links,
                                                rotation_link, wait_mka_establish):
        """A profile with no fallback key still behaves exactly as it always did.

        The fallback fields are optional, and every link on the testbed that
        was not moved onto a dedicated profile is running without them. This is
        the regression guard: adding the feature must not have given those
        links a second CA or changed which one is principal.

        ``rotation_link`` is taken so the one port this module did move onto a
        two-CA profile can be excluded by name, rather than the result
        depending on whether this class happened to run first.
        """
        for dut_port in ctrl_links:
            if dut_port == rotation_link.dut_port:
                continue
            participants = get_mka_participants(duthost, dut_port)
            if not participants:
                continue
            assert len(participants) == 1, \
                "Single-CA link {} has {} participants".format(
                    dut_port, len(participants))
            participant = participants[0]
            assert str(participant.get("is_principal")).lower() == "yes", \
                "Participant on {} is not the principal".format(dut_port)
            assert str(participant.get("is_fallback")).lower() != "yes", \
                "Participant on {} is flagged as a fallback CA".format(dut_port)
            assert int(participant.get("live_peers", 0)) >= 1, \
                "Participant on {} has no live peer".format(dut_port)

    def test_sak_rekey_by_period(self, duthost, armed_rekey_link):
        """A periodic SAK refresh rolls both directions without losing traffic.

        The SAK is refreshed under the current CA, so the principal CKN must
        not move. Both the egress and the ingress SA have to roll: a refresh
        the peer did not follow would show up as a one-sided change here, and
        as loss below.
        """
        link = armed_rekey_link
        dut_port = link.dut_port
        tmp_file = "/tmp/macsec_sak_rekey_ping.txt"
        window = 2 * REKEY_INTERVAL_MAX

        principal_before = get_principal_ckn(duthost, dut_port)
        egress_before = sa_saks(duthost, dut_port, "EGRESS")
        ingress_before = sa_saks(duthost, dut_port, "INGRESS")

        start_bg_ping(duthost, dut_port, link.upstream_ip, window, tmp_file)

        def _both_directions_rolled():
            return (sa_saks(duthost, dut_port, "EGRESS") != egress_before
                    and sa_saks(duthost, dut_port, "INGRESS") != ingress_before)

        assert wait_until(window, 2, 0, _both_directions_rolled), \
            "SAK did not roll within {}s of arming a {}s rekey period".format(
                window, REKEY_PERIOD)
        assert get_principal_ckn(duthost, dut_port) == principal_before, \
            "Principal CKN changed during a periodic SAK refresh"

        time.sleep(window)
        loss = read_ping_loss(duthost, tmp_file)
        assert loss <= LOSS_TOLERANCE, \
            "Periodic SAK rekey packet loss {}% exceeds tolerance".format(loss)

    def test_sak_rekey_by_period_sustained(self, duthost, armed_rekey_link):
        """Consecutive automatic refreshes stay hitless.

        One clean rekey can be luck -- the datapath only breaks when the two
        ends briefly disagree about which SAK is live, and that is a race.
        Watching the SAK advance several times under a single uninterrupted
        ping is what shows the make-before-break sequence is actually stable.
        """
        link = armed_rekey_link
        dut_port = link.dut_port
        expected_rekeys = 3
        tmp_file = "/tmp/macsec_sak_rekey_sustained_ping.txt"
        window = (expected_rekeys + 1) * REKEY_INTERVAL_MAX

        principal_before = get_principal_ckn(duthost, dut_port)
        start_bg_ping(duthost, dut_port, link.upstream_ip, window, tmp_file)

        # Sample often enough that no SAK can be installed and retired between
        # two samples and go uncounted.
        saks = set()
        deadline = time.time() + window
        while time.time() < deadline:
            saks |= sa_saks(duthost, dut_port)
            time.sleep(2)

        assert get_principal_ckn(duthost, dut_port) == principal_before, \
            "Principal CKN changed during periodic SAK refreshes"
        # n refreshes leave n+1 distinct SAKs behind, counting the one the CA
        # started with.
        assert len(saks) >= expected_rekeys + 1, \
            ("Expected at least {} rekeys in {}s with a {}s period, saw {} "
             "distinct SAKs").format(expected_rekeys, window, REKEY_PERIOD,
                                     len(saks))

        time.sleep(5)
        loss = read_ping_loss(duthost, tmp_file)
        assert loss <= LOSS_TOLERANCE, \
            "Sustained SAK rekey packet loss {}% exceeds tolerance".format(loss)
