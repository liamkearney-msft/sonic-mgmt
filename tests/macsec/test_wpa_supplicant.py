"""Direct wpa_supplicant participant and principal-ownership tests.

Production lifecycle coverage belongs in ``test_fallback_key.py`` and
``test_key_rotation.py``. This module exercises control-socket behavior that
the production CLI does not expose.
"""
import logging
import time

import pytest
from passlib.hash import cisco_type7

from tests.common.macsec.macsec_config_helper import (
    disable_macsec_port,
    enable_macsec_port,
    replace_macsec_port,
)
from tests.common.macsec.macsec_helper import (
    get_mka_participants,
    get_participant_by_ckn,
    get_principal_ckn,
    run_wpa_cli,
    wait_for_ckn_live,
    wait_principal_invariant,
)
from tests.common.utilities import wait_until
from tests.macsec.macsec_key_helpers import (
    LOSS_TOLERANCE,
    make_dedicated_link,
    make_deployed_link,
    read_ping_loss,
    restore_baseline_link,
    sa_saks,
    start_bg_ping,
    wait_link_settled,
    wait_macsec_ok,
    wait_principal_ckn,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]

OUTAGE_CYCLES = 5
PEER_EXPIRY_TIMEOUT = 30


def _participant_summary(host, port):
    """One-line rendering of every participant, for failure messages."""
    return " | ".join(
        "ckn={}.. live_peers={} principal={} elected={} key_server={}".format(
            p.get("ckn", "?")[:16], p.get("live_peers", "?"),
            p.get("is_principal", "?"), p.get("is_elected", "?"),
            p.get("is_key_server", "?"))
        for p in get_mka_participants(host, port)) or "<no participants>"


def _sa_summary(duthost, dut_port):
    """Counts of installed SAs in each direction, for failure messages."""
    return "egress_sas={} ingress_sas={}".format(
        len(sa_saks(duthost, dut_port, "EGRESS")),
        len(sa_saks(duthost, dut_port, "INGRESS")))


def _has_sas(duthost, dut_port):
    """Return whether SAs are installed in both directions."""
    return (bool(sa_saks(duthost, dut_port, "EGRESS"))
            and bool(sa_saks(duthost, dut_port, "INGRESS")))


def _peer_expired(duthost, dut_port):
    """True once no participant on the DUT still holds a live peer."""
    for participant in get_mka_participants(duthost, dut_port):
        try:
            if int(participant.get("live_peers", 0)) >= 1:
                return False
        except ValueError:
            return False
    return True


def _peer_live(duthost, dut_port):
    """True once some participant on the DUT holds a live peer again."""
    for participant in get_mka_participants(duthost, dut_port):
        try:
            if int(participant.get("live_peers", 0)) >= 1:
                return True
        except ValueError:
            continue
    return False


def _raw_cak(type7_cak):
    """Decode the CONFIG_DB representation before passing a CAK to wpa_cli."""
    return cisco_type7.decode(type7_cak)


def _macsec_add_mka(host, port, ckn, cak, fallback=False):
    """Add an MKA participant directly through the wpa control socket."""
    args = ["macsec_add_mka", "ckn={}".format(ckn), "cak={}".format(cak)]
    if fallback:
        args.append("fallback=1")
    return run_wpa_cli(host, port, *args)


def _macsec_del_mka(host, port, ckn):
    """Remove an MKA participant directly through the wpa control socket."""
    return run_wpa_cli(host, port, "macsec_del_mka", "ckn={}".format(ckn))


def _all_participants_peerless(host, port):
    participants = get_mka_participants(host, port)
    return bool(participants) and all(
        int(participant.get("live_peers", 0)) == 0
        for participant in participants)


def _no_session_stable(host, port, duration=10):
    deadline = time.time() + duration
    while time.time() < deadline:
        if (not _all_participants_peerless(host, port)
                or sa_saks(host, port, "EGRESS")
                or sa_saks(host, port, "INGRESS")):
            return False
        time.sleep(2)
    return True


def _restore_wpa_link(link):
    """Restore both participants after a direct control-socket test."""
    link.apply_shape()
    assert link.settled(), \
        "Link {} did not settle after restoring its participants".format(
            link.dut_port)
    assert link.wait_cas_live(), \
        "Link {} did not restore both configured CAs".format(link.dut_port)
    assert wait_principal_ckn(
        link.duthost, link.dut_port, link.shape["primary_ckn"]), \
        "Primary CA did not reclaim {} after restoration".format(link.dut_port)


@pytest.fixture(scope="class")
def wpa_participant_link(duthost, ctrl_links, upstream_links, get_port_profile,
                         default_priority, cipher_suite, policy, send_sci,
                         wait_mka_establish):
    """A dedicated two-CA link for direct participant tests."""
    link = make_dedicated_link(
        duthost, ctrl_links, upstream_links, get_port_profile,
        default_priority, cipher_suite, policy, send_sci, 0,
        require_sonic_peer=True)
    try:
        assert link.settled(), \
            "Link {} did not settle on its dedicated profile".format(
                link.dut_port)
        assert link.wait_cas_live(), \
            "Both CAs did not negotiate on {}".format(link.dut_port)
        yield link
    finally:
        restore_baseline_link(link)


class TestWpaSupplicantParticipants(object):
    """Participant behavior unavailable through the production config CLI."""

    def test_primary_delete_and_readd_is_hitless(self, wpa_participant_link):
        """Deleting and restoring primary moves traffic fallback and back."""
        link = wpa_participant_link
        primary_ckn = link.shape["primary_ckn"]
        fallback_ckn = link.shape["fallback_ckn"]

        assert wait_principal_ckn(link.duthost, link.dut_port, primary_ckn), \
            "Principal did not start on the primary CA"
        failover_ping = start_bg_ping(
            link.duthost, link.dut_port, link.upstream_ip, 30)
        try:
            _macsec_del_mka(
                link.nbr["host"], link.nbr["port"], primary_ckn)
            assert wait_principal_ckn(
                link.duthost, link.dut_port, fallback_ckn, timeout=15), \
                "Fallback CA did not take over after primary deletion"
            failover_loss = read_ping_loss(failover_ping)
            assert failover_loss <= LOSS_TOLERANCE, \
                "Primary deletion packet loss {}% exceeds tolerance".format(
                    failover_loss)

            failback_ping = start_bg_ping(
                link.duthost, link.dut_port, link.upstream_ip, 45)
            _macsec_add_mka(
                link.nbr["host"], link.nbr["port"], primary_ckn,
                _raw_cak(link.shape["primary_cak"]))
            assert wait_for_ckn_live(
                link.duthost, link.dut_port, primary_ckn, timeout=15), \
                "Primary CA did not become live after it was restored"
            assert wait_principal_ckn(
                link.duthost, link.dut_port, primary_ckn, timeout=15), \
                "Primary CA did not take over after it was restored"

            failback_loss = read_ping_loss(failback_ping)
            assert failback_loss <= LOSS_TOLERANCE, \
                "Primary re-add packet loss {}% exceeds tolerance".format(
                    failback_loss)
        finally:
            _restore_wpa_link(link)

    def test_fallback_only_session_forwards(self, wpa_participant_link):
        """The fallback CA can own the link when neither peer has a primary."""
        link = wpa_participant_link
        primary_ckn = link.shape["primary_ckn"]
        fallback_ckn = link.shape["fallback_ckn"]
        try:
            for host, port, _ in link.hosts:
                _macsec_del_mka(host, port, primary_ckn)

            assert wait_for_ckn_live(
                link.duthost, link.dut_port, fallback_ckn, timeout=30), \
                "Fallback-only CA did not negotiate a live peer"
            assert wait_principal_ckn(
                link.duthost, link.dut_port, fallback_ckn, timeout=30), \
                "Fallback-only CA did not become principal"
            assert wait_link_settled(
                link.duthost, link.dut_port, link.upstream_ip), \
                "Fallback-only session did not forward traffic"
        finally:
            _restore_wpa_link(link)

    def test_crossed_primary_fallback_roles_follow_key_server(
            self, wpa_participant_link):
        """Crossed roles work and key server chooses the principal."""
        link = wpa_participant_link
        primary_ckn = link.shape["primary_ckn"]
        fallback_ckn = link.shape["fallback_ckn"]
        peer = link.nbr["host"]
        peer_port = link.nbr["port"]
        try:
            _macsec_del_mka(peer, peer_port, primary_ckn)
            _macsec_del_mka(peer, peer_port, fallback_ckn)
            _macsec_add_mka(
                peer, peer_port, fallback_ckn,
                _raw_cak(link.shape["fallback_cak"]))
            _macsec_add_mka(
                peer, peer_port, primary_ckn,
                _raw_cak(link.shape["primary_cak"]), fallback=True)

            assert wait_for_ckn_live(
                link.duthost, link.dut_port, primary_ckn, timeout=30), \
                "Crossed primary CA did not become live"
            assert wait_for_ckn_live(
                link.duthost, link.dut_port, fallback_ckn, timeout=30), \
                "Crossed fallback CA did not become live"

            principal_ckn = get_principal_ckn(
                link.duthost, link.dut_port)
            assert principal_ckn is not None, \
                "Crossed-key link has no principal"
            principal = get_participant_by_ckn(
                link.duthost, link.dut_port, principal_ckn)
            assert principal is not None, \
                "Crossed-key principal participant disappeared"
            dut_is_key_server = (
                str(principal.get("is_key_server", "")).lower() == "yes")
            expected_ckn = primary_ckn if dut_is_key_server else fallback_ckn
            assert wait_principal_ckn(
                link.duthost, link.dut_port, expected_ckn, timeout=30), \
                "Principal does not match the key server's primary CA"
            assert wait_link_settled(
                link.duthost, link.dut_port, link.upstream_ip), \
                "Crossed primary/fallback roles did not forward traffic"
        finally:
            _restore_wpa_link(link)

    def test_completely_mismatched_keys_form_no_session(
            self, wpa_participant_link):
        """No CA becomes live when the peer shares neither configured key."""
        link = wpa_participant_link
        primary_ckn = link.shape["primary_ckn"]
        fallback_ckn = link.shape["fallback_ckn"]
        peer = link.nbr["host"]
        peer_port = link.nbr["port"]
        wrong_primary_cak, wrong_primary_ckn = link.new_key_pair()
        wrong_fallback_cak, wrong_fallback_ckn = link.new_key_pair(
            wrong_primary_ckn)
        try:
            _macsec_del_mka(peer, peer_port, primary_ckn)
            _macsec_del_mka(peer, peer_port, fallback_ckn)
            _macsec_add_mka(
                peer, peer_port, wrong_primary_ckn,
                _raw_cak(wrong_primary_cak))
            _macsec_add_mka(
                peer, peer_port, wrong_fallback_ckn,
                _raw_cak(wrong_fallback_cak), fallback=True)

            assert get_participant_by_ckn(
                peer, peer_port, wrong_primary_ckn) is not None, \
                "Peer did not install its mismatched primary participant"
            assert get_participant_by_ckn(
                peer, peer_port, wrong_fallback_ckn) is not None, \
                "Peer did not install its mismatched fallback participant"
            assert _no_session_stable(link.duthost, link.dut_port), \
                "Completely mismatched keys formed a session or installed SAs"
        finally:
            _restore_wpa_link(link)


@pytest.fixture(scope="module")
def principal_link(duthost, ctrl_links, upstream_links, get_port_profile,
                   wait_mka_establish):
    """A deployed link whose neighbor may be taken down."""
    deployed = make_deployed_link(
        duthost, ctrl_links, upstream_links, get_port_profile)
    dut_port = deployed.dut_port
    nbr = deployed.nbr
    profile_name = deployed.profile_name
    link = {
        "dut_port": dut_port,
        "nbr": nbr,
        "nbr_port": nbr["port"],
        "nbr_host": nbr["host"],
        "profile_name": profile_name,
        "upstream_ip": deployed.upstream_ip,
    }

    try:
        yield link
    finally:
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)
        if not wait_macsec_ok(duthost, dut_port, nbr):
            logger.error(
                "MACsec did not recover on %s after the peer was restored "
                "(%s); recreating the DUT participant",
                dut_port, _participant_summary(duthost, dut_port))
            replace_macsec_port(duthost, dut_port, profile_name)
            assert wait_macsec_ok(duthost, dut_port, nbr), \
                "MACsec still down on {} after a port bounce".format(
                    dut_port)
        assert wait_link_settled(
            duthost, dut_port, link["upstream_ip"]), \
            "Link {} did not resume forwarding after teardown".format(
                dut_port)
        deployed.release()


class TestWpaSupplicantPrincipalOwnership():

    def test_principal_returns_after_peer_outage(
            self, duthost, principal_link):
        """A returning peer restores ownership, SAs, and forwarding."""
        dut_port = principal_link["dut_port"]
        nbr_host = principal_link["nbr_host"]
        nbr_port = principal_link["nbr_port"]
        profile_name = principal_link["profile_name"]

        assert _peer_live(duthost, dut_port), \
            "No live peer on {} before the test: {}".format(
                dut_port, _participant_summary(duthost, dut_port))
        assert _has_sas(duthost, dut_port), \
            "No MACsec SAs on {} before the test: {}".format(
                dut_port, _sa_summary(duthost, dut_port))

        for cycle in range(1, OUTAGE_CYCLES + 1):
            disable_macsec_port(nbr_host, nbr_port)
            try:
                expired = wait_until(PEER_EXPIRY_TIMEOUT, 1, 0,
                                     _peer_expired, duthost, dut_port)
                assert expired, \
                    (
                        "Cycle {}: peer on {} did not expire within {}s: {}"
                    ).format(
                        cycle, dut_port, PEER_EXPIRY_TIMEOUT,
                        _participant_summary(duthost, dut_port))
            finally:
                enable_macsec_port(nbr_host, nbr_port, profile_name)

            assert wait_until(180, 2, 0, _peer_live, duthost, dut_port), \
                "Cycle {}: peer never came back on {} after rebinding {} on " \
                "{}: {}".format(cycle, dut_port, nbr_port, nbr_host.hostname,
                                _participant_summary(duthost, dut_port))

            violation = wait_principal_invariant(
                duthost, dut_port, timeout=60)
            assert violation is None, \
                "Cycle {} of {}: {} has a live peer but no owner after the " \
                "peer returned. This port installs no SA and blackholes " \
                "while MKA reports the session up. {}".format(
                    cycle, OUTAGE_CYCLES, dut_port, violation)

            assert wait_until(180, 3, 0, _has_sas, duthost, dut_port), \
                "Cycle {} of {}: {} has a live peer and an owner but no SAs " \
                "installed. This is the silent blackhole: MKA reports the " \
                "session up and the port reports ok while no traffic " \
                "can cross. {} [{}]".format(
                    cycle, OUTAGE_CYCLES, dut_port,
                    _sa_summary(duthost, dut_port),
                    _participant_summary(duthost, dut_port))

        assert wait_link_settled(duthost, principal_link["dut_port"],
                                 principal_link["upstream_ip"]), \
            "Link {} did not settle after the peer outage cycles".format(
                principal_link["dut_port"])
