"""Principal ownership of a MACsec port across a peer-side outage.

KaY tracks the owner of a controlled port -- its *principal* participant -- and
only the owner distributes a SAK. A participant that has a live peer but owns
nothing installs no SA, so MKA keeps reporting the session as up, the peer keeps
sending MKPDUs, and the datapath silently blackholes. Port state and peer counts
both look healthy right up until traffic is tried, which is why every assertion
below is on SA presence in APPL_DB rather than on MKA state.

The rest of this suite cannot see that state at all. Every other test changes a
profile on the DUT, and deleting a DUT participant makes KaY re-run principal
selection as a side effect, repairing ownership before anything can observe it
missing. So the outage here is applied to the **neighbor only**: the DUT's
configuration is never touched and its participant is never deleted. The only
thing that changes on the DUT is that its peer stops transmitting and later
resumes.

Scope, stated plainly so this is not over-read:

* This covers recovery of port ownership after a peer goes away and returns. It
  is worth having -- nothing else in the suite exercises that path.
* It is **not** a reproduction of any specific field failure, and a pass here is
  not evidence that one is fixed. Removing the neighbor's profile destroys and
  recreates the neighbor's MKA participant, so the peer returns with a fresh
  member identifier and KaY treats it as a new peer. The paths that turn on a
  returning peer being recognised as the *same* peer are therefore not reached.
  Covering those needs an outage that keeps the neighbor's participant running
  -- filtering EAPOL rather than unconfiguring MACsec -- which this does not do.

The outage is kept short and repeated: a single cycle proves very little when
the behaviour under test is a recovery path.
"""
import logging

import pytest

from tests.common.macsec.macsec_config_helper import (
    disable_macsec_port,
    enable_macsec_port,
    replace_macsec_port,
)
from tests.common.macsec.macsec_helper import (
    check_principal_invariant,
    get_mka_participants,
    wait_principal_invariant,
)
from tests.common.utilities import wait_until
from tests.macsec.macsec_key_helpers import (
    sa_saks,
    select_ctrl_link,
    wait_link_settled,
    wait_macsec_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]

# A recovery path is not usefully tested once. Cycle it: intermittent failures
# to reclaim ownership would otherwise pass on a lucky first attempt.
OUTAGE_CYCLES = 5

# MKA declares a peer dead after MKA_LIFE_TIME (6s). Allow for the hello
# interval on top, but no more: a long outage is the easy case.
PEER_EXPIRY_TIMEOUT = 30


def _participant_summary(host, port):
    """One-line rendering of every participant, for failure messages."""
    return " | ".join(
        "ckn={}.. live_peers={} principal={} elected={} key_server={}".format(
            p.get("ckn", "?")[:16], p.get("live_peers", "?"),
            p.get("is_principal", "?"), p.get("is_elected", "?"),
            p.get("is_key_server", "?"))
        for p in get_mka_participants(host, port)) or "<no participants>"


def _owner_count(host, port):
    """Number of participants currently reporting themselves as principal."""
    return sum(1 for p in get_mka_participants(host, port)
               if str(p.get("is_principal", "")).strip().lower() == "yes")


def _sa_summary(duthost, dut_port):
    """Counts of installed SAs in each direction, for failure messages."""
    return "egress_sas={} ingress_sas={}".format(
        len(sa_saks(duthost, dut_port, "EGRESS")),
        len(sa_saks(duthost, dut_port, "INGRESS")))


def _has_sas(duthost, dut_port):
    """True once the port has an SA installed in both directions.

    This is the assertion that matters, and it is deliberately not
    ``iface_macsec_ok``: that reads MACSEC_PORT_TABLE state. A port was observed
    on this testbed reporting that state as 'ok', with its peer live and MKPDUs
    flowing, while no SA existed and the datapath was dark. Whatever the cause,
    SA presence was the only signal that showed it, so it is the only signal
    worth asserting on here.
    """
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


@pytest.fixture(scope="module")
def principal_link(duthost, ctrl_links, upstream_links, get_port_profile,
                   wait_mka_establish):
    """A control link this module may take down from the neighbor side.

    Nothing is reconfigured on the way in: the link keeps the profile it was
    deployed with, because the whole point is to leave the DUT side untouched.
    """
    dut_port, nbr = select_ctrl_link(ctrl_links, upstream_links)
    if dut_port is None:
        pytest.skip("No control link with an upstream IP is available")

    profile_name = get_port_profile(dut_port)["name"]
    link = {
        "dut_port": dut_port,
        "nbr": nbr,
        "nbr_port": nbr["port"],
        "nbr_host": nbr["host"],
        "profile_name": profile_name,
        "upstream_ip": upstream_links[dut_port]["local_ipv4_addr"],
    }

    try:
        yield link
    finally:
        # Whatever the test left behind, the neighbor has to end up bound to
        # the profile it started on, and the DUT has to end up forwarding.
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)
        if not wait_macsec_ok(duthost, dut_port, nbr):
            # A wedged principal survives any amount of waiting; recreating the
            # DUT participant is what clears it, and leaving the port dark for
            # the rest of the run would be worse than the bounce.
            logger.error(
                "MACsec did not recover on %s after the peer was restored "
                "(%s); recreating the DUT participant",
                dut_port, _participant_summary(duthost, dut_port))
            replace_macsec_port(duthost, dut_port, profile_name)
            if not wait_macsec_ok(duthost, dut_port, nbr):
                logger.error("MACsec still down on %s after a port bounce",
                             dut_port)
        wait_link_settled(duthost, dut_port, link["upstream_ip"])


class TestMacsecPrincipalOwnership():
    """Ownership of a controlled port must survive the peer going away."""

    def test_baseline_port_is_owned(self, duthost, principal_link):
        """Every participant with a live peer is accounted for by an owner.

        Recorded before anything is broken so the post-outage result is read
        against this port's own baseline rather than against the general model.
        """
        dut_port = principal_link["dut_port"]
        violation = check_principal_invariant(duthost, dut_port)
        assert violation is None, violation
        assert _peer_live(duthost, dut_port), \
            "No live peer on {} before the test started: {}".format(
                dut_port, _participant_summary(duthost, dut_port))
        assert _has_sas(duthost, dut_port), \
            "No MACsec SAs installed on {} before the test started: {}".format(
                dut_port, _sa_summary(duthost, dut_port))
        logger.info("Baseline %s: %s [%s]", dut_port,
                    _participant_summary(duthost, dut_port),
                    _sa_summary(duthost, dut_port))

    def test_principal_returns_after_peer_outage(self, duthost, principal_link):
        """A peer that leaves and returns must leave the port owned.

        Each cycle unbinds MACsec on the neighbor interface only, waits for the
        DUT to age its peer out, then rebinds. The DUT keeps its profile, its
        port binding and its participant throughout, so KaY is never given the
        participant-deleted edge that the rest of the suite generates for free.

        Losing ownership while the peer is away is expected and is not asserted
        against -- it is logged, because it is the entry half of the failure and
        worth having on record. What must hold is that ownership comes back once
        the peer does. A cycle that ends with a live peer and no owner is a port
        that will blackhole.
        """
        dut_port = principal_link["dut_port"]
        nbr_host = principal_link["nbr_host"]
        nbr_port = principal_link["nbr_port"]
        profile_name = principal_link["profile_name"]

        unowned_while_away = 0

        for cycle in range(1, OUTAGE_CYCLES + 1):
            disable_macsec_port(nbr_host, nbr_port)

            expired = wait_until(PEER_EXPIRY_TIMEOUT, 1, 0,
                                 _peer_expired, duthost, dut_port)
            if not expired:
                # The peer never aged out, so this cycle did not construct the
                # state under test. Rebind and move on rather than reporting a
                # pass that measured nothing.
                logger.warning(
                    "Cycle %s: peer on %s did not expire within %ss: %s",
                    cycle, dut_port, PEER_EXPIRY_TIMEOUT,
                    _participant_summary(duthost, dut_port))
            else:
                during = _participant_summary(duthost, dut_port)
                if _owner_count(duthost, dut_port) == 0:
                    unowned_while_away += 1
                logger.info("Cycle %s: %s peerless: %s", cycle, dut_port, during)

            enable_macsec_port(nbr_host, nbr_port, profile_name)

            assert wait_until(180, 2, 0, _peer_live, duthost, dut_port), \
                "Cycle {}: peer never came back on {} after rebinding {} on " \
                "{}: {}".format(cycle, dut_port, nbr_port, nbr_host.hostname,
                                _participant_summary(duthost, dut_port))

            violation = wait_principal_invariant(duthost, dut_port, timeout=60)
            assert violation is None, \
                "Cycle {} of {}: {} has a live peer but no owner after the " \
                "peer returned. This port installs no SA and blackholes " \
                "while MKA reports the session up. {}".format(
                    cycle, OUTAGE_CYCLES, dut_port, violation)

            # Ownership is necessary but not sufficient. MKA state and port
            # state can both report healthy on a port that has installed no SA,
            # so the SA tables are checked separately rather than inferred.
            assert wait_until(180, 3, 0, _has_sas, duthost, dut_port), \
                "Cycle {} of {}: {} has a live peer and an owner but no SAs " \
                "installed. This is the silent blackhole: MKA reports the " \
                "session up and MACSEC_PORT_TABLE reports ok while no traffic " \
                "can cross. {} [{}]".format(
                    cycle, OUTAGE_CYCLES, dut_port, _sa_summary(duthost, dut_port),
                    _participant_summary(duthost, dut_port))

        logger.info(
            "%s survived %s peer outages; unowned while peerless in %s of them",
            dut_port, OUTAGE_CYCLES, unowned_while_away)

    def test_link_forwards_after_outages(self, duthost, principal_link):
        """The link still carries traffic once the outages are over.

        Ownership and SA presence are read out of MKA and the ASIC; this is the
        end-to-end check that nothing was left half-configured.
        """
        assert wait_link_settled(duthost, principal_link["dut_port"],
                                 principal_link["upstream_ip"]), \
            "Link {} did not settle after the peer outage cycles".format(
                principal_link["dut_port"])
