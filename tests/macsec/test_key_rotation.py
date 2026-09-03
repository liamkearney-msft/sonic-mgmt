"""CAK rotation and periodic SAK rekey tests."""

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

ROTATION_STRESS_COUNT = 5

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


def _dut_is_key_server(duthost, dut_port):
    """Return whether the DUT's principal participant is key server."""
    for participant in get_mka_participants(duthost, dut_port):
        if str(participant.get("is_principal")).lower() == "yes":
            return str(participant.get("is_key_server")).lower() == "yes"
    return False


@pytest.fixture(scope="module")
def rotation_link(duthost, ctrl_links, upstream_links, get_port_profile,
                  default_priority, cipher_suite, policy, send_sci,
                  wait_mka_establish):
    """A control link using an isolated primary/fallback profile."""
    link = make_dedicated_link(
        duthost, ctrl_links, upstream_links, get_port_profile, default_priority,
        cipher_suite, policy, send_sci, 0)

    try:
        assert link.settled(), \
            "Link {} did not settle on its dedicated two-CA profile".format(link.dut_port)
        assert link.wait_cas_live(), \
            "Both CAs of the dedicated profile did not negotiate a live peer"
        yield link
    finally:
        restore_baseline_link(link)


@pytest.fixture(scope="class")
def armed_rekey_link(duthost, rotation_link):
    """Run periodic SAK tests with the SONiC DUT as key server."""
    original_rekey_period = rotation_link.shape["rekey_period"]
    original_dut_priority = rotation_link.dut_priority
    original_nbr_priority = rotation_link.nbr_priority
    try:
        # Lower priority wins the key-server election. Make the SONiC DUT drive
        # the timer so EOS support for configuring a rekey period is irrelevant.
        rotation_link.dut_priority = original_nbr_priority
        rotation_link.nbr_priority = original_dut_priority
        rotation_link.apply_shape(rekey_period=REKEY_PERIOD)
        assert rotation_link.settled(), \
            "Link did not settle after arming a {}s rekey period".format(
                REKEY_PERIOD)
        assert wait_until(
            30, 2, 0, _dut_is_key_server, duthost,
            rotation_link.dut_port), \
            "DUT did not become key server after the profile priorities were swapped"
        yield rotation_link
    finally:
        rotation_link.dut_priority = original_dut_priority
        rotation_link.nbr_priority = original_nbr_priority
        rotation_link.apply_shape(rekey_period=original_rekey_period)
        assert rotation_link.settled(), \
            "Link did not settle after restoring rekey_period={}".format(
                original_rekey_period)


def _rotate_both_ends(link, old_ckn, new_ckn, new_cak,
                      endpoint_ckns=None):
    """Roll one CA over on both ends of the link."""
    if endpoint_ckns is None:
        endpoint_ckns = [old_ckn for _ in link.hosts]
    for index, (host, _, _) in enumerate(link.hosts):
        rotate_macsec_profile_key(
            host, link.profile_name, endpoint_ckns[index], new_ckn, new_cak)
        endpoint_ckns[index] = new_ckn
    return endpoint_ckns


def _restore_ca(link, endpoint_ckns, original_ckn, original_cak):
    for index, (host, _, _) in enumerate(link.hosts):
        if endpoint_ckns[index] != original_ckn:
            rotate_macsec_profile_key(
                host, link.profile_name, endpoint_ckns[index],
                original_ckn, original_cak)
            endpoint_ckns[index] = original_ckn


def _run_dut_rotation(duthost, link, old_ckn, new_ckn, new_cak):
    """Run the SONiC rollover CLI and return its result without raising."""
    return duthost.command(
        "config macsec {} profile update {} --old_ckn {} --new_ckn {} "
        "--new_cak {}".format(
            getns_prefix(duthost, link.dut_port), link.profile_name,
            old_ckn, new_ckn, new_cak),
        module_ignore_errors=True)


def _participant_peerless(host, port, ckn):
    participant = get_participant_by_ckn(host, port, ckn)
    return (participant is not None
            and int(participant.get("live_peers", 0)) == 0)


def _measure_rotation(link, old_ckn, new_ckn, new_cak,
                      endpoint_ckns, window=30):
    """Roll a CA over inside a continuity window and return the packet loss."""
    assert link.settled(), \
        "Link never returned to clean forwarding before the measurement window"
    ping = start_bg_ping(link.duthost, link.dut_port, link.upstream_ip, window)
    try:
        _rotate_both_ends(
            link, old_ckn, new_ckn, new_cak, endpoint_ckns)
        assert wait_for_ckn_live(
            link.duthost, link.dut_port, new_ckn, timeout=window), \
            "Rotated CA {} did not become live inside the window".format(
                new_ckn)
    except Exception:
        pool, _ = ping
        pool.terminate()
        raise
    return read_ping_loss(ping)


class TestMacsecKeyRotation():

    def test_hitless_primary_cak_rotation(self, duthost, rotation_link):
        """Rolling the primary CAK is hitless and preserves the fallback."""
        dut_port = rotation_link.dut_port
        old_ckn = rotation_link.shape["primary_ckn"]
        old_cak = rotation_link.shape["primary_cak"]
        fb_ckn = rotation_link.shape["fallback_ckn"]
        new_cak, new_ckn = rotation_link.new_key_pair()
        endpoint_ckns = [old_ckn for _ in rotation_link.hosts]

        try:
            loss = _measure_rotation(
                rotation_link, old_ckn, new_ckn, new_cak, endpoint_ckns)
            rotation_link.shape.update(primary_cak=new_cak, primary_ckn=new_ckn)

            assert wait_principal_ckn(duthost, dut_port, new_ckn, timeout=180), \
                "Principal did not end on the new primary CKN"
            assert get_participant_by_ckn(duthost, dut_port, fb_ckn) is not None, \
                "Rotating the primary key removed the fallback CA"
            assert get_participant_by_ckn(duthost, dut_port, old_ckn) is None, \
                "Old primary CA is still present after the rollover"
            assert loss <= LOSS_TOLERANCE, \
                "Primary CAK rotation packet loss {}% exceeds tolerance".format(loss)
        finally:
            _restore_ca(rotation_link, endpoint_ckns, old_ckn, old_cak)
            rotation_link.shape.update(primary_cak=old_cak, primary_ckn=old_ckn)
            assert rotation_link.wait_cas_live(), \
                "Link did not recover after primary CAK rotation"

    def test_hitless_fallback_cak_rotation(self, duthost, rotation_link):
        """Rolling the fallback CAK is hitless and does not rekey the SAK."""
        dut_port = rotation_link.dut_port
        primary_ckn = rotation_link.shape["primary_ckn"]
        old_ckn = rotation_link.shape["fallback_ckn"]
        old_cak = rotation_link.shape["fallback_cak"]
        new_cak, new_ckn = rotation_link.new_key_pair()
        endpoint_ckns = [old_ckn for _ in rotation_link.hosts]

        assert wait_principal_ckn(duthost, dut_port, primary_ckn), \
            "Principal did not start on the primary CA"
        egress_saks = sa_saks(duthost, dut_port, "EGRESS")
        ingress_saks = sa_saks(duthost, dut_port, "INGRESS")
        assert egress_saks and ingress_saks, \
            "No active SAKs before fallback rotation"

        try:
            loss = _measure_rotation(
                rotation_link, old_ckn, new_ckn, new_cak, endpoint_ckns)
            rotation_link.shape.update(fallback_cak=new_cak, fallback_ckn=new_ckn)

            assert get_principal_ckn(duthost, dut_port) == primary_ckn.lower(), \
                "Principal changed while the fallback key was rotated"
            standby = get_participant_by_ckn(duthost, dut_port, new_ckn)
            assert standby is not None, "Rotated fallback CA is not present"
            assert str(standby.get("is_fallback")).lower() == "yes", \
                "Rotated CA did not keep the fallback role"
            assert get_participant_by_ckn(duthost, dut_port, old_ckn) is None, \
                "Old fallback CA is still present after the rollover"
            assert sa_saks(duthost, dut_port, "EGRESS") == egress_saks, \
                "Fallback rotation forced an egress SAK rekey"
            assert sa_saks(duthost, dut_port, "INGRESS") == ingress_saks, \
                "Fallback rotation forced an ingress SAK rekey"
            assert loss <= LOSS_TOLERANCE, \
                "Fallback CAK rotation packet loss {}% exceeds tolerance".format(loss)
        finally:
            _restore_ca(rotation_link, endpoint_ckns, old_ckn, old_cak)
            rotation_link.shape.update(fallback_cak=old_cak, fallback_ckn=old_ckn)
            assert rotation_link.wait_cas_live(), \
                "Link did not recover after fallback CAK rotation"

    def test_back_to_back_primary_rotations_do_not_wedge(
            self, duthost, rotation_link):
        """Repeated primary CAK rotations remain hitless and converge each time."""
        original_cak = rotation_link.shape["primary_cak"]
        original_ckn = rotation_link.shape["primary_ckn"]
        endpoint_ckns = [original_ckn for _ in rotation_link.hosts]

        try:
            for iteration in range(1, ROTATION_STRESS_COUNT + 1):
                new_cak, new_ckn = rotation_link.new_key_pair()
                old_ckn = endpoint_ckns[0]
                loss = _measure_rotation(
                    rotation_link, old_ckn, new_ckn, new_cak,
                    endpoint_ckns)
                rotation_link.shape.update(
                    primary_cak=new_cak, primary_ckn=new_ckn)

                assert wait_principal_ckn(
                    duthost, rotation_link.dut_port, new_ckn,
                    timeout=REKEY_INTERVAL_MAX), \
                    "Rotation {} did not establish its new primary CA".format(
                        iteration)
                assert get_participant_by_ckn(
                    duthost, rotation_link.dut_port, old_ckn) is None, \
                    "Rotation {} left its old primary participant behind".format(
                        iteration)
                assert loss <= LOSS_TOLERANCE, \
                    "Rotation {} packet loss {}% exceeds tolerance".format(
                        iteration, loss)
        finally:
            _restore_ca(
                rotation_link, endpoint_ckns, original_ckn, original_cak)
            rotation_link.shape.update(
                primary_cak=original_cak, primary_ckn=original_ckn)
            assert rotation_link.wait_cas_live(), \
                "Link did not recover after back-to-back CAK rotations"

    def test_rotation_rejects_unsafe_keys(self, duthost, rotation_link):
        """The CLI rejects duplicate, conflicting, and unknown CKNs."""
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

    def test_fallback_rotation_with_dead_primary_is_accepted(
            self, duthost, rotation_link):
        """A configured primary permits fallback rotation even when it is dead."""
        old_primary_ckn = rotation_link.shape["primary_ckn"]
        fallback_ckn = rotation_link.shape["fallback_ckn"]
        new_primary_cak, new_primary_ckn = rotation_link.new_key_pair()
        new_fallback_cak, new_fallback_ckn = rotation_link.new_key_pair(
            new_primary_ckn)

        try:
            rotate_macsec_profile_key(
                duthost, rotation_link.profile_name, old_primary_ckn,
                new_primary_ckn, new_primary_cak)
            assert wait_principal_ckn(
                duthost, rotation_link.dut_port, fallback_ckn, timeout=30), \
                "Fallback CA did not take over after the primary became mismatched"

            result = _run_dut_rotation(
                duthost, rotation_link, fallback_ckn,
                new_fallback_ckn, new_fallback_cak)
            output = "{}\n{}".format(
                result.get("stdout", ""), result.get("stderr", ""))
            assert result["rc"] == 0, \
                "Fallback rotation was rejected despite a configured primary CA: " \
                "{}".format(output.strip())
            assert wait_until(
                30, 1, 0, _participant_peerless, duthost,
                rotation_link.dut_port, new_fallback_ckn), \
                "Rotated fallback participant was not installed"
            assert get_participant_by_ckn(
                duthost, rotation_link.dut_port, fallback_ckn) is None, \
                "Old fallback participant remained after rotation"
        finally:
            rotation_link.apply_shape()
            assert rotation_link.wait_cas_live(), \
                "Link did not recover after fallback rotation with a dead primary"

    def test_primary_rotation_with_dead_fallback_is_accepted(
            self, duthost, rotation_link):
        """A configured fallback permits primary rotation even when it is dead."""
        primary_ckn = rotation_link.shape["primary_ckn"]
        old_fallback_ckn = rotation_link.shape["fallback_ckn"]
        new_fallback_cak, new_fallback_ckn = rotation_link.new_key_pair()
        new_primary_cak, new_primary_ckn = rotation_link.new_key_pair(
            new_fallback_ckn)

        try:
            rotate_macsec_profile_key(
                duthost, rotation_link.profile_name, old_fallback_ckn,
                new_fallback_ckn, new_fallback_cak)
            assert wait_until(
                30, 1, 0, _participant_peerless, duthost,
                rotation_link.dut_port, new_fallback_ckn), \
                "Mismatched fallback unexpectedly negotiated a live peer"
            assert wait_principal_ckn(
                duthost, rotation_link.dut_port, primary_ckn, timeout=30), \
                "Primary CA stopped protecting the link"

            result = _run_dut_rotation(
                duthost, rotation_link, primary_ckn,
                new_primary_ckn, new_primary_cak)
            output = "{}\n{}".format(
                result.get("stdout", ""), result.get("stderr", ""))
            assert result["rc"] == 0, \
                "Primary rotation was rejected despite a configured fallback CA: " \
                "{}".format(output.strip())
            assert wait_until(
                30, 1, 0, _participant_peerless, duthost,
                rotation_link.dut_port, new_primary_ckn), \
                "Rotated primary participant was not installed"
            assert get_participant_by_ckn(
                duthost, rotation_link.dut_port, primary_ckn) is None, \
                "Old primary participant remained after rotation"
        finally:
            rotation_link.apply_shape()
            assert rotation_link.wait_cas_live(), \
                "Link did not recover after primary rotation with a dead fallback"

    def test_primary_rotation_without_configured_fallback_is_rejected(
            self, duthost, rotation_link):
        """A bound profile cannot rotate its only configured CA."""
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
            assert rotation_link.settled(), \
                "Link did not settle after restoring its fallback CA"
            assert rotation_link.wait_cas_live(), \
                "Link did not restore both CAs"


class TestMacsecSakRekey():
    def test_primary_rollover_at_sak_rekey_boundary(
            self, duthost, armed_rekey_link):
        """A primary mismatch and recovery remain hitless as a periodic SAK rolls."""
        link = armed_rekey_link
        old_cak = link.shape["primary_cak"]
        old_ckn = link.shape["primary_ckn"]
        fallback_ckn = link.shape["fallback_ckn"]
        new_cak, new_ckn = link.new_key_pair()
        saks_before = sa_saks(duthost, link.dut_port, "EGRESS")
        ping = start_bg_ping(
            duthost, link.dut_port, link.upstream_ip,
            4 * REKEY_INTERVAL_MAX)
        dut_rotated = False
        peer_rotated = False

        try:
            assert wait_until(
                REKEY_INTERVAL_MAX, 0.5, 0,
                lambda: sa_saks(
                    duthost, link.dut_port, "EGRESS") != saks_before), \
                "No SAK rekey occurred before the CAK boundary test"

            rotate_macsec_profile_key(
                duthost, link.profile_name, old_ckn, new_ckn, new_cak)
            dut_rotated = True
            assert wait_principal_ckn(
                duthost, link.dut_port, fallback_ckn,
                timeout=REKEY_INTERVAL_MAX), \
                "Fallback did not take over at the SAK rekey boundary"

            rotate_macsec_profile_key(
                link.nbr["host"], link.profile_name,
                old_ckn, new_ckn, new_cak)
            peer_rotated = True
            link.shape.update(primary_cak=new_cak, primary_ckn=new_ckn)
            assert wait_principal_ckn(
                duthost, link.dut_port, new_ckn,
                timeout=REKEY_INTERVAL_MAX), \
                "Primary did not recover at the SAK rekey boundary"

            loss = read_ping_loss(ping)
            assert loss <= LOSS_TOLERANCE, \
                "CAK rollover at the SAK rekey boundary lost {}% traffic".format(
                    loss)
        finally:
            if dut_rotated and not peer_rotated:
                rotate_macsec_profile_key(
                    link.nbr["host"], link.profile_name,
                    old_ckn, new_ckn, new_cak)
                peer_rotated = True
            if dut_rotated and peer_rotated:
                _rotate_both_ends(link, new_ckn, old_ckn, old_cak)
                link.shape.update(primary_cak=old_cak, primary_ckn=old_ckn)
            assert link.wait_cas_live(), \
                "Link did not recover after the SAK/CAK boundary test"

    def test_sak_rekey_by_period(self, duthost, armed_rekey_link):
        """A periodic SAK refresh rolls both directions without loss."""
        link = armed_rekey_link
        dut_port = link.dut_port
        window = 2 * REKEY_INTERVAL_MAX

        principal_before = get_principal_ckn(duthost, dut_port)
        egress_before = sa_saks(duthost, dut_port, "EGRESS")
        ingress_before = sa_saks(duthost, dut_port, "INGRESS")

        ping = start_bg_ping(duthost, dut_port, link.upstream_ip, window)

        def _both_directions_rolled():
            return (sa_saks(duthost, dut_port, "EGRESS") != egress_before
                    and sa_saks(duthost, dut_port, "INGRESS") != ingress_before)

        assert wait_until(window, 2, 0, _both_directions_rolled), \
            "SAK did not roll within {}s of arming a {}s rekey period".format(
                window, REKEY_PERIOD)
        assert get_principal_ckn(duthost, dut_port) == principal_before, \
            "Principal CKN changed during a periodic SAK refresh"

        loss = read_ping_loss(ping)
        assert loss <= LOSS_TOLERANCE, \
            "Periodic SAK rekey packet loss {}% exceeds tolerance".format(loss)
