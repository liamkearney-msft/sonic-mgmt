"""Fallback CA lifecycle tests through the production ``config macsec`` CLI."""

import time

import pytest

from tests.common.macsec.macsec_config_helper import (
    replace_macsec_profile,
    rotate_macsec_profile_key,
)
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
    make_dedicated_link,
    make_deployed_link,
    read_ping_loss,
    restore_baseline_link,
    sa_saks,
    start_bg_ping,
    wait_principal_ckn,
)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


@pytest.fixture(scope="module")
def deployed_fallback_link(duthost, ctrl_links, upstream_links, get_port_profile,
                           wait_mka_establish):
    """A control link using its deployed fallback profile."""
    link = make_deployed_link(duthost, ctrl_links, upstream_links,
                              get_port_profile, require_fallback=True)
    try:
        yield link
    finally:
        link.release()


@pytest.fixture(scope="module")
def fallback_link(duthost, ctrl_links, upstream_links, get_port_profile,
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


def _assert_two_ca_baseline(link):
    """Assert the link is back in the shape the fixture guarantees."""
    assert link.wait_cas_live(), \
        "Link {} did not return to two live CAs".format(link.dut_port)
    assert wait_principal_ckn(link.duthost, link.dut_port,
                              link.shape["primary_ckn"], timeout=180), \
        "Principal did not return to the primary CA on {}".format(link.dut_port)


def _replace_peer_profile(link, shape):
    host, port, priority = link.hosts[1]
    replace_macsec_profile(
        host, port, link.profile_name, priority, link.cipher_suite,
        shape["primary_cak"], shape["primary_ckn"], link.policy,
        link.send_sci, shape["rekey_period"], shape.get("fallback_cak"),
        shape.get("fallback_ckn"))


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


class TestMacsecFallbackKey():

    def test_fallback_profile_live_on_every_configured_link(
            self, duthost, ctrl_links, get_port_profile, wait_mka_establish):
        """Every fallback-configured link negotiates both CAs on both peers."""
        checked = 0
        for dut_port, nbr in ctrl_links.items():
            profile = get_port_profile(dut_port)
            primary_ckn = profile.get("primary_ckn")
            fallback_ckn = profile.get("fallback_ckn")
            if not fallback_ckn:
                continue
            checked += 1
            for host, port in (
                    (duthost, dut_port), (nbr["host"], nbr["port"])):
                assert wait_for_ckn_live(
                    host, port, primary_ckn, timeout=120), \
                    "Primary CA is not live on {} {}".format(
                        host.hostname, port)
                assert wait_for_ckn_live(
                    host, port, fallback_ckn, timeout=120), \
                    "Fallback CA is not live on {} {}".format(
                        host.hostname, port)
                assert wait_principal_ckn(
                    host, port, primary_ckn, timeout=60), \
                    "Primary CA does not take precedence on {} {}".format(
                        host.hostname, port)
                fallback = get_participant_by_ckn(host, port, fallback_ckn)
                assert str(fallback.get("is_fallback")).lower() == "yes", \
                    "Fallback CA is not marked as fallback on {} {}".format(
                        host.hostname, port)

        if not checked:
            pytest.skip("No control link is configured with a fallback CA")

    def test_primary_only_and_add_fallback(self, duthost, fallback_link):
        """A primary-only profile forwards and accepts a fallback on replacement."""
        dut_port = fallback_link.dut_port
        primary_ckn = fallback_link.shape["primary_ckn"]
        fb_cak = fallback_link.shape["fallback_cak"]
        fb_ckn = fallback_link.shape["fallback_ckn"]

        try:
            fallback_link.apply_shape(fallback_cak=None, fallback_ckn=None)
            assert fallback_link.settled(), \
                "Link did not settle on the single-CA profile"
            assert get_participant_by_ckn(duthost, dut_port, fb_ckn) is None, \
                "Standby CA survived a replacement that dropped the fallback key"
            assert wait_principal_ckn(duthost, dut_port, primary_ckn), \
                "Primary-only CA did not become principal"
            assert (sa_saks(duthost, dut_port, "EGRESS")
                    and sa_saks(duthost, dut_port, "INGRESS")), \
                "Primary-only session has no SAs"

            fallback_link.apply_shape(fallback_cak=fb_cak, fallback_ckn=fb_ckn)
            assert fallback_link.settled(), \
                "Link did not settle after the fallback key was added back"
            assert wait_for_ckn_live(duthost, dut_port, fb_ckn, timeout=180), \
                "Standby CA did not negotiate a live peer after being added"
        finally:
            if fallback_link.shape["fallback_ckn"] != fb_ckn:
                fallback_link.apply_shape(fallback_cak=fb_cak, fallback_ckn=fb_ckn)
                fallback_link.settled()
            _assert_two_ca_baseline(fallback_link)

    def test_primary_rollover_fails_over_and_back(self, duthost, fallback_link):
        """The config-supported primary transition fails over and back."""
        dut_port = fallback_link.dut_port
        nbr = fallback_link.nbr
        old_ckn = fallback_link.shape["primary_ckn"]
        old_cak = fallback_link.shape["primary_cak"]
        fb_ckn = fallback_link.shape["fallback_ckn"]
        new_cak, new_ckn = fallback_link.new_key_pair()
        dut_rotated = False
        peer_rotated = False

        try:
            failover_ping = start_bg_ping(
                duthost, dut_port, fallback_link.upstream_ip, 30)
            rotate_macsec_profile_key(duthost, fallback_link.profile_name,
                                      old_ckn, new_ckn, new_cak)
            dut_rotated = True

            assert wait_principal_ckn(duthost, dut_port, fb_ckn, timeout=30), \
                "Principal did not fail over to the fallback CA after the two " \
                "ends were left with different primary keys"
            failover_loss = read_ping_loss(failover_ping)
            assert failover_loss <= LOSS_TOLERANCE, \
                "Fallback takeover packet loss {}% exceeds tolerance".format(
                    failover_loss)

            assert (sa_saks(duthost, dut_port, "EGRESS")
                    and sa_saks(duthost, dut_port, "INGRESS")), \
                "Datapath torn down while running on the fallback CA"

            failback_ping = start_bg_ping(
                duthost, dut_port, fallback_link.upstream_ip, 30)
            rotate_macsec_profile_key(nbr["host"], fallback_link.profile_name,
                                      old_ckn, new_ckn, new_cak)
            peer_rotated = True
            fallback_link.shape.update(primary_cak=new_cak, primary_ckn=new_ckn)

            assert wait_for_ckn_live(duthost, dut_port, new_ckn, timeout=30), \
                "New primary CA did not negotiate a live peer once both ends " \
                "had been rotated"
            assert wait_principal_ckn(duthost, dut_port, new_ckn, timeout=30), \
                "Principal did not fail back to the primary CA after the " \
                "rollover completed"
            failback_loss = read_ping_loss(failback_ping)
            assert failback_loss <= LOSS_TOLERANCE, \
                "Primary takeover packet loss {}% exceeds tolerance".format(
                    failback_loss)
            assert get_principal_ckn(duthost, dut_port) != fb_ckn.lower(), \
                "Link is still running on its fallback CA"
        finally:
            if dut_rotated and not peer_rotated:
                rotate_macsec_profile_key(nbr["host"], fallback_link.profile_name,
                                          old_ckn, new_ckn, new_cak)
                peer_rotated = True
            if dut_rotated and peer_rotated:
                for host, port, _ in fallback_link.hosts:
                    rotate_macsec_profile_key(host, fallback_link.profile_name,
                                              new_ckn, old_ckn, old_cak)
                fallback_link.shape.update(primary_cak=old_cak, primary_ckn=old_ckn)
            _assert_two_ca_baseline(fallback_link)

    def test_fallback_key_only_profile_forwards(self, duthost, fallback_link):
        """The fallback key material works as the sole configured CA."""
        original = dict(fallback_link.shape)
        try:
            fallback_link.apply_shape(
                primary_cak=original["fallback_cak"],
                primary_ckn=original["fallback_ckn"],
                fallback_cak=None,
                fallback_ckn=None)
            assert fallback_link.settled(), \
                "Fallback-key-only profile did not forward traffic"
            assert wait_principal_ckn(
                duthost, fallback_link.dut_port,
                original["fallback_ckn"], timeout=60), \
                "Fallback key did not become the sole principal CA"
            assert (sa_saks(duthost, fallback_link.dut_port, "EGRESS")
                    and sa_saks(
                        duthost, fallback_link.dut_port, "INGRESS")), \
                "Fallback-key-only profile has no SAs"
        finally:
            fallback_link.apply_shape(**original)
            assert fallback_link.settled(), \
                "Link did not settle after restoring both CAs"
            _assert_two_ca_baseline(fallback_link)

    def test_crossed_primary_fallback_roles_follow_key_server(
            self, duthost, fallback_link):
        """Crossed roles configured through the CLI follow the key server."""
        original = dict(fallback_link.shape)
        crossed = dict(original)
        crossed.update(
            primary_cak=original["fallback_cak"],
            primary_ckn=original["fallback_ckn"],
            fallback_cak=original["primary_cak"],
            fallback_ckn=original["primary_ckn"])
        try:
            _replace_peer_profile(fallback_link, crossed)
            assert wait_for_ckn_live(
                duthost, fallback_link.dut_port,
                original["primary_ckn"], timeout=60), \
                "Crossed primary CA did not become live"
            assert wait_for_ckn_live(
                duthost, fallback_link.dut_port,
                original["fallback_ckn"], timeout=60), \
                "Crossed fallback CA did not become live"

            principal_ckn = get_principal_ckn(
                duthost, fallback_link.dut_port)
            assert principal_ckn is not None, \
                "Crossed-key link has no principal"
            principal = get_participant_by_ckn(
                duthost, fallback_link.dut_port, principal_ckn)
            assert principal is not None, \
                "Crossed-key principal participant disappeared"
            dut_is_key_server = (
                str(principal.get("is_key_server", "")).lower() == "yes")
            expected_ckn = (
                original["primary_ckn"] if dut_is_key_server
                else original["fallback_ckn"])
            assert wait_principal_ckn(
                duthost, fallback_link.dut_port,
                expected_ckn, timeout=60), \
                "Principal does not match the key server's primary CA"
            assert fallback_link.settled(), \
                "Crossed primary/fallback roles did not forward traffic"
        finally:
            fallback_link.apply_shape(**original)
            assert fallback_link.settled(), \
                "Link did not settle after restoring matching CA roles"
            _assert_two_ca_baseline(fallback_link)

    def test_completely_mismatched_profiles_form_no_session(
            self, duthost, fallback_link):
        """Profiles sharing neither CA form no session through config flow."""
        original = dict(fallback_link.shape)
        wrong_primary_cak, wrong_primary_ckn = fallback_link.new_key_pair()
        wrong_fallback_cak, wrong_fallback_ckn = fallback_link.new_key_pair(
            wrong_primary_ckn)
        mismatched = dict(
            original,
            primary_cak=wrong_primary_cak,
            primary_ckn=wrong_primary_ckn,
            fallback_cak=wrong_fallback_cak,
            fallback_ckn=wrong_fallback_ckn)
        try:
            _replace_peer_profile(fallback_link, mismatched)
            assert wait_until(
                60, 2, 0,
                lambda: get_participant_by_ckn(
                    fallback_link.nbr["host"],
                    fallback_link.nbr["port"],
                    wrong_primary_ckn) is not None), \
                "Peer did not install its mismatched primary participant"
            assert wait_until(
                60, 2, 0,
                lambda: get_participant_by_ckn(
                    fallback_link.nbr["host"],
                    fallback_link.nbr["port"],
                    wrong_fallback_ckn) is not None), \
                "Peer did not install its mismatched fallback participant"
            assert _no_session_stable(
                duthost, fallback_link.dut_port), \
                "Mismatched profiles formed a session or installed SAs"
        finally:
            fallback_link.apply_shape(**original)
            assert fallback_link.settled(), \
                "Link did not settle after restoring matching profiles"
            _assert_two_ca_baseline(fallback_link)

    def test_delete_profile_in_use_is_rejected(self, duthost, deployed_fallback_link):
        """Deleting a profile still bound to a port is rejected."""
        result = duthost.command(
            "config macsec {} profile del {}".format(
                getns_prefix(duthost, deployed_fallback_link.dut_port),
                deployed_fallback_link.profile_name),
            module_ignore_errors=True)

        assert result["rc"] != 0, \
            "Deleting {}, which {} is bound to, was accepted".format(
                deployed_fallback_link.profile_name, deployed_fallback_link.dut_port)
        output = "{}\n{}".format(result.get("stdout", ""), result.get("stderr", ""))
        assert "being used by port" in output, \
            "Delete was rejected, but not because the profile is in use: {}".format(
                output.strip())

        # The rejection has to be a no-op, not a partial delete.
        assert deployed_fallback_link.wait_cas_live(timeout=60), \
            "A rejected profile delete disturbed the link"
