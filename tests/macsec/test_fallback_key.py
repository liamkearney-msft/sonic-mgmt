"""MACsec fallback CA lifecycle, driven through ``config macsec`` commands.

A MACsec profile may carry a second, standby CA -- the fallback key. Its job is
to keep a port protected at moments when the primary CA cannot: while the
primary key is being rolled over, or when the two ends have been given
different primary keys because a rollout is only half done. These tests cover
that lifecycle the way it is operated in production:

* ``config macsec profile add --fallback_cak --fallback_ckn`` provisions the
  standby CA;
* a full profile replacement (unbind, ``profile del``, ``profile add``, rebind)
  adds or removes the fallback afterwards, because ``profile add`` refuses to
  touch a profile that exists and ``profile del`` refuses to drop one a port is
  bound to;
* ``config macsec profile update`` re-keys one CA at a time, which is what
  drives a link onto -- and back off -- its fallback.

CONFIG_DB is written once, when the testbed is deployed. Nothing here writes to
it directly and nothing here talks to the wpa_supplicant control socket: an
operator has neither, so a test that used them would not be testing the
product.

Scope note: asymmetric cold-start and crossed-CKN scenarios that need the two
ends provisioned differently *before* the link ever comes up are not covered,
because the testbed fixtures bring both ends up together.
"""
import logging

import pytest

from tests.common.macsec.macsec_config_helper import rotate_macsec_profile_key
from tests.common.macsec.macsec_helper import (
    get_appl_db,
    get_mka_participants,
    get_participant_by_ckn,
    get_principal_ckn,
    getns_prefix,
    wait_for_ckn_live,
)
from tests.common.utilities import wait_until
from tests.macsec.macsec_key_helpers import (
    make_dedicated_link,
    restore_baseline_link,
    wait_principal_ckn,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


@pytest.fixture(scope="module")
def fallback_link(duthost, ctrl_links, upstream_links, get_port_profile,
                  default_priority, cipher_suite, policy, send_sci,
                  rekey_period, wait_mka_establish):
    """One control link on a dedicated two-CA profile: a primary and a fallback.

    Every test in this module is handed the link in that shape and has to give
    it back in that shape, so the tests stay independent of the order they run
    in. The two tests that need a different shape replace the profile and
    restore it in a ``finally`` block.
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


def _ns_option(duthost, dut_port):
    """The ``-n <namespace>`` option a config command needs for ``dut_port``.

    ``config macsec`` is mandatory-namespaced on a multi-ASIC host, and the
    helpers hide that; a test that calls the CLI directly has to supply it.
    """
    return getns_prefix(duthost, dut_port)


def _assert_two_ca_baseline(link):
    """Assert the link is back in the shape the fixture guarantees."""
    assert link.wait_cas_live(), \
        "Link {} did not return to two live CAs".format(link.dut_port)
    assert wait_principal_ckn(link.duthost, link.dut_port,
                              link.shape["primary_ckn"], timeout=180), \
        "Principal did not return to the primary CA on {}".format(link.dut_port)


class TestMacsecFallbackKey():
    """The standby CA: how it is provisioned, what it protects, how it is removed."""

    def test_fallback_profile_brings_up_two_participants(self, duthost, fallback_link):
        """A profile carrying the fallback fields runs two CAs, one principal.

        This is what ``config macsec profile add --fallback_cak --fallback_ckn``
        is supposed to produce: both CKNs negotiated with the peer, exactly one
        of them elected principal and actually protecting traffic, the other
        standing by and flagged as the fallback.
        """
        dut_port = fallback_link.dut_port
        participants = get_mka_participants(duthost, dut_port)
        assert len(participants) >= 2, \
            "Fallback profile did not bring up two participants, found {}".format(
                len(participants))

        principals = [p for p in participants
                      if str(p.get("is_principal")).lower() == "yes"]
        assert len(principals) == 1, \
            "Expected exactly one principal, found {}".format(len(principals))

        standby = [p for p in participants
                   if str(p.get("is_principal")).lower() != "yes"]
        assert all(str(p.get("is_fallback")).lower() == "yes" for p in standby), \
            "Non-principal participant is not flagged is_fallback=yes"

        ckns = {p.get("ckn", "").lower() for p in participants}
        assert fallback_link.shape["primary_ckn"].lower() in ckns
        assert fallback_link.shape["fallback_ckn"].lower() in ckns
        for participant in participants:
            assert int(participant.get("live_peers", 0)) >= 1, \
                "Participant {} has no live peer".format(participant.get("ckn"))

    def test_add_fallback_by_profile_replacement(self, duthost, fallback_link):
        """A profile with no fallback gains one through a full replacement.

        ``config macsec profile add`` will not edit a profile that already
        exists, so adding a standby CA to a live profile is the unbind /
        ``profile del`` / ``profile add`` / rebind sequence. The port is down
        for the duration -- this is a maintenance operation, not a hitless one --
        so what matters is that it comes back with both CAs negotiated.
        """
        dut_port = fallback_link.dut_port
        fb_cak = fallback_link.shape["fallback_cak"]
        fb_ckn = fallback_link.shape["fallback_ckn"]

        try:
            # Down to a single-CA profile, which is the state a link that was
            # never given a fallback key is in.
            fallback_link.apply_shape(fallback_cak=None, fallback_ckn=None)
            assert fallback_link.settled(), \
                "Link did not settle on the single-CA profile"
            assert get_participant_by_ckn(duthost, dut_port, fb_ckn) is None, \
                "Standby CA survived a replacement that dropped the fallback key"

            # And back up to two CAs, which is the operation under test.
            fallback_link.apply_shape(fallback_cak=fb_cak, fallback_ckn=fb_ckn)
            assert fallback_link.settled(), \
                "Link did not settle after the fallback key was added back"
            assert wait_for_ckn_live(duthost, dut_port, fb_ckn, timeout=180), \
                "Standby CA did not negotiate a live peer after being added"

            participants = get_mka_participants(duthost, dut_port)
            assert len(participants) >= 2, \
                "Adding the fallback key did not bring up a second CA, found {}".format(
                    len(participants))
        finally:
            if fallback_link.shape["fallback_ckn"] != fb_ckn:
                fallback_link.apply_shape(fallback_cak=fb_cak, fallback_ckn=fb_ckn)
                fallback_link.settled()
            _assert_two_ca_baseline(fallback_link)

    def test_remove_fallback_preserves_the_principal(self, duthost, fallback_link):
        """Dropping the standby CA leaves the principal and the datapath alone.

        Removing a fallback key is a planned operation on a live link, so the
        CA that is actually protecting traffic must not be disturbed by it: the
        principal stays on the same CKN and the receive SC keeps carrying
        traffic.
        """
        dut_port = fallback_link.dut_port
        nbr = fallback_link.nbr
        primary_ckn = fallback_link.shape["primary_ckn"]
        fb_cak = fallback_link.shape["fallback_cak"]
        fb_ckn = fallback_link.shape["fallback_ckn"]

        assert wait_principal_ckn(duthost, dut_port, primary_ckn), \
            "Principal did not start on the primary CA"

        try:
            fallback_link.apply_shape(fallback_cak=None, fallback_ckn=None)
            assert fallback_link.settled(), \
                "Link did not settle after the fallback key was removed"

            assert wait_until(
                120, 2, 0,
                lambda: get_participant_by_ckn(duthost, dut_port, fb_ckn) is None), \
                "Standby CA was not removed when the fallback key was dropped"
            assert wait_principal_ckn(duthost, dut_port, primary_ckn), \
                "Principal changed when the fallback key was removed"

            _, _, ingress_sc, egress_sa, ingress_sa = get_appl_db(
                duthost, dut_port, nbr["host"], nbr["port"])
            assert ingress_sc and egress_sa and ingress_sa, \
                "Datapath torn down when the fallback key was removed"
        finally:
            fallback_link.apply_shape(fallback_cak=fb_cak, fallback_ckn=fb_ckn)
            fallback_link.settled()
            _assert_two_ca_baseline(fallback_link)

    def test_primary_rollover_fails_over_and_back(self, duthost, fallback_link):
        """A half-finished primary rollover falls back, and recovers when it finishes.

        Rolling a primary key over a fleet is not atomic: for a while one end
        of a link has the new key and the other still has the old one, and the
        primary CA cannot form. That is exactly what the fallback key is for --
        the standby CA, which both ends still share, takes over and the port
        keeps forwarding.

        The fallback is a stopgap, not a destination, so finishing the rollover
        on the lagging end has to hand the port back to the primary CA;
        otherwise a fleet would quietly end up running on its standby keys.

        Rotating one end at a time reproduces the whole sequence using nothing
        but the rollover command itself.
        """
        dut_port = fallback_link.dut_port
        nbr = fallback_link.nbr
        old_ckn = fallback_link.shape["primary_ckn"]
        old_cak = fallback_link.shape["primary_cak"]
        fb_ckn = fallback_link.shape["fallback_ckn"]
        new_cak, new_ckn = fallback_link.new_key_pair()

        try:
            # Only the DUT end moves, so the two ends no longer share a primary.
            rotate_macsec_profile_key(duthost, fallback_link.profile_name,
                                      old_ckn, new_ckn, new_cak)
            fallback_link.shape.update(primary_cak=new_cak, primary_ckn=new_ckn)

            assert wait_principal_ckn(duthost, dut_port, fb_ckn, timeout=180), \
                "Principal did not fail over to the fallback CA after the two " \
                "ends were left with different primary keys"

            _, _, ingress_sc, egress_sa, ingress_sa = get_appl_db(
                duthost, dut_port, nbr["host"], nbr["port"])
            assert ingress_sc and egress_sa and ingress_sa, \
                "Datapath torn down while running on the fallback CA"

            # Finish the rollover on the peer; the primary CA can form again.
            rotate_macsec_profile_key(nbr["host"], fallback_link.profile_name,
                                      old_ckn, new_ckn, new_cak)

            assert wait_for_ckn_live(duthost, dut_port, new_ckn, timeout=180), \
                "New primary CA did not negotiate a live peer once both ends " \
                "had been rotated"
            assert wait_principal_ckn(duthost, dut_port, new_ckn, timeout=180), \
                "Principal did not fail back to the primary CA after the " \
                "rollover completed"
            assert get_principal_ckn(duthost, dut_port) != fb_ckn.lower(), \
                "Link is still running on its fallback CA"
        finally:
            # Leave the fixture's baseline key in place for the next test. If
            # the peer never got the new key, put it there first so both ends
            # are rotating the same CA back.
            if get_participant_by_ckn(nbr["host"], nbr["port"], new_ckn) is None:
                rotate_macsec_profile_key(nbr["host"], fallback_link.profile_name,
                                          old_ckn, new_ckn, new_cak)
            for host, port, _ in fallback_link.hosts:
                rotate_macsec_profile_key(host, fallback_link.profile_name,
                                          new_ckn, old_ckn, old_cak)
            fallback_link.shape.update(primary_cak=old_cak, primary_ckn=old_ckn)
            _assert_two_ca_baseline(fallback_link)

    def test_delete_profile_in_use_is_rejected(self, duthost, fallback_link):
        """``config macsec profile del`` refuses to strip a port of its keys.

        Deleting a profile a port is bound to would leave that port configured
        for MACsec with no key to use, so the CLI rejects it and names the port.
        This is the guard rail that makes the replacement sequence in these
        tests -- unbind first, then delete -- the only way round.
        """
        result = duthost.command(
            "config macsec {} profile del {}".format(
                _ns_option(duthost, fallback_link.dut_port),
                fallback_link.profile_name),
            module_ignore_errors=True)

        assert result["rc"] != 0, \
            "Deleting {}, which {} is bound to, was accepted".format(
                fallback_link.profile_name, fallback_link.dut_port)
        output = "{}\n{}".format(result.get("stdout", ""), result.get("stderr", ""))
        assert "being used by port" in output, \
            "Delete was rejected, but not because the profile is in use: {}".format(
                output.strip())

        # The rejection has to be a no-op, not a partial delete.
        assert fallback_link.wait_cas_live(timeout=60), \
            "A rejected profile delete disturbed the link"
