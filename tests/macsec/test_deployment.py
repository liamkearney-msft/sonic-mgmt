import pytest
import logging

from tests.common.utilities import wait_until, ping_ip
from tests.common import config_reload
from tests.common.reboot import reboot
from tests.common.macsec.macsec_helper import (
    check_appl_db,
    get_appl_db,
    get_ipnetns_prefix,
)
from tests.common.macsec.failure_safe_cleanup import (
    FailureSafeCleanup,
    preserve_config_db_files,
)
from tests.common.macsec.mka_state_helper import (
    get_mka_state,
    mka_state_cli_supported,
    validate_mka_snapshot,
)
from time import sleep
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "lrh", "urh", "t0-sonic"),
]


def _mka_operational_state_ok(
        duthost, ctrl_links, macsec_profile, port_profiles):
    if not mka_state_cli_supported(duthost):
        return True
    for port in ctrl_links:
        profile = port_profiles[port] if port_profiles else macsec_profile
        session, participants = get_mka_state(duthost, port)
        if validate_mka_snapshot(
                session, participants, profile, profile["primary_ckn"]):
            return False
    return True


def _routed_traffic_ok(duthost, ctrl_links, upstream_links):
    for port in ctrl_links:
        if port not in upstream_links:
            continue
        if not ping_ip(
                duthost, upstream_links[port]["local_ipv4_addr"],
                count=4, cmd_prefix=get_ipnetns_prefix(duthost, port)):
            return False
    return True


class TestDeployment():
    MKA_TIMEOUT = 6

    @pytest.mark.disable_loganalyzer
    def test_config_reload(
            self, duthost, ctrl_links, policy, cipher_suite, send_sci,
            macsec_profile, port_profiles, upstream_links,
            wait_mka_establish):
        """Verify MACsec participant, SC/SA, and traffic recovery after reload."""
        with preserve_config_db_files(duthost):
            duthost.shell("config save -y")
            config_reload(duthost)
        assert wait_until(300, 6, 12, check_appl_db, duthost, ctrl_links, policy, cipher_suite, send_sci)
        assert wait_until(
            300, 5, 0,
            _mka_operational_state_ok,
            duthost, ctrl_links, macsec_profile, port_profiles,
        ), "MKA participant state did not recover after config reload"
        assert wait_until(
            120, 5, 0,
            _routed_traffic_ok, duthost, ctrl_links, upstream_links,
        ), "Routed MACsec traffic did not recover after config reload"

    @pytest.mark.reboot
    @pytest.mark.disable_loganalyzer
    def test_reboot_with_fallback_profile(
            self, duthost, localhost, ctrl_links, policy, cipher_suite,
            send_sci, macsec_profile, port_profiles, upstream_links,
            wait_mka_establish):
        """Verify a persisted dual-CA profile recovers after a cold reboot."""
        if port_profiles or macsec_profile["name"] != "MACSEC_PROFILE_FALLBACK":
            pytest.skip(
                "Run one bounded reboot with the static fallback profile")

        with preserve_config_db_files(duthost):
            duthost.shell("config save -y")
            reboot(
                duthost, localhost, reboot_type="cold",
                safe_reboot=True, check_intf_up_ports=True,
                wait_for_bgp=True)
        assert wait_until(
            300, 6, 12, check_appl_db, duthost, ctrl_links,
            policy, cipher_suite, send_sci,
        ), "APPL_DB did not recover after reboot"
        assert wait_until(
            300, 5, 0,
            _mka_operational_state_ok,
            duthost, ctrl_links, macsec_profile, port_profiles,
        ), "Dual-CA MKA state did not recover after reboot"
        assert wait_until(
            120, 5, 0,
            _routed_traffic_ok, duthost, ctrl_links, upstream_links,
        ), "Routed MACsec traffic did not recover after reboot"

    @pytest.mark.disable_loganalyzer
    def test_scale_rekey(self, duthost, ctrl_links, rekey_period, wait_mka_establish):
        """Verify every selected MACsec link recovers and periodically rekeys."""
        dut_egress_sa_table_orig = {}
        dut_ingress_sa_table_orig = {}
        dut_egress_sa_table_current = {}
        dut_ingress_sa_table_current = {}
        new_dut_egress_sa_table = {}
        new_dut_ingress_sa_table = {}

        with FailureSafeCleanup("MACsec scale interface flap") as cleanup:
            # Shut the interface and wait for all macsec sessions to be down
            for dut_port, nbr in ctrl_links.items():
                _, _, _, dut_egress_sa_table_orig[dut_port], dut_ingress_sa_table_orig[dut_port] = get_appl_db(
                    duthost, dut_port, nbr["host"], nbr["port"])
                intf_asic = duthost.get_port_asic_instance(dut_port)
                intf_asic.shutdown_interface(dut_port)
                cleanup.callback(intf_asic.startup_interface, dut_port)

            sleep(TestDeployment.MKA_TIMEOUT)
            cleanup.restore()

        for dut_port, nbr in ctrl_links.items():
            def check_new_mka_session():
                _, _, _, dut_egress_sa_table_current[dut_port], dut_ingress_sa_table_current[dut_port] = get_appl_db(
                    duthost, dut_port, nbr["host"], nbr["port"])
                if dut_egress_sa_table_orig[dut_port] and dut_egress_sa_table_current[dut_port]:
                    assert dut_egress_sa_table_orig[dut_port] != dut_egress_sa_table_current[dut_port]
                if dut_ingress_sa_table_orig[dut_port] and dut_ingress_sa_table_current[dut_port]:
                    assert dut_ingress_sa_table_orig[dut_port] != dut_ingress_sa_table_current[dut_port]
                return True
            assert wait_until(30, 2, 2, check_new_mka_session)

        # if rekey_period for the profile is valid, Wait for rekey and make sure all sessions are present
        if rekey_period != 0:
            sleep(rekey_period * 2)

            for dut_port, nbr in ctrl_links.items():
                _, _, _, new_dut_egress_sa_table[dut_port], new_dut_ingress_sa_table[dut_port] = get_appl_db(
                    duthost, dut_port, nbr["host"], nbr["port"])
                if dut_egress_sa_table_current[dut_port] and new_dut_egress_sa_table[dut_port]:
                    assert dut_egress_sa_table_current[dut_port] != new_dut_egress_sa_table[dut_port]
                if dut_ingress_sa_table_current[dut_port] and new_dut_ingress_sa_table[dut_port]:
                    assert dut_ingress_sa_table_current[dut_port] != new_dut_ingress_sa_table[dut_port]

    @pytest.mark.stress_test
    def test_all_eligible_links(
            self, request, duthost, ctrl_links, nbrhosts, upstream_links,
            macsec_profile, port_profiles, policy, cipher_suite, send_sci,
            wait_mka_establish):
        """Verify fallback MKA on every opt-in eligible neighbor link."""
        if not request.config.getoption("--macsec_all_links"):
            pytest.skip("Requires --macsec_all_links")
        if not macsec_profile.get("fallback_ckn"):
            pytest.skip("Requires a fallback-enabled base profile")

        assert len(ctrl_links) == len(nbrhosts), (
            "Expected every eligible neighbor link to be controlled"
        )
        if port_profiles:
            assert set(port_profiles) == set(ctrl_links)
        assert wait_until(
            300, 6, 0, check_appl_db, duthost, ctrl_links,
            policy, cipher_suite, send_sci,
        )
        assert wait_until(
            300, 5, 0,
            _mka_operational_state_ok,
            duthost, ctrl_links, macsec_profile, port_profiles,
        )
        for port, neighbor in ctrl_links.items():
            assert duthost.iface_macsec_ok(port)
            assert neighbor["host"].iface_macsec_ok(neighbor["port"])
        assert wait_until(
            120, 5, 0,
            _routed_traffic_ok, duthost, ctrl_links, upstream_links,
        )
