"""Unit tests for cSONiC-specific MACsec helper command selection."""

from unittest.mock import MagicMock, patch

from tests.common.devices.csonic import CsonicHost
from tests.common.macsec.macsec_config_helper import enable_macsec_feature
from tests.common.macsec.macsec_helper import get_mka_session
from tests.common.macsec.macsec_platform_helper import get_portchannel, global_cmd
from tests.common.macsec.recovery_helpers import (
    dirty_kill_macsecmgrd,
    dirty_kill_wpa_supplicant,
)


def _result(stdout="", stdout_lines=None, rc=0):
    return {
        "stdout": stdout,
        "stdout_lines": stdout_lines if stdout_lines is not None else [],
        "rc": rc,
    }


def _csonic_host():
    return CsonicHost("csonic_test_VM0152")


def test_global_cmd_skips_csonic_neighbor():
    duthost = MagicMock()
    csonic = _csonic_host()
    with patch.object(csonic, "command") as command:
        global_cmd(duthost, {"neighbor": {"host": csonic}}, "unsupported feature command")
    duthost.command.assert_called_once_with("unsupported feature command")
    command.assert_not_called()


def test_enable_feature_checks_flat_csonic_macsecmgrd_only():
    duthost = MagicMock()
    duthost.num_asics.return_value = 1
    duthost.shell.side_effect = [
        _result(stdout_lines=["macsec"]),
        _result(stdout_lines=["macsecmgrd"]),
    ]
    csonic = _csonic_host()
    with patch.object(csonic, "shell", return_value=_result(stdout_lines=["macsecmgrd"])) as shell, \
            patch("tests.common.macsec.macsec_config_helper.global_cmd"), \
            patch("tests.common.macsec.macsec_config_helper.wait_until", side_effect=lambda *args: args[-1]()):
        enable_macsec_feature(duthost, {"neighbor": {"host": csonic}})
    shell.assert_called_once_with("ps -ef | grep macsecmgrd | grep -v grep")


def test_get_mka_session_uses_flat_command_for_csonic():
    csonic = _csonic_host()
    with patch.object(csonic, "command", return_value=_result(stdout="[]")) as command:
        assert get_mka_session(csonic) == {}
    command.assert_called_once_with("ip -j macsec show")


def test_get_mka_session_preserves_syncd_command_for_sonic():
    sonic = MagicMock()
    sonic.command.return_value = _result(stdout="[]")
    assert get_mka_session(sonic) == {}
    sonic.command.assert_called_once_with("docker exec syncd ip -j macsec show")


def test_recovery_process_signals_run_flat_on_csonic():
    csonic = _csonic_host()
    with patch.object(csonic, "shell") as shell:
        dirty_kill_macsecmgrd(csonic, signal=6)
        dirty_kill_wpa_supplicant(csonic, "Ethernet1")
    assert shell.call_args_list[0].args == ("pkill -6 -x macsecmgrd",)
    assert shell.call_args_list[1].args == ("pkill -9 -f '/var/run/Ethernet1'",)


def test_recovery_process_signals_preserve_macsec_container_for_sonic():
    sonic = MagicMock()
    dirty_kill_macsecmgrd(sonic, signal=6)
    dirty_kill_wpa_supplicant(sonic, "Ethernet1")
    assert sonic.shell.call_args_list[0].args == (
        "docker exec macsec pkill -6 -x macsecmgrd",
    )
    assert sonic.shell.call_args_list[1].args == (
        "docker exec macsec pkill -9 -f '/var/run/Ethernet1'",
    )


def test_get_portchannel_handles_command_failure_and_short_output():
    host = MagicMock()
    host.command.return_value = _result(rc=1)
    assert get_portchannel(host) == {}

    host.command.return_value = _result(stdout_lines=["No PortChannels configured"])
    assert get_portchannel(host) == {}
