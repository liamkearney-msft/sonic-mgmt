import ast
import importlib.util
from pathlib import Path

import pytest


HELPER_PATH = (
    Path(__file__).resolve().parents[2]
    / "macsec" / "failure_safe_cleanup.py"
)
DEPLOYMENT_PATH = (
    Path(__file__).resolve().parents[3]
    / "macsec" / "test_deployment.py"
)
INTEROP_PATH = (
    Path(__file__).resolve().parents[3]
    / "macsec" / "test_interop_protocol.py"
)

SPEC = importlib.util.spec_from_file_location(
    "failure_safe_cleanup", HELPER_PATH)
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)


class _Logger:
    def error(self, *args):
        pass

    def exception(self, *args):
        pass


HELPERS.logger = _Logger()
FailureSafeCleanup = HELPERS.FailureSafeCleanup
preserve_config_db_files = HELPERS.preserve_config_db_files


class _Host:
    def __init__(self, fail_fragment=None):
        self.fail_fragment = fail_fragment
        self.commands = []

    def shell(self, command, module_ignore_errors=False):
        self.commands.append((command, module_ignore_errors))
        if self.fail_fragment and self.fail_fragment in command:
            return {"failed": True, "rc": 1, "stdout": ""}
        if command.startswith("mktemp "):
            return {
                "failed": False,
                "rc": 0,
                "stdout": "/tmp/macsec_config_backup.ABC123\n",
            }
        return {"failed": False, "rc": 0, "stdout": ""}


def _function_calls(path, function_name):
    tree = ast.parse(path.read_text())
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == function_name
    )
    return {
        node.func.id
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
    }


@pytest.mark.parametrize("failure", ["reload failed", "reboot failed"])
def test_config_backup_restores_files_after_transition_failure(failure):
    """Restore every persisted config file when a transition raises."""
    host = _Host()
    with pytest.raises(ValueError, match=failure):
        with preserve_config_db_files(host):
            raise ValueError(failure)
    commands = [command for command, _ in host.commands]
    assert commands == [
        "mktemp -d /tmp/macsec_config_backup.XXXXXX",
        "sudo cp -a /etc/sonic/config_db*.json "
        "/tmp/macsec_config_backup.ABC123/",
        "sudo cp -a /tmp/macsec_config_backup.ABC123/"
        "config_db*.json /etc/sonic/",
        "sudo rm -rf -- /tmp/macsec_config_backup.ABC123",
    ]


def test_config_backup_cleanup_failure_does_not_mask_body_error():
    """Keep the transition failure authoritative if restore also fails."""
    host = _Host(fail_fragment="config_db*.json /etc/sonic/")
    with pytest.raises(ValueError, match="traffic failed"):
        with preserve_config_db_files(host):
            raise ValueError("traffic failed")
    assert any(
        command.startswith("sudo rm -rf --")
        for command, _ in host.commands)


def test_config_backup_restore_failure_surfaces_after_success():
    """Surface persisted-config restoration failure after a green body."""
    host = _Host(fail_fragment="config_db*.json /etc/sonic/")
    with pytest.raises(
            RuntimeError,
            match="preserving SONiC configuration"):
        with preserve_config_db_files(host):
            pass


def test_cleanup_stack_restores_only_successful_partial_mutations():
    """Restore registered mutations in reverse without broad reset."""
    events = []
    with pytest.raises(ValueError, match="third disable failed"):
        with FailureSafeCleanup("partial disable") as cleanup:
            events.append("disable-dut")
            cleanup.callback(events.append, "enable-dut")
            events.append("disable-peer")
            cleanup.callback(events.append, "enable-peer")
            raise ValueError("third disable failed")
    assert events == [
        "disable-dut",
        "disable-peer",
        "enable-peer",
        "enable-dut",
    ]


def test_cleanup_stack_supports_precise_portchannel_restore_order():
    """Run MACsec enable before the final PortChannel member add."""
    events = []
    with FailureSafeCleanup("portchannel order") as cleanup:
        cleanup.callback(events.append, "enable-macsec")
        cleanup.callback(
            events.append, "add-member", _run_last=True)
    assert events == ["enable-macsec", "add-member"]


def test_cleanup_stack_preserves_body_error_when_cleanup_fails():
    """Do not replace a product assertion with cleanup failure."""
    def _failed_cleanup():
        raise RuntimeError("cleanup failed")

    with pytest.raises(ValueError, match="protocol failed"):
        with FailureSafeCleanup("body precedence") as cleanup:
            cleanup.callback(_failed_cleanup)
            raise ValueError("protocol failed")


def test_deployment_transitions_use_persisted_config_guard():
    """Guard both config reload and reboot persisted-file mutations."""
    assert "preserve_config_db_files" in _function_calls(
        DEPLOYMENT_PATH, "test_config_reload")
    assert "preserve_config_db_files" in _function_calls(
        DEPLOYMENT_PATH, "test_reboot_with_fallback_profile")
    assert "FailureSafeCleanup" in _function_calls(
        DEPLOYMENT_PATH, "test_scale_rekey")


@pytest.mark.parametrize(
    "function_name",
    ["test_port_channel", "test_lldp", "test_bgp"],
)
def test_interop_mutations_use_failure_safe_cleanup(function_name):
    """Require cleanup ownership around every interop port mutation."""
    assert "FailureSafeCleanup" in _function_calls(
        INTEROP_PATH, function_name)
