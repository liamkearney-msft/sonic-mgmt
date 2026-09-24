import ast
from contextlib import contextmanager
from pathlib import Path

import pytest


RECOVERY_TEST_PATH = (
    Path(__file__).resolve().parents[3]
    / "macsec" / "test_macsec_recovery.py"
)


class _Logger:
    def __init__(self):
        self.errors = []

    def info(self, *args):
        pass

    def error(self, *args):
        self.errors.append(args)


def _load_recovery_helpers(restart, converged=lambda *args: True):
    tree = ast.parse(RECOVERY_TEST_PATH.read_text())
    names = {
        "_macsec_recovery_supported",
        "macsec_recovery_platform",
        "_profile_runtime_fields",
        "_set_profile_runtime_fields",
        "_forced_dut_key_server",
    }
    functions = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name not in names:
            continue
        if node.name == "macsec_recovery_platform":
            node.decorator_list = []
        functions.append(node)
    logger = _Logger()
    namespace = {
        "contextmanager": contextmanager,
        "pytest": pytest,
        "logger": logger,
        "graceful_restart_macsec": restart,
        "wait_for_mka_converged": converged,
    }
    exec(
        compile(
            ast.Module(body=functions, type_ignores=[]),
            str(RECOVERY_TEST_PATH),
            "exec",
        ),
        namespace,
    )
    return namespace, logger


class _Host:
    def __init__(self, multi_asic=False, fail_first_hset=False):
        self.is_multi_asic = multi_asic
        self.fail_first_hset = fail_first_hset
        self.shell_commands = []
        self.hset_calls = 0

    def shell(self, command, module_ignore_errors=False):
        self.shell_commands.append(command)
        if " HGET " in command and command.endswith(" priority"):
            return {"stdout": "64"}
        if " HGET " in command and command.endswith(" rekey_period"):
            return {"stdout": "0"}
        if " HSET " in command:
            self.hset_calls += 1
            if self.fail_first_hset and self.hset_calls == 1:
                raise RuntimeError("partial HSET failure")
            return {"stdout": ""}
        raise AssertionError("Unexpected command {}".format(command))


def test_multi_asic_guard_skips_before_any_config_db_access():
    """Skip unsupported chassis before a namespace-less DB mutation."""
    helpers, _ = _load_recovery_helpers(lambda host: None)
    host = _Host(multi_asic=True)
    with pytest.raises(
            pytest.skip.Exception,
            match="multi-ASIC recovery is unsupported"):
        helpers["macsec_recovery_platform"](host)
    assert host.shell_commands == []


def test_single_asic_guard_preserves_recovery_coverage():
    """Allow supported single-ASIC and VS hosts to run recovery tests."""
    helpers, _ = _load_recovery_helpers(lambda host: None)
    host = _Host(multi_asic=False)
    assert helpers["macsec_recovery_platform"](host) is None
    assert host.shell_commands == []


def test_force_key_server_restores_profile_after_setup_restart_failure():
    """Restore priority and rekey period when setup fails before yield."""
    restarts = []

    def _restart(host):
        restarts.append(host)
        if len(restarts) == 1:
            raise RuntimeError("restart failed")

    helpers, _ = _load_recovery_helpers(_restart)
    host = _Host()
    with pytest.raises(RuntimeError, match="restart failed"):
        with helpers["_forced_dut_key_server"](
                host, "profile", {}, "security", "cipher", "true"):
            pass
    hsets = [
        command for command in host.shell_commands if " HSET " in command]
    assert len(hsets) == 2
    assert "priority 0 rekey_period 0" in hsets[0]
    assert "priority 64 rekey_period 0" in hsets[1]
    assert len(restarts) == 2


def test_force_key_server_restores_after_partial_hset_failure():
    """Attempt restoration even when the initial DB write raises."""
    helpers, _ = _load_recovery_helpers(lambda host: None)
    host = _Host(fail_first_hset=True)
    with pytest.raises(RuntimeError, match="partial HSET failure"):
        with helpers["_forced_dut_key_server"](
                host, "profile", {}, "security", "cipher", "true"):
            pass
    hsets = [
        command for command in host.shell_commands if " HSET " in command]
    assert len(hsets) == 2
    assert "priority 64 rekey_period 0" in hsets[1]


def test_force_key_server_preserves_body_error_when_cleanup_fails():
    """Keep the test failure authoritative if teardown also fails."""
    restart_calls = []

    def _restart(host):
        restart_calls.append(host)
        if len(restart_calls) == 2:
            raise RuntimeError("cleanup restart failed")

    helpers, logger = _load_recovery_helpers(_restart)
    host = _Host()
    with pytest.raises(ValueError, match="test failed"):
        with helpers["_forced_dut_key_server"](
                host, "profile", {}, "security", "cipher", "true"):
            raise ValueError("test failed")
    assert logger.errors
    hsets = [
        command for command in host.shell_commands if " HSET " in command]
    assert len(hsets) == 2
