import ast
import hashlib
import re
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest


HELPER_PATH = (
    Path(__file__).resolve().parents[2] / "macsec" / "fallback_cak_helper.py"
)
MKA_HELPER_PATH = HELPER_PATH.with_name("mka_state_helper.py")
FALLBACK_TEST_PATH = (
    Path(__file__).resolve().parents[3] / "macsec" / "test_fallback_cak.py"
)


def _load_mka_validator():
    source = MKA_HELPER_PATH.read_text()
    tree = ast.parse(source)
    names = {
        "REQUIRED_SESSION_FIELDS",
        "REQUIRED_PARTICIPANT_FIELDS",
        "validate_mka_snapshot",
        "validate_point_to_point_ingress_sc",
    }
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = {
                target.id for target in node.targets
                if isinstance(target, ast.Name)
            }
            if targets.intersection(names):
                nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            nodes.append(node)
    namespace = {}
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]),
                str(MKA_HELPER_PATH), "exec"),
        namespace,
    )
    return namespace


def _load_fallback_helpers():
    source = HELPER_PATH.read_text()
    tree = ast.parse(source)
    names = {
        "MutationResult",
        "LinkSnapshot",
        "MkaStateReader",
        "StateDbMkaReader",
        "read_link_snapshot",
        "PeerAdapter",
        "EosPeerAdapter",
        "peer_adapter",
    }
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name in names:
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            nodes.append(node)
        elif isinstance(node, ast.Assign):
            targets = {
                target.id for target in node.targets
                if isinstance(target, ast.Name)
            }
            if "STATE_DB_READER" in targets:
                nodes.append(node)

    mka = _load_mka_validator()

    class _EosHost:
        pass

    namespace = {
        "dataclass": dataclass,
        "hashlib": hashlib,
        "EosHost": _EosHost,
        "get_mka_state": lambda host, port: ({}, {}),
        "get_appl_db": lambda *args: ({}, {}, {}, {}, {}),
        "get_macsec_profile_config": lambda *args: {},
        "get_macsec_ingress_sc_state": lambda *args: [],
        "get_macsec_teardown_state": lambda *args: {
            "port_enable": "false",
            "egress_sa_keys": [],
            "ingress_sa_keys": [],
        },
        "parse_eos_mka_participants": lambda output, port: {},
        "parse_eos_profile_ckns": lambda output, profile: set(),
        "validate_mka_snapshot": mka["validate_mka_snapshot"],
        "validate_point_to_point_ingress_sc":
            mka["validate_point_to_point_ingress_sc"],
        "delete_macsec_profile": lambda *args, **kwargs: None,
        "disable_macsec_port": lambda *args, **kwargs: None,
        "enable_macsec_port": lambda *args, **kwargs: None,
        "set_macsec_profile": lambda *args, **kwargs: None,
        "update_macsec_profile_key": lambda *args, **kwargs: None,
    }
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]),
                str(HELPER_PATH), "exec"),
        namespace,
    )
    return namespace


HELPERS = _load_fallback_helpers()
LinkSnapshot = HELPERS["LinkSnapshot"]
MkaStateReader = HELPERS["MkaStateReader"]
StateDbMkaReader = HELPERS["StateDbMkaReader"]
PeerAdapter = HELPERS["PeerAdapter"]
EosPeerAdapter = HELPERS["EosPeerAdapter"]
peer_adapter = HELPERS["peer_adapter"]
read_link_snapshot = HELPERS["read_link_snapshot"]
EosHost = HELPERS["EosHost"]


def _load_traffic_window():
    source = FALLBACK_TEST_PATH.read_text()
    tree = ast.parse(source)
    traffic_window = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "_TrafficWindow"
    )
    stopped = []

    def _cleanup_all(items, cleanup):
        errors = []
        for item in items:
            try:
                cleanup(item)
            except Exception as error:
                errors.append(error)
        if errors:
            raise errors[0]

    class _Logger:
        def exception(self, message):
            pass

    namespace = {
        "AbstractContextManager": AbstractContextManager,
        "cleanup_all": _cleanup_all,
        "_start_bidirectional_traffic": lambda *args: ["one", "two"],
        "_stop_ping": lambda ping, assert_loss=True: stopped.append(
            (ping, assert_loss)) or {"ping": ping},
        "logger": _Logger(),
    }
    exec(
        compile(ast.Module(body=[traffic_window], type_ignores=[]),
                str(FALLBACK_TEST_PATH), "exec"),
        namespace,
    )
    return namespace["_TrafficWindow"], namespace, stopped


def _load_ping_helpers():
    source = FALLBACK_TEST_PATH.read_text()
    tree = ast.parse(source)
    names = {
        "_parse_ping_output",
        "_ping_observation_result",
        "_read_ping_output",
        "_ping_process_running",
        "_drain_ping_observation",
        "_stop_ping",
        "_macsecmgrd_restart_known_failure",
    }
    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    namespace = {
        "re": re,
        "wait_until": (
            lambda timeout, interval, delay, function: function()),
    }
    exec(
        compile(ast.Module(body=functions, type_ignores=[]),
                str(FALLBACK_TEST_PATH), "exec"),
        namespace,
    )
    return namespace


def _load_primary_mismatch(
        adapter, wait_link, wait_peer, wait_removed):
    source = FALLBACK_TEST_PATH.read_text()
    tree = ast.parse(source)
    mismatch = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_primary_mismatch"
    )

    class _Logger:
        def __init__(self):
            self.errors = []

        def error(self, *args):
            self.errors.append(args)

    logger = _Logger()
    namespace = {
        "contextmanager": contextmanager,
        "peer_adapter": lambda environment, port: adapter,
        "_wait_link_protected": wait_link,
        "_wait_peer_protected": wait_peer,
        "_wait_peer_primary_removed": wait_removed,
        "_safe_diagnostics": lambda environment, port: {"redacted": True},
        "logger": logger,
    }
    exec(
        compile(ast.Module(body=[mismatch], type_ignores=[]),
                str(FALLBACK_TEST_PATH), "exec"),
        namespace,
    )
    return namespace["_primary_mismatch"], logger


def _load_fallback_mismatch(
        adapter, wait_link, wait_peer, wait_blocked):
    source = FALLBACK_TEST_PATH.read_text()
    tree = ast.parse(source)
    mismatch = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_ceos_fallback_mismatch"
    )

    class _Logger:
        def __init__(self):
            self.errors = []

        def error(self, *args):
            self.errors.append(args)

    logger = _Logger()
    namespace = {
        "contextmanager": contextmanager,
        "_snapshot": lambda environment, port: type(
            "Snapshot", (), {"session": {"last_updated": "old"}})(),
        "_wait_link_blocked": wait_blocked,
        "_wait_peer_blocked": lambda *args, **kwargs: None,
        "_wait_link_protected": wait_link,
        "_wait_peer_protected": wait_peer,
        "_safe_diagnostics": lambda environment, port: {"redacted": True},
        "logger": logger,
    }
    exec(
        compile(ast.Module(body=[mismatch], type_ignores=[]),
                str(FALLBACK_TEST_PATH), "exec"),
        namespace,
    )
    return namespace["_ceos_fallback_mismatch"], logger


def _profile():
    return {
        "name": "fallback",
        "priority": 64,
        "cipher_suite": "GCM-AES-128",
        "primary_cak": "primary-secret",
        "primary_ckn": "AABB",
        "fallback_cak": "fallback-secret",
        "fallback_ckn": "CCDD",
        "policy": "security",
        "send_sci": True,
        "rekey_period": 0,
    }


def _session(**updates):
    session = {
        "profile": "fallback",
        "kay_status": "active",
        "authenticated": "false",
        "secured": "true",
        "failed": "false",
        "actor_sci": "0011",
        "actor_priority": "64",
        "key_server_priority": "64",
        "is_key_server": "true",
        "keys_distributed": "1",
        "keys_received": "1",
        "mka_hello_time_ms": "2000",
        "query_status": "ok",
        "last_updated": "new",
        "config_status": "in-sync",
    }
    session.update(updates)
    return session


def _participant(primary, principal, live_peers=1, **updates):
    participant = {
        "participant_index": "0",
        "mi": "0011",
        "mn": "1",
        "active": "true",
        "retain": "false",
        "is_principal": str(principal).lower(),
        "is_primary": str(primary).lower(),
        "live_peers": str(live_peers),
        "potential_peers": "0",
        "is_key_server": "true",
        "is_elected": "true",
    }
    participant.update(updates)
    return participant


def _protected_snapshot(authoritative=False, controlled_port=True):
    return LinkSnapshot(
        port="Ethernet0",
        profile_name="fallback",
        profile_config={},
        session=_session(),
        participants={
            "aabb": _participant(True, True),
            "ccdd": _participant(False, False),
        },
        appl_port={"enable": "true"},
        egress_sc={"encoding_an": "1"},
        egress_sas={1: {"sak": "installed-secret", "ssci": "7"}},
        ingress_scs=[{
            "sci": "peer",
            "sas": {1: {"active": "true", "sak": "received-secret"}},
        }],
        controlled_port=controlled_port,
        controlled_port_authoritative=authoritative,
    )


def _blocked_snapshot(authoritative=False, controlled_port=True):
    return LinkSnapshot(
        port="Ethernet0",
        profile_name="fallback",
        profile_config={},
        session=_session(secured="false"),
        participants={
            "aabb": _participant(True, False, live_peers=0),
            "ccdd": _participant(False, False, live_peers=0),
        },
        appl_port={"enable": "false"},
        egress_sc={"encoding_an": "0"},
        egress_sas={},
        ingress_scs=[],
        controlled_port=controlled_port,
        controlled_port_authoritative=authoritative,
    )


def _environment(host):
    profile = _profile()
    return {
        "duthost": object(),
        "links": {"Ethernet0": {"host": host, "port": "Ethernet4"}},
        "profile": dict(profile),
        "neighbor_profiles": {"Ethernet0": "fallback"},
        "neighbor_priorities": {"Ethernet0": 64},
        "peer_profiles": {"Ethernet0": dict(profile)},
    }


class _Host:
    def __init__(self):
        self.eos_config_calls = []
        self.eos_command_result = {"stdout": [{}, ""]}
        self.controlled_port = True

    def eos_config(self, **kwargs):
        self.eos_config_calls.append(kwargs)

    def eos_command(self, **kwargs):
        return self.eos_command_result

    def iface_macsec_ok(self, port):
        return self.controlled_port


class _EosFakeHost(EosHost, _Host):
    def __init__(self):
        _Host.__init__(self)


class _MismatchAdapter:
    def __init__(
            self, supports_primary_delete=False,
            restore_error=None):
        self.supports_primary_delete = supports_primary_delete
        self.restore_error = restore_error
        self.calls = []
        self.committed_profiles = []

    @staticmethod
    def profile_with_pair(profile, role, pair):
        updated = dict(profile)
        updated["{}_cak".format(role)] = pair[0]
        updated["{}_ckn".format(role)] = pair[1]
        return updated

    def delete_primary_if_supported(self, pair):
        self.calls.append(("delete", pair))

    def add_primary(self, pair):
        self.calls.append(("add", pair))

    def delete_fallback(self, pair):
        self.calls.append(("delete-fallback", pair))

    def add_fallback(self, pair):
        self.calls.append(("add-fallback", pair))

    def rotate(self, role, old_pair, new_pair, **kwargs):
        self.calls.append(("rotate", role, old_pair, new_pair, kwargs))

    def commit_profile(self, profile):
        self.committed_profiles.append(dict(profile))

    def restore_primary(self, original_profile, mismatched_pair):
        self.calls.append(("restore", mismatched_pair))
        if self.restore_error:
            raise self.restore_error

    def restore_fallback(self, original_profile, mismatched_pair):
        self.calls.append(("restore-fallback", mismatched_pair))
        if self.restore_error:
            raise self.restore_error


class _PingHost:
    def __init__(
            self, pre_stop_output, final_output,
            initially_running=True, signal_failed=False,
            exits_after_signal=True, drain_output=None):
        self.pre_stop_output = pre_stop_output
        self.drain_output = (
            pre_stop_output if drain_output is None else drain_output)
        self.final_output = final_output
        self.running = initially_running
        self.signal_failed = signal_failed
        self.exits_after_signal = exits_after_signal
        self.signal_sent = False
        self.running_read_count = 0
        self.commands = []

    def shell(self, command, module_ignore_errors=False):
        self.commands.append(command)
        if command.startswith("cat "):
            if not self.signal_sent:
                self.running_read_count += 1
            return {
                "stdout": (
                    self.final_output if self.signal_sent
                    else (
                        self.pre_stop_output
                        if self.running_read_count == 1
                        else self.drain_output)),
                "failed": False,
            }
        if "kill -0" in command:
            if self.signal_sent and self.exits_after_signal:
                self.running = False
            return {"failed": not self.running}
        if "kill -INT" in command:
            self.signal_sent = True
            return {"failed": self.signal_failed}
        if "kill -TERM" in command:
            self.running = False
            return {"failed": False}
        if command.startswith("rm -f "):
            return {"failed": False}
        raise AssertionError("Unexpected command {}".format(command))


def _ping_output(
        sequences, transmitted=None, received=None, extra_lines=()):
    lines = [
        "[1.0] 64 bytes from 10.0.0.1: icmp_seq={} ttl=64 time=0.1 ms"
        .format(sequence)
        for sequence in sequences
    ]
    lines.extend(extra_lines)
    if transmitted is not None:
        lines.extend([
            "--- 10.0.0.1 ping statistics ---",
            "{} packets transmitted, {} received, "
            "0.1% packet loss, time 1ms".format(
                transmitted, received),
        ])
    return "\n".join(lines)


def test_link_snapshot_accepts_complete_protected_state():
    """Evaluate protection from published session, SC, and SA state."""
    snapshot = _protected_snapshot()
    assert snapshot.protected_errors(_profile(), "AABB") == []
    assert snapshot.principal_ckns() == ["aabb"]


def test_sonic_controlled_port_helper_is_diagnostic_only():
    """Do not reject SONiC protection from its non-authoritative helper."""
    snapshot = _protected_snapshot(
        authoritative=False, controlled_port=False)
    assert snapshot.protected_errors(_profile(), "AABB") == []
    snapshot.controlled_port_authoritative = True
    assert snapshot.protected_errors(
        _profile(), "AABB") == ["provider controlled port is closed"]


@pytest.mark.parametrize(
    "mutation, expected_error",
    [
        (lambda snapshot: snapshot.appl_port.update(enable="false"),
         "APPL_DB controlled port is not enabled"),
        (lambda snapshot: snapshot.egress_sas.clear(),
         "egress encoding SA 1 is missing"),
        (lambda snapshot: snapshot.ingress_scs.clear(),
         "expected one ingress SC, found 0: []"),
    ],
)
def test_link_snapshot_rejects_incomplete_protection(
        mutation, expected_error):
    """Reject disabled or incomplete protected-link publication."""
    snapshot = _protected_snapshot()
    mutation(snapshot)
    assert expected_error in snapshot.protected_errors(
        _profile(), "AABB")


def test_blocked_state_uses_published_teardown_not_sonic_helper():
    """Accept SONiC teardown even if its legacy helper still reports ok."""
    snapshot = _blocked_snapshot(
        authoritative=False, controlled_port=True)
    assert snapshot.blocked_errors(("AABB", "CCDD")) == []
    snapshot.controlled_port_authoritative = True
    assert snapshot.blocked_errors(
        ("AABB", "CCDD")) == [
            "provider controlled port remains open"]


@pytest.mark.parametrize(
    "mutation, expected_error",
    [
        (lambda snapshot: snapshot.session.update(secured="true"),
         "session is still secured"),
        (lambda snapshot: snapshot.appl_port.update(enable="true"),
         "APPL_DB controlled port is enabled"),
        (lambda snapshot: snapshot.egress_sas.update(
            {1: {"sak": "secret"}}),
         "MACsec SAs remain installed"),
        (lambda snapshot: snapshot.participants["aabb"].update(
            live_peers="invalid"),
         "aabb has invalid live_peers"),
    ],
)
def test_link_snapshot_rejects_incomplete_teardown(
        mutation, expected_error):
    """Reject stale session, port, SA, and participant teardown state."""
    snapshot = _blocked_snapshot()
    mutation(snapshot)
    assert expected_error in snapshot.blocked_errors(("AABB", "CCDD"))


def test_snapshot_diagnostics_are_redacted_and_sci_is_optional():
    """Expose normalized identities without logging SAK or CAK material."""
    snapshot = _protected_snapshot()
    identity = snapshot.active_key_identity()
    diagnostics = snapshot.redacted()
    rendered = repr((identity, diagnostics))
    assert "installed-secret" not in rendered
    assert "received-secret" not in rendered
    assert "primary-secret" not in rendered
    assert identity[1] == hashlib.sha256(
        b"installed-secret").hexdigest()
    assert snapshot.optional_key_server_sci is None
    snapshot.session["key_server_sci"] = "0011"
    assert snapshot.optional_key_server_sci == "0011"


def test_normalized_reader_seam_does_not_expose_external_layout():
    """Keep callers bound to the normalized reader contract."""
    with pytest.raises(NotImplementedError):
        MkaStateReader().read(object(), "Ethernet0")
    HELPERS["get_mka_state"] = lambda host, port: (
        {"profile": "fallback"}, {"aabb": {}})
    assert StateDbMkaReader().read(object(), "Ethernet0") == (
        {"profile": "fallback"}, {"aabb": {}})


def test_read_link_snapshot_uses_injected_normalized_reader(monkeypatch):
    """Build a link snapshot without coupling callers to STATE_DB layout."""
    class _Reader:
        def read(self, host, port):
            return _session(), {
                "aabb": _participant(True, True),
                "ccdd": _participant(False, False),
            }

    host = _Host()
    monkeypatch.setitem(
        HELPERS, "get_appl_db",
        lambda *args: (
            {"enable": "true"},
            {"encoding_an": "1"},
            {}, {1: {"sak": "secret"}}, {},
        ))
    monkeypatch.setitem(
        HELPERS, "get_macsec_profile_config",
        lambda *args: {"primary_ckn": "AABB"})
    monkeypatch.setitem(
        HELPERS, "get_macsec_ingress_sc_state",
        lambda *args: [{"sci": "peer", "sas": {1: {"active": "true"}}}])
    snapshot = read_link_snapshot(
        host,
        "Ethernet0",
        {"host": object(), "port": "Ethernet4"},
        "fallback",
        reader=_Reader(),
    )
    assert snapshot.profile_name == "fallback"
    assert snapshot.controlled_port_authoritative is False
    assert snapshot.ingress_scs[0]["sci"] == "peer"


def test_sonic_adapter_rotates_and_tracks_profile(monkeypatch):
    """Centralize SONiC profile mutation and environment bookkeeping."""
    calls = []
    monkeypatch.setitem(
        HELPERS, "update_macsec_profile_key",
        lambda *args, **kwargs: calls.append((args, kwargs)))
    environment = _environment(_Host())
    adapter = PeerAdapter(environment, "Ethernet0")
    result = adapter.rotate(
        "fallback", ("old-cak", "old-ckn"),
        ("new-cak", "new-ckn"))
    assert result.provider == "peer"
    assert result.operation == "rotate_fallback"
    assert calls[0][1]["is_fallback"] is True
    assert environment["peer_profiles"]["Ethernet0"]["fallback_ckn"] == (
        "new-ckn")
    unsupported = adapter.delete_primary_if_supported(("cak", "ckn"))
    assert adapter.supports_primary_delete is False
    assert unsupported.supported is False


def test_adapter_can_defer_profile_commit_until_runtime_verification(
        monkeypatch):
    """Keep rollback state authoritative until mutation verification passes."""
    monkeypatch.setitem(
        HELPERS, "update_macsec_profile_key",
        lambda *args, **kwargs: None)
    environment = _environment(_Host())
    original = dict(environment["peer_profiles"]["Ethernet0"])
    adapter = PeerAdapter(environment, "Ethernet0")
    result = adapter.rotate(
        "primary",
        (original["primary_cak"], original["primary_ckn"]),
        ("new-cak", "new-ckn"),
        commit=False,
        base_profile=original,
    )
    assert environment["peer_profiles"]["Ethernet0"] == original
    assert result.profile["primary_ckn"] == "new-ckn"
    adapter.commit_profile(result.profile)
    assert environment["peer_profiles"]["Ethernet0"]["primary_ckn"] == (
        "new-ckn")


def test_sonic_adapter_rebind_and_restore_order(monkeypatch):
    """Apply destructive profile changes through one ordered adapter path."""
    calls = []
    monkeypatch.setitem(
        HELPERS, "disable_macsec_port",
        lambda host, port: calls.append(("disable", port)))
    monkeypatch.setitem(
        HELPERS, "delete_macsec_profile",
        lambda host, name: calls.append(("delete", name)))
    monkeypatch.setitem(
        HELPERS, "set_macsec_profile",
        lambda host, name, *args: calls.append(("set", name)))
    monkeypatch.setitem(
        HELPERS, "enable_macsec_port",
        lambda host, port, name: calls.append(("enable", port, name)))
    environment = _environment(_Host())
    adapter = PeerAdapter(environment, "Ethernet0")
    adapter.restore("fallback", _profile())
    assert calls == [
        ("disable", "Ethernet4"),
        ("delete", "fallback"),
        ("set", "fallback"),
        ("enable", "Ethernet4", "fallback"),
    ]


def test_adapter_replaces_profile_with_provider_priority(monkeypatch):
    """Centralize detach, replacement, rebind, and profile bookkeeping."""
    calls = []
    monkeypatch.setitem(
        HELPERS, "disable_macsec_port",
        lambda host, port: calls.append(("disable", port)))
    monkeypatch.setitem(
        HELPERS, "delete_macsec_profile",
        lambda host, name: calls.append(("delete", name)))
    monkeypatch.setitem(
        HELPERS, "set_macsec_profile",
        lambda host, name, priority, *args:
            calls.append(("set", name, priority)))
    monkeypatch.setitem(
        HELPERS, "enable_macsec_port",
        lambda host, port, name: calls.append(("enable", port, name)))
    environment = _environment(_Host())
    adapter = PeerAdapter(environment, "Ethernet0")
    replacement = dict(_profile(), primary_ckn="EEFF")
    adapter.replace_profile("fallback", replacement, priority=7)
    assert calls == [
        ("disable", "Ethernet4"),
        ("delete", "fallback"),
        ("set", "fallback", 7),
        ("enable", "Ethernet4", "fallback"),
    ]
    assert environment["peer_profiles"]["Ethernet0"] == replacement


def test_sonic_peer_blocked_requires_fresh_in_sync_publication():
    """Reject stale or unhealthy peer publication during both-invalid."""
    environment = _environment(_Host())
    adapter = PeerAdapter(environment, "Ethernet0")
    snapshot = _blocked_snapshot()
    snapshot.session["last_updated"] = "old"
    adapter.snapshot = lambda: snapshot
    assert adapter.blocked_errors(
        ("AABB", "CCDD"), previous_last_updated="old") == [
            "peer STATE_DB publication is stale"]
    snapshot.session.update(
        query_status="error",
        config_status="out-of-sync",
        last_updated="new",
    )
    assert adapter.blocked_errors(
        ("AABB", "CCDD"), previous_last_updated="old") == [
            "query_status is not ok",
            "config_status is not in-sync",
        ]


def test_ceos_adapter_uses_exact_supported_key_lines():
    """Delete and restore cEOS primary through exact profile key lines."""
    host = _EosFakeHost()
    adapter = EosPeerAdapter(_environment(host), "Ethernet0")
    assert adapter.supports_primary_delete is True
    removed = adapter.delete_primary_if_supported(("cak", "AABB"))
    added = adapter.add_primary(("cak", "AABB"))
    assert removed.supported is True
    assert host.eos_config_calls == [
        {
            "lines": ["no key AABB 7 cak"],
            "parents": ["mac security", "profile fallback"],
        },
        {
            "lines": ["key AABB 7 cak"],
            "parents": ["mac security", "profile fallback"],
        },
    ]
    assert added.operation == "add_primary"


def test_ceos_primary_removal_requires_config_and_runtime_absence():
    """Reject a cEOS deletion until only the live fallback actor remains."""
    adapter = EosPeerAdapter(_environment(_EosFakeHost()), "Ethernet0")
    adapter.snapshot = lambda profile=None: {
        "configured_ckns": {"ccdd"},
        "participants": {
            "ccdd": {
                "success": True,
                "active": True,
                "live_peers": 1,
            },
        },
        "controlled_port": True,
    }
    assert adapter.primary_removed_errors(_profile()) == []
    adapter.snapshot = lambda profile=None: {
        "configured_ckns": {"aabb", "ccdd"},
        "participants": {
            "aabb": {
                "success": True,
                "active": True,
                "live_peers": 1,
            },
            "ccdd": {
                "success": True,
                "active": True,
                "live_peers": 1,
            },
        },
        "controlled_port": True,
    }
    errors = adapter.primary_removed_errors(_profile())
    assert "configured CKN set does not contain only fallback" in errors
    assert "removed primary remains in runtime participants" in errors


def test_ceos_restore_primary_handles_each_partial_mutation():
    """Restore original config after delete-only or invalid-primary setup."""
    host = _EosFakeHost()
    adapter = EosPeerAdapter(_environment(host), "Ethernet0")
    invalid_pair = ("invalid-cak", "EEFF")
    adapter.snapshot = lambda profile=None: {
        "configured_ckns": {"ccdd"},
        "participants": {},
        "controlled_port": False,
    }
    adapter.restore_primary(_profile(), invalid_pair)
    adapter.snapshot = lambda profile=None: {
        "configured_ckns": {"ccdd", "eeff"},
        "participants": {},
        "controlled_port": False,
    }
    adapter.restore_primary(_profile(), invalid_pair)
    assert host.eos_config_calls == [
        {
            "lines": ["key AABB 7 primary-secret"],
            "parents": ["mac security", "profile fallback"],
        },
        {
            "lines": [
                "no key EEFF 7 invalid-cak",
                "key AABB 7 primary-secret",
            ],
            "parents": ["mac security", "profile fallback"],
        },
    ]


def test_ceos_fallback_mutations_use_exact_supported_key_lines():
    """Delete, add, and restore fallback with full cEOS key syntax."""
    host = _EosFakeHost()
    adapter = EosPeerAdapter(_environment(host), "Ethernet0")
    invalid_pair = ("invalid-cak", "EEFF")
    adapter.delete_fallback(("fallback-secret", "CCDD"))
    adapter.add_fallback(invalid_pair)
    adapter.snapshot = lambda profile=None: {
        "configured_ckns": {"aabb", "eeff"},
        "participants": {},
        "controlled_port": False,
    }
    adapter.restore_fallback(_profile(), invalid_pair)
    assert host.eos_config_calls == [
        {
            "lines": ["no key CCDD 7 fallback-secret fallback"],
            "parents": ["mac security", "profile fallback"],
        },
        {
            "lines": ["key EEFF 7 invalid-cak fallback"],
            "parents": ["mac security", "profile fallback"],
        },
        {
            "lines": [
                "no key EEFF 7 invalid-cak fallback",
                "key CCDD 7 fallback-secret fallback",
            ],
            "parents": ["mac security", "profile fallback"],
        },
    ]


def test_ceos_blocked_state_rejects_stale_runtime_participant():
    """Require exact cEOS configured and runtime CKN sets when blocked."""
    adapter = EosPeerAdapter(_environment(_EosFakeHost()), "Ethernet0")
    adapter.snapshot = lambda: {
        "configured_ckns": {"aabb", "ccdd"},
        "participants": {
            "aabb": {"live_peers": 0},
            "ccdd": {"live_peers": 0},
            "eeff": {"live_peers": 0},
        },
        "controlled_port": False,
    }
    assert adapter.blocked_errors(("AABB", "CCDD")) == [
        "runtime participant CKN set does not match"]


def test_peer_adapter_selects_provider():
    """Select cEOS only for an EOS host and SONiC otherwise."""
    assert isinstance(
        peer_adapter(_environment(_EosFakeHost()), "Ethernet0"),
        EosPeerAdapter)
    assert type(peer_adapter(
        _environment(_Host()), "Ethernet0")) is PeerAdapter


def test_primary_mismatch_context_uses_ceos_delete_first_and_restores():
    """Delete the live cEOS primary before installing a mismatch."""
    adapter = _MismatchAdapter(supports_primary_delete=True)
    waits = []
    mismatch, _ = _load_primary_mismatch(
        adapter,
        lambda *args, **kwargs: waits.append(("link", args[2])),
        lambda *args, **kwargs: waits.append(("peer", args[2])),
        lambda *args, **kwargs: waits.append(("removed", None)),
    )
    environment = _environment(_Host())
    invalid_pair = ("invalid-cak", "EEFF")
    with mismatch(environment, "Ethernet0", invalid_pair):
        waits.append(("body", None))
    assert [call[0] for call in adapter.calls] == [
        "delete", "add", "restore"]
    assert waits == [
        ("link", "CCDD"),
        ("removed", None),
        ("link", "CCDD"),
        ("peer", "CCDD"),
        ("body", None),
        ("link", "AABB"),
        ("peer", "AABB"),
    ]
    assert adapter.committed_profiles[0]["primary_ckn"] == "EEFF"
    assert adapter.committed_profiles[-1]["primary_ckn"] == "AABB"


def test_primary_mismatch_context_restores_after_setup_failure():
    """Own rollback before the first mutating operation can fail."""
    adapter = _MismatchAdapter(supports_primary_delete=True)
    calls = []

    def _wait_link(*args, **kwargs):
        calls.append("wait-link")
        if len(calls) == 1:
            raise AssertionError("fallback did not establish")

    mismatch, _ = _load_primary_mismatch(
        adapter, _wait_link,
        lambda *args, **kwargs: None,
        lambda *args, **kwargs: None,
    )
    environment = _environment(_Host())
    with pytest.raises(
            AssertionError, match="fallback did not establish"):
        with mismatch(
                environment, "Ethernet0", ("invalid-cak", "EEFF")):
            pass
    assert [call[0] for call in adapter.calls] == ["delete", "restore"]
    assert environment["peer_profiles"]["Ethernet0"]["primary_ckn"] == (
        "AABB")
    assert adapter.committed_profiles[-1]["primary_ckn"] == "AABB"


def test_primary_mismatch_context_preserves_body_error_on_cleanup_failure():
    """Keep the scenario failure authoritative when restoration also fails."""
    adapter = _MismatchAdapter(
        supports_primary_delete=False,
        restore_error=RuntimeError("restore failed"),
    )
    mismatch, logger = _load_primary_mismatch(
        adapter,
        lambda *args, **kwargs: None,
        lambda *args, **kwargs: None,
        lambda *args, **kwargs: None,
    )
    environment = _environment(_Host())
    with pytest.raises(ValueError, match="scenario failed"):
        with mismatch(
                environment, "Ethernet0", ("invalid-cak", "EEFF")):
            raise ValueError("scenario failed")
    assert [call[0] for call in adapter.calls] == ["rotate", "restore"]
    assert logger.errors
    assert adapter.committed_profiles[-1]["primary_ckn"] == "AABB"


def test_fallback_mismatch_context_restores_after_setup_failure():
    """Restore the cEOS fallback after a blocked-state setup failure."""
    adapter = _MismatchAdapter()

    def _wait_blocked(*args, **kwargs):
        raise AssertionError("link did not block")

    mismatch, _ = _load_fallback_mismatch(
        adapter,
        lambda *args, **kwargs: None,
        lambda *args, **kwargs: None,
        _wait_blocked,
    )
    environment = _environment(_Host())
    environment["peer_profiles"]["Ethernet0"]["primary_ckn"] = "EEFF"
    with pytest.raises(AssertionError, match="link did not block"):
        with mismatch(
                environment,
                "Ethernet0",
                adapter,
                ("invalid-fallback-cak", "FF00")):
            pass
    assert [call[0] for call in adapter.calls] == [
        "delete-fallback", "restore-fallback"]
    assert adapter.committed_profiles[-1]["fallback_ckn"] == "CCDD"


def test_rejected_rotation_setup_is_owned_by_mismatch_context():
    """Keep setup, verdict, and restoration in one failure-safe scope."""
    tree = ast.parse(FALLBACK_TEST_PATH.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == (
            "test_fallback_rotation_rejected_while_fallback_is_principal")
    )
    mismatch_scope = next(
        node for node in ast.walk(function)
        if isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Name)
            and item.context_expr.func.id == "_primary_mismatch"
            for item in node.items
        )
    )
    calls = {
        node.func.id
        for node in ast.walk(mismatch_scope)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
    }
    assert "_profile_update" in calls
    assert "_TrafficWindow" in calls


def test_ping_stop_excludes_only_the_inflight_trailing_probe():
    """Exclude a post-boundary final probe without tolerating measured loss."""
    helpers = _load_ping_helpers()
    transition_end = _ping_output(range(1, 828))
    drained = _ping_output(range(1, 831))
    final = _ping_output(range(1, 831), transmitted=831, received=830)
    host = _PingHost(
        transition_end, final, drain_output=drained)
    result = helpers["_stop_ping"]({
        "host": host,
        "path": "/tmp/ping.log",
        "pid": 42,
    })
    assert result == {
        "transmitted": 830,
        "received": 830,
        "loss_percent": 0.0,
        "summary_transmitted": 831,
        "summary_received": 830,
        "summary_loss_percent": 0.1,
        "observation_boundary": 830,
    }
    assert "sudo kill -INT 42" in host.commands
    assert "rm -f /tmp/ping.log" in host.commands


def test_ping_stop_rejects_interior_loss_despite_trailing_race():
    """Reject any gap before the pre-SIGINT observation boundary."""
    helpers = _load_ping_helpers()
    transition_sequences = [
        sequence for sequence in range(1, 828)
        if sequence != 417]
    drained_sequences = [
        sequence for sequence in range(1, 831)
        if sequence != 417]
    transition_end = _ping_output(
        transition_sequences,
        extra_lines=(
            "downstream monitor icmp_seq=417 is not a ping reply",
        ),
    )
    drained = _ping_output(
        drained_sequences,
        extra_lines=(
            "downstream monitor icmp_seq=417 is not a ping reply",
        ),
    )
    final = _ping_output(
        drained_sequences, transmitted=831, received=829,
        extra_lines=(
            "downstream monitor icmp_seq=417 is not a ping reply",
        ),
    )
    host = _PingHost(
        transition_end, final, drain_output=drained)
    with pytest.raises(
            AssertionError,
            match="Traffic loss detected during MACsec transition"):
        helpers["_stop_ping"]({
            "host": host,
            "path": "/tmp/ping.log",
            "pid": 42,
        })
    observation = helpers["_ping_observation_result"](
        drained, final)
    assert observation["boundary"] == 830
    assert observation["missing_sequences"] == [417]


def test_ping_drain_exposes_lost_final_transition_probe():
    """Turn a lost transition-tail probe into an interior sequence gap."""
    helpers = _load_ping_helpers()
    transition_end = _ping_output(range(1, 828))
    drained_sequences = list(range(1, 828)) + [829, 830, 831]
    drained = _ping_output(drained_sequences)
    final = _ping_output(
        drained_sequences, transmitted=832, received=830)
    host = _PingHost(
        transition_end, final, drain_output=drained)
    with pytest.raises(
            AssertionError,
            match="Traffic loss detected during MACsec transition"):
        helpers["_stop_ping"]({
            "host": host,
            "path": "/tmp/ping.log",
            "pid": 42,
        })
    observation = helpers["_ping_observation_result"](
        drained, final)
    assert observation["boundary"] == 831
    assert observation["missing_sequences"] == [828]


def test_ping_stop_rejects_process_that_exited_before_boundary():
    """Do not accept a summary from a ping that died before shutdown."""
    helpers = _load_ping_helpers()
    output = _ping_output(
        range(1, 20), transmitted=19, received=19)
    host = _PingHost(
        output,
        output,
        initially_running=False,
        signal_failed=True,
    )
    with pytest.raises(
            AssertionError,
            match="exited before the observation window closed"):
        helpers["_stop_ping"]({
            "host": host,
            "path": "/tmp/ping.log",
            "pid": 42,
        })
    assert "rm -f /tmp/ping.log" in host.commands


@pytest.mark.parametrize(
    "conf_name, asic_type, expected",
    [
        ("vms26-t2-7800-1", "broadcom", True),
        ("vms26-t2-7800-1", "vs", False),
        ("vms27-t2-7800-1", "broadcom", False),
    ],
)
def test_macsecmgrd_restart_skip_is_physical_vms26_only(
        conf_name, asic_type, expected):
    """Skip only the affected physical testbed, never VS or other labs."""
    helpers = _load_ping_helpers()
    duthost = type("Dut", (), {
        "facts": {"asic_type": asic_type},
    })()
    assert helpers["_macsecmgrd_restart_known_failure"](
        duthost, {"conf-name": conf_name}) is expected


def test_traffic_window_stops_each_stream_once_with_strict_verdict():
    """Stop both streams exactly once when the scenario requests verdict."""
    traffic_window, _, stopped = _load_traffic_window()
    with traffic_window(object(), object()) as traffic:
        results = traffic.assert_zero_loss()
    assert results == [{"ping": "one"}, {"ping": "two"}]
    assert stopped == [("one", True), ("two", True)]


def test_traffic_window_preserves_body_error_during_cleanup():
    """Keep the scenario error authoritative and make cleanup diagnostic."""
    traffic_window, namespace, stopped = _load_traffic_window()

    def _failing_stop(ping, assert_loss=True):
        stopped.append((ping, assert_loss))
        if ping == "one":
            raise RuntimeError("cleanup failed")

    namespace["_stop_ping"] = _failing_stop
    with pytest.raises(ValueError, match="scenario failed"):
        with traffic_window(object(), object()):
            raise ValueError("scenario failed")
    assert stopped == [("one", False), ("two", False)]
