import ast
import importlib.util
from pathlib import Path

import pytest


HELPER_PATH = (
    Path(__file__).resolve().parents[2] / "macsec" / "mka_state_helper.py"
)
FALLBACK_TEST_PATH = (
    Path(__file__).resolve().parents[3] / "macsec" / "test_fallback_cak.py"
)
SPEC = importlib.util.spec_from_file_location("mka_state_helper", HELPER_PATH)
MKA_STATE_HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MKA_STATE_HELPER)

find_secret_fields = MKA_STATE_HELPER.find_secret_fields
active_key_state = MKA_STATE_HELPER.active_key_state
classify_macsec_teardown = MKA_STATE_HELPER.classify_macsec_teardown
cleanup_all = MKA_STATE_HELPER.cleanup_all
crossed_role_peer_key_server_supported = (
    MKA_STATE_HELPER.crossed_role_peer_key_server_supported
)
eos_key_replacement_status = MKA_STATE_HELPER.eos_key_replacement_status
eos_key_deletion_status = MKA_STATE_HELPER.eos_key_deletion_status
get_macsec_ingress_sc_state = (
    MKA_STATE_HELPER.get_macsec_ingress_sc_state
)
get_macsec_max_sa_per_sc = MKA_STATE_HELPER.get_macsec_max_sa_per_sc
get_macsec_teardown_state = MKA_STATE_HELPER.get_macsec_teardown_state
_mka_show_result_supported = MKA_STATE_HELPER._mka_show_result_supported
_mka_state_cli_supported = MKA_STATE_HELPER.mka_state_cli_supported
macsecmgrd_restart_ready = MKA_STATE_HELPER.macsecmgrd_restart_ready
macsecmgrd_restart_command = MKA_STATE_HELPER.macsecmgrd_restart_command
mka_hello_timeout_seconds = MKA_STATE_HELPER.mka_hello_timeout_seconds
parse_db_hash = MKA_STATE_HELPER.parse_db_hash
parse_eos_profile_ckns = MKA_STATE_HELPER.parse_eos_profile_ckns
parse_eos_mka_participants = MKA_STATE_HELPER.parse_eos_mka_participants
parse_wpa_mka_participants = MKA_STATE_HELPER.parse_wpa_mka_participants
quiescence_budget_seconds = MKA_STATE_HELPER.quiescence_budget_seconds
remaining_link_items = MKA_STATE_HELPER.remaining_link_items
select_independent_port_pair = MKA_STATE_HELPER.select_independent_port_pair
validate_multi_port_alternate_state = (
    MKA_STATE_HELPER.validate_multi_port_alternate_state
)
validate_eos_mka_participants = (
    MKA_STATE_HELPER.validate_eos_mka_participants
)
validate_point_to_point_ingress_sc = (
    MKA_STATE_HELPER.validate_point_to_point_ingress_sc
)
validate_mka_snapshot = MKA_STATE_HELPER.validate_mka_snapshot
validate_lifecycle_cleanup_state = (
    MKA_STATE_HELPER.validate_lifecycle_cleanup_state
)


class _FakeHost:
    def __init__(self, result):
        self.result = result
        self.commands = []

    def command(self, command, **kwargs):
        self.commands.append((command, kwargs))
        return self.result


class _CommandHost:
    def __init__(self, results, multi_asic=False):
        self.results = results
        self.is_multi_asic = multi_asic
        self.commands = []

    def get_port_asic_instance(self, interface):
        return type("Asic", (), {"asic_index": 0})()

    def get_namespace_from_asic_id(self, asic_index):
        return "asic{}".format(asic_index)

    def command(self, command, **kwargs):
        self.commands.append(command)
        return self.results.get(
            command, {"failed": False, "stdout": "", "stdout_lines": []})


def _profile():
    return {
        "name": "MACSEC_PROFILE_FALLBACK",
        "primary_ckn": "AABB",
        "fallback_ckn": "CCDD",
    }


def _session():
    return {
        "profile": "MACSEC_PROFILE_FALLBACK",
        "kay_status": "active",
        "authenticated": "false",
        "secured": "true",
        "failed": "false",
        "actor_sci": "0011223344550001",
        "key_server_sci": "0011223344550001",
        "actor_priority": "64",
        "key_server_priority": "63",
        "is_key_server": "false",
        "keys_distributed": "0",
        "keys_received": "1",
        "mka_hello_time_ms": "2000",
        "query_status": "ok",
        "last_updated": "2026-09-17T00:00:00Z",
        "config_status": "in-sync",
    }


def _participant(is_primary, is_principal):
    return {
        "participant_index": "0",
        "mi": "00112233445566778899aabb",
        "mn": "10",
        "active": "true",
        "retain": "false",
        "is_principal": is_principal,
        "is_primary": is_primary,
        "live_peers": "1",
        "potential_peers": "0",
        "is_key_server": "false",
        "is_elected": "true",
    }


@pytest.mark.parametrize(
    "output, expected",
    [
        ('{"field": "value"}', {"field": "value"}),
        ("{'field': 7}", {"field": "7"}),
        ("field\nvalue\ncount\n2\n", {"field": "value", "count": "2"}),
        ("", {}),
    ],
)
def test_parse_db_hash(output, expected):
    """Parse JSON, Python-literal, line-pair, and empty DB output."""
    assert parse_db_hash(output) == expected


@pytest.mark.parametrize(
    "result",
    [
        {
            "failed": False,
            "rc": 0,
            "stdout": "Interface  KaY  Secured  Principal CKN\n",
            "stderr": "",
        },
        {"failed": False, "rc": 0, "stdout": "", "stderr": ""},
    ],
)
def test_mka_state_cli_supported(result):
    """Accept successful populated and empty canonical MKA show output."""
    host = _FakeHost(result)
    assert _mka_state_cli_supported(host)
    assert host.commands == [
        (
            "show macsec --mka",
            {"module_ignore_errors": True, "verbose": False},
        )
    ]


@pytest.mark.parametrize(
    "result",
    [
        {
            "failed": True,
            "rc": 127,
            "stdout": "",
            "stderr": "show: command not found",
        },
        {
            "failed": False,
            "rc": 0,
            "stdout": "",
            "stderr": "Error: No such option: --mka",
        },
        {
            "failed": False,
            "rc": 2,
            "stdout": "Usage: show macsec [OPTIONS]",
            "stderr": "",
        },
    ],
)
def test_mka_state_cli_unsupported(result):
    """Reject command-not-found, unsupported-option, and nonzero results."""
    assert not _mka_show_result_supported(result)


def test_parse_db_hash_rejects_partial_pair():
    """Reject malformed line-pair output rather than fabricating a value."""
    with pytest.raises(ValueError):
        parse_db_hash("field\nvalue\norphan")


def test_validate_primary_fallback_snapshot():
    """Accept latest-schema participants without the removed participant field."""
    participants = {
        "aabb": _participant("true", "true"),
        "ccdd": _participant("false", "false"),
    }
    assert validate_mka_snapshot(
        _session(), participants, _profile(), "AABB") == []


@pytest.mark.parametrize(
    "required_field",
    [
        "participant_index",
        "mi",
        "mn",
        "active",
        "retain",
        "is_principal",
        "is_primary",
        "live_peers",
        "potential_peers",
        "is_key_server",
        "is_elected",
    ],
)
def test_validate_snapshot_rejects_missing_required_participant_field(
        required_field):
    """Reject latest-schema participant rows missing a required field."""
    participants = {
        "aabb": _participant("true", "true"),
        "ccdd": _participant("false", "false"),
    }
    del participants["ccdd"][required_field]
    errors = validate_mka_snapshot(
        _session(), participants, _profile(), "AABB")
    assert "ccdd missing fields: ['{}']".format(required_field) in errors


@pytest.mark.parametrize(
    "updates, expected_error",
    [
        (
            {"authenticated": "true", "secured": "false"},
            "authenticated='true', expected 'false'",
        ),
        (
            {"authenticated": "true", "secured": "true"},
            "authenticated='true', expected 'false'",
        ),
        (
            {"authenticated": "false", "secured": "false"},
            "secured='false', expected 'true'",
        ),
        (
            {"kay_status": "not-active"},
            "kay_status='not-active', expected 'active'",
        ),
        (
            {"failed": "true"},
            "failed='true', expected 'false'",
        ),
    ],
)
def test_validate_snapshot_rejects_unhealthy_controlled_port(
        updates, expected_error):
    """Reject unprotected, contradictory, inactive, and failed CP states."""
    session = _session()
    session.update(updates)
    participants = {
        "aabb": _participant("true", "true"),
        "ccdd": _participant("false", "false"),
    }
    errors = validate_mka_snapshot(
        session, participants, _profile(), "AABB")
    assert expected_error in errors


def test_validate_snapshot_reports_role_and_liveness_errors():
    """Report an unsafe fallback and unexpected principal ownership."""
    participants = {
        "aabb": _participant("true", "false"),
        "ccdd": _participant("true", "true"),
    }
    participants["ccdd"]["live_peers"] = "0"
    errors = validate_mka_snapshot(
        _session(), participants, _profile(), "AABB")
    assert any("is_primary" in error for error in errors)
    assert any("no live peer" in error for error in errors)
    assert any("principal CKNs" in error for error in errors)


def test_dut_principal_mismatch_remains_strict():
    """Reject a DUT snapshot whose principal differs from the expectation."""
    participants = {
        "aabb": _participant("true", "false"),
        "ccdd": _participant("false", "true"),
    }
    errors = validate_mka_snapshot(
        _session(), participants, _profile(), "AABB")
    assert "principal CKNs ['ccdd'], expected aabb" in errors


def test_peer_snapshot_can_ignore_principal_flags():
    """Validate peer connectivity without using peer ownership flags."""
    participants = {
        "aabb": _participant("true", "false"),
        "ccdd": _participant("false", "false"),
    }
    assert validate_mka_snapshot(
        _session(), participants, _profile(), "AABB",
        require_principal=False) == []


def test_find_secret_fields_is_allowlist_safe():
    """Detect key material fields without flagging key-server metadata."""
    state = {
        "session": {"is_key_server": "true", "key_server_sci": "0011"},
        "participant": {"sak": "secret", "auth_key": "secret"},
    }
    assert find_secret_fields(state) == [
        "participant.sak",
        "participant.auth_key",
    ]


def test_parse_eos_mka_participants_normalizes_roles_and_peers():
    """Preserve principal/default state without inferring configured role."""
    output = {
        "interfaces": {
            "Ethernet1": {
                "participants": {
                    "AABB": {
                        "success": True,
                        "electedSelf": False,
                        "defaultActor": False,
                        "principalActor": True,
                        "details": {
                            "livePeerList": ["peer"],
                            "sakTransmit": True,
                        },
                    },
                    "CCDD": {
                        "Success": "Yes",
                        "Elected-Self": "No",
                        "Default": "Yes",
                        "Principal": "No",
                        "Details": {
                            "Live Peers": 1,
                            "SAK Transmit": "No",
                        },
                    },
                }
            }
        }
    }
    participants = parse_eos_mka_participants(output, "ethernet1")
    assert participants["aabb"] == {
        "success": True,
        "active": True,
        "failed": False,
        "is_principal": True,
        "default_actor": False,
        "is_key_server": False,
        "live_peers": 1,
        "sak_transmit": True,
    }
    assert participants["ccdd"]["active"]
    assert participants["ccdd"]["default_actor"]
    assert participants["ccdd"]["live_peers"] == 1


@pytest.mark.parametrize(
    "principal_ckns",
    [set(), {"aabb"}, {"aabb", "ccdd"}],
)
def test_validate_eos_operational_ignores_ownership_flags(principal_ckns):
    """Accept zero, one, or multiple diagnostic EOS principal flags."""
    participants = {
        "aabb": {
            "success": True,
            "active": True,
            "failed": False,
            "is_principal": "aabb" in principal_ckns,
            "default_actor": False,
            "live_peers": 1,
        },
        "ccdd": {
            "success": True,
            "active": True,
            "failed": False,
            "is_principal": "ccdd" in principal_ckns,
            "default_actor": True,
            "live_peers": 1,
        },
    }
    assert validate_eos_mka_participants(
        participants,
        {
            "primary_ckn": "AABB",
            "fallback_ckn": "CCDD",
        },
        controlled_port=True,
    ) == []


@pytest.mark.parametrize(
    "participants, controlled_port, expected_error",
    [
        (
            {
                "aabb": {
                    "success": True, "active": True, "failed": False,
                    "live_peers": 1,
                },
            },
            True,
            "participant CKNs ['aabb'], expected ['aabb', 'ccdd']",
        ),
        (
            {
                "aabb": {
                    "success": False, "active": True, "failed": False,
                    "live_peers": 1,
                },
                "ccdd": {
                    "success": True, "active": True, "failed": False,
                    "live_peers": 1,
                },
            },
            True,
            "aabb is not successful",
        ),
        (
            {
                "aabb": {
                    "success": True, "active": False, "failed": False,
                    "live_peers": 1,
                },
                "ccdd": {
                    "success": True, "active": True, "failed": False,
                    "live_peers": 1,
                },
            },
            True,
            "aabb is not active",
        ),
        (
            {
                "aabb": {
                    "success": True, "active": True, "failed": True,
                    "live_peers": 1,
                },
                "ccdd": {
                    "success": True, "active": True, "failed": False,
                    "live_peers": 1,
                },
            },
            True,
            "aabb is failed",
        ),
        (
            {
                "aabb": {
                    "success": True, "active": True, "failed": False,
                    "live_peers": 0,
                },
                "ccdd": {
                    "success": True, "active": True, "failed": False,
                    "live_peers": 1,
                },
            },
            True,
            "aabb has no live peer",
        ),
        (
            {
                "aabb": {
                    "success": True, "active": True, "failed": False,
                    "live_peers": 1,
                },
                "ccdd": {
                    "success": True, "active": True, "failed": False,
                    "live_peers": 1,
                },
            },
            False,
            "controlled port is not open",
        ),
    ],
)
def test_validate_eos_operational_rejects_unhealthy_state(
        participants, controlled_port, expected_error):
    """Reject wrong CKN, unsuccessful, no-live, or closed cEOS state."""
    errors = validate_eos_mka_participants(
        participants,
        {
            "primary_ckn": "AABB",
            "fallback_ckn": "CCDD",
        },
        controlled_port=controlled_port,
    )
    assert expected_error in errors


def test_parse_wpa_mka_participants():
    """Parse primary/fallback roles from runtime supplicant output."""
    output = """
participant_idx=0
ckn=AABB
active=Yes participant=Yes retain=No
is_principal=No is_primary=Yes
live_peers=0 potential_peers=0

participant_idx=1
ckn=CCDD
active=Yes participant=Yes retain=No
is_principal=Yes is_primary=No
live_peers=1 potential_peers=0
"""
    assert parse_wpa_mka_participants(output) == {
        "aabb": {
            "active": True,
            "is_principal": False,
            "is_primary": True,
            "live_peers": 0,
        },
        "ccdd": {
            "active": True,
            "is_principal": True,
            "is_primary": False,
            "live_peers": 1,
        },
    }


@pytest.mark.parametrize(
    "entries, expected_error",
    [
        ([], "expected one ingress SC, found 0: []"),
        (
            [
                {"key": "one", "sci": "0011", "sas": {}},
                {"key": "two", "sci": "0022", "sas": {}},
            ],
            "expected one ingress SC, found 2: ['one', 'two']",
        ),
    ],
)
def test_validate_ingress_sc_count(entries, expected_error):
    """Reject zero or multiple point-to-point ingress SCs."""
    assert validate_point_to_point_ingress_sc(entries) == [expected_error]


def test_enumerate_actual_ingress_sc_and_active_sa():
    """Enumerate the actual APPL_DB SCI rather than synthesizing a peer SCI."""
    keys_cmd = (
        "sonic-db-cli -n asic0 APPL_DB KEYS "
        "'MACSEC_INGRESS_SC_TABLE:Ethernet0:*'"
    )
    sc_key = "MACSEC_INGRESS_SC_TABLE:Ethernet0:aabbccdd00000001"
    host = _CommandHost(
        {
            keys_cmd: {
                "failed": False,
                "stdout_lines": [sc_key],
            },
            "sonic-db-cli -n asic0 APPL_DB HGETALL '{}'".format(sc_key): {
                "failed": False,
                "stdout": "{'encoding_an': '0'}",
            },
            "sonic-db-cli -n asic0 APPL_DB HGETALL "
            "'MACSEC_INGRESS_SA_TABLE:Ethernet0:aabbccdd00000001:0'": {
                "failed": False,
                "stdout": "{'active': 'true', 'sak': 'redacted'}",
            },
        },
        multi_asic=True,
    )
    entries = get_macsec_ingress_sc_state(host, "Ethernet0")
    assert entries[0]["sci"] == "aabbccdd00000001"
    assert entries[0]["sas"][0]["active"] == "true"
    assert validate_point_to_point_ingress_sc(entries) == []


def test_active_key_state_excludes_cumulative_counters():
    """Keep quiescence stable when only cumulative MKA counters change."""
    participants = {
        "aabb": {"is_principal": "true"},
        "ccdd": {"is_principal": "false"},
    }
    egress_sc = {"encoding_an": "1"}
    egress_sas = {
        0: {"sak": "old"},
        1: {
            "sak": "secret-egress-sak",
            "salt": "secret-egress-salt",
            "ssci": "1",
        },
    }
    ingress_scs = [{
        "sci": "peer",
        "sas": {
            1: {
                "active": "true",
                "sak": "secret-ingress-sak",
            },
        },
    }]
    first = active_key_state(
        {"keys_distributed": "1", "keys_received": "2",
         "kay_status": "active", "secured": "true"},
        participants, egress_sc, egress_sas, ingress_scs)
    second = active_key_state(
        {"keys_distributed": "99", "keys_received": "100",
         "kay_status": "active", "secured": "true"},
        participants, egress_sc, egress_sas, ingress_scs)
    assert first == second
    assert "secret-egress-sak" not in repr(first)
    assert "secret-egress-salt" not in repr(first)
    assert "secret-ingress-sak" not in repr(first)
    changed = active_key_state(
        {"kay_status": "active", "secured": "true"},
        participants, {"encoding_an": "0"}, egress_sas, ingress_scs)
    assert changed != first


@pytest.mark.parametrize(
    "session, intervals, expected",
    [
        ({"mka_hello_time_ms": "2000"}, 4, 8),
        ({"mka_hello_time_ms": "2000"}, 6, 12),
        ({}, 4, 8),
    ],
)
def test_mka_hello_timeout_seconds(session, intervals, expected):
    """Derive four/six-hello protocol bounds with a safe default."""
    assert mka_hello_timeout_seconds(session, intervals) == expected


@pytest.mark.parametrize("value", ["bad", "0", "-1"])
def test_mka_hello_timeout_rejects_malformed(value):
    """Use the default only for a missing field, not malformed state."""
    with pytest.raises(ValueError):
        mka_hello_timeout_seconds(
            {"mka_hello_time_ms": value}, 4)


def test_eos_key_replacement_status_and_rebind_decision():
    """Require new config/runtime CKN and old actor absence after hot update."""
    participants = {
        "new": {
            "success": False, "active": False, "failed": False,
            "live_peers": 0,
        },
        "fallback": {
            "success": True, "active": True, "failed": False,
            "live_peers": 1,
        },
    }
    assert eos_key_replacement_status(
        {"new", "fallback"}, participants, "old", "new",
        required_live_ckns={"fallback"}, controlled_port=True,
        expected_configured_ckns={"new", "fallback"}) == []
    errors = eos_key_replacement_status(
        {"old", "fallback"}, {"old": {}, "fallback": participants["fallback"]},
        "old", "new", required_live_ckns={"fallback"},
        controlled_port=True,
        expected_configured_ckns={"new", "fallback"})
    assert "old CKN remains in runtime participants" in errors


def test_eos_key_deletion_requires_actor_absence_and_live_survivor():
    """Start protocol expiry only after config and runtime actor deletion."""
    fallback = {
        "success": True, "active": True, "failed": False,
        "live_peers": 1,
    }
    assert eos_key_deletion_status(
        {"fallback"}, {"fallback": fallback}, "primary",
        {"fallback"}) == []
    errors = eos_key_deletion_status(
        {"fallback"}, {"primary": {}, "fallback": fallback},
        "primary", {"fallback"})
    assert "deleted CKN remains in runtime participants" in errors


def test_select_independent_port_pair_rejects_shared_profile_scope():
    """Choose ports whose peer profile mutation cannot affect each other."""
    ports = ["Ethernet0", "Ethernet4", "Ethernet8"]
    scopes = {
        "Ethernet0": ("eos-a", "shared"),
        "Ethernet4": ("eos-a", "shared"),
        "Ethernet8": ("eos-b", "shared"),
    }
    assert select_independent_port_pair(
        ports, scopes) == ("Ethernet0", "Ethernet8")
    assert select_independent_port_pair(
        ports[:2], scopes) is None


def test_selected_link_identity_survives_reconciliation_iteration():
    """Keep selected DUT/peer identity separate from remaining-link loops."""
    selected_neighbor = object()
    links = {
        "Ethernet0": selected_neighbor,
        "Ethernet4": object(),
        "Ethernet8": object(),
    }
    remaining = remaining_link_items(links, "Ethernet0")
    assert [port for port, _ in remaining] == ["Ethernet4", "Ethernet8"]
    assert links["Ethernet0"] is selected_neighbor


def test_multi_port_preconditions_are_independent():
    """Require unsafe alternate down and every safe alternate active/live."""
    states = {
        "Ethernet0": {
            "ccdd": {
                "active": "true",
                "success": "true",
                "live_peers": "0",
            },
        },
        "Ethernet4": {
            "ccdd": {
                "active": "true",
                "success": "true",
                "live_peers": "1",
            },
        },
    }
    peer_states = {
        "Ethernet0": {},
        "Ethernet4": {
            "ccdd": {
                "active": True,
                "success": True,
                "live_peers": 1,
            },
        },
    }
    configured_ckns = {
        "Ethernet0": {"mismatch"},
        "Ethernet4": {"ccdd"},
    }
    assert validate_multi_port_alternate_state(
        states, "CCDD", "Ethernet0", ["Ethernet4"],
        peer_states, configured_ckns) == []
    peer_states["Ethernet4"]["ccdd"]["success"] = False
    assert "Ethernet4 peer alternate is not successful" in \
        validate_multi_port_alternate_state(
            states, "CCDD", "Ethernet0", ["Ethernet4"],
            peer_states, configured_ckns)
    peer_states["Ethernet4"]["ccdd"]["success"] = True
    states["Ethernet4"]["ccdd"]["live_peers"] = "0"
    assert "Ethernet4 alternate has no live peer" in \
        validate_multi_port_alternate_state(
            states, "CCDD", "Ethernet0", ["Ethernet4"],
            peer_states, configured_ckns)
    states["Ethernet0"]["ccdd"]["live_peers"] = "1"
    assert "Ethernet0 alternate retains a live peer" in \
        validate_multi_port_alternate_state(
            states, "CCDD", "Ethernet0", ["Ethernet4"],
            peer_states, configured_ckns)


@pytest.mark.parametrize(
    "old_pids, new_pids, status, expected",
    [
        (["10"], ["11"], "macsecmgrd RUNNING pid 11", True),
        (["10"], ["10"], "macsecmgrd RUNNING pid 10", False),
        (["10"], ["11"], "macsecmgrd STOPPED", False),
    ],
)
def test_macsecmgrd_restart_ready(old_pids, new_pids, status, expected):
    """Require supervisor RUNNING and a different process identity."""
    assert macsecmgrd_restart_ready(
        old_pids, new_pids, status) is expected


def test_macsecmgrd_restart_command():
    """Use supervisor restart in the selected namespace-local container."""
    assert macsecmgrd_restart_command(
        "macsec0") == "docker exec macsec0 supervisorctl restart macsecmgrd"


def test_quiescence_budget_includes_measured_snapshot_cost():
    """Allow protocol settling plus at least two full stable snapshots."""
    assert quiescence_budget_seconds(12, 15.2, 2) == 58
    assert quiescence_budget_seconds(12, 1, 2) == 18


@pytest.mark.parametrize(
    "participants, enable, egress, ingress, log_seen, expected",
    [
        ({"a": {"live_peers": "1"}}, "true", ["tx"], ["rx"], False,
         "live-peers-remain"),
        ({"a": {"live_peers": "0"}}, "true", ["tx"], ["rx"], False,
         "controlled-port-propagation"),
        ({"a": {"live_peers": "0"}}, "true", ["tx"], ["rx"], True,
         "controlled-port-propagation"),
        ({"a": {"live_peers": "0"}}, "false", ["tx"], [], True,
         "secy-orch-sa-teardown"),
        ({"a": {"live_peers": "0"}}, "false", [], [], False,
         "complete-without-observed-log"),
        ({"a": {"live_peers": "0"}}, "false", [], [], True, "complete"),
    ],
)
def test_classify_macsec_teardown(
        participants, enable, egress, ingress, log_seen, expected):
    """Identify the first failed layer in both-invalid reconciliation."""
    assert classify_macsec_teardown(
        participants, enable, egress, ingress, log_seen) == expected


def test_get_macsec_teardown_state_reads_port_and_sa_keys():
    """Read namespace-local enable state and non-secret TX/RX SA keys."""
    results = {
        "sonic-db-cli -n asic0 APPL_DB HGETALL "
        "'MACSEC_PORT_TABLE:Ethernet0'": {
            "failed": False, "stdout": "{'enable': 'false'}"},
        "sonic-db-cli -n asic0 APPL_DB KEYS "
        "'MACSEC_EGRESS_SA_TABLE:Ethernet0:*'": {
            "failed": False,
            "stdout_lines": ["MACSEC_EGRESS_SA_TABLE:Ethernet0:0"]},
        "sonic-db-cli -n asic0 APPL_DB KEYS "
        "'MACSEC_INGRESS_SA_TABLE:Ethernet0:*'": {
            "failed": False, "stdout_lines": []},
    }
    host = _CommandHost(results, multi_asic=True)
    assert get_macsec_teardown_state(host, "Ethernet0") == {
        "port_enable": "false",
        "egress_sa_keys": ["MACSEC_EGRESS_SA_TABLE:Ethernet0:0"],
        "ingress_sa_keys": [],
    }


def test_validate_lifecycle_cleanup_state_requires_fresh_healthy_state():
    """Require fresh query/config/process/controlled-port and exact SC/SAs."""
    session = {
        "query_status": "ok",
        "config_status": "in-sync",
        "last_updated": "new",
    }
    ingress = [{
        "sci": "peer",
        "key": "MACSEC_INGRESS_SC_TABLE:Ethernet0:peer",
        "sas": {0: {"active": "true", "sak": "secret"}},
    }]
    assert validate_lifecycle_cleanup_state(
        session, "old", True, True,
        {"encoding_an": "0"},
        {0: {"sak": "secret"}},
        ingress,
    ) == []
    errors = validate_lifecycle_cleanup_state(
        dict(session, query_status="error", last_updated="old"),
        "old", False, False, {}, {}, [])
    assert "query_status is not ok" in errors
    assert "last_updated did not refresh" in errors
    assert "wpa_supplicant process is not healthy" in errors
    assert "controlled port is not open" in errors
    assert "egress SC is missing" in errors


def _function_calls(path, function_name):
    tree = ast.parse(path.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == function_name
    )
    calls = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            calls.add(node.func.attr)
    return calls


def _function_source(path, function_name):
    source = path.read_text()
    tree = ast.parse(source)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == function_name
    )
    return ast.get_source_segment(source, function)


@pytest.mark.parametrize(
    "function_name",
    ["_replace_peer_key_and_verify", "_delete_peer_key_and_verify"],
)
def test_eos_hot_update_helpers_never_detach_profiles(function_name):
    """Keep hitless EOS updates strictly key-line-only."""
    calls = _function_calls(FALLBACK_TEST_PATH, function_name)
    assert not calls.intersection({
        "_replace_peer_profile",
        "disable_macsec_port",
        "enable_macsec_port",
        "delete_macsec_profile",
    })


def test_primary_rotation_preserves_selected_link_names():
    """Prevent reconciliation loops from overwriting selected link identity."""
    source = _function_source(
        FALLBACK_TEST_PATH,
        "test_primary_failure_rotation_and_recovery_are_hitless")
    assert "selected_port, selected_neighbor = _select_routed_link" in source
    assert "for candidate_port in environment[\"links\"]" in source
    assert "remaining_link_items(" in source
    assert "for port in environment[\"links\"]" not in source


def test_cleanup_all_runs_every_cleanup_before_raising():
    """Always clean every traffic stream even when one cleanup fails."""
    cleaned = []

    def _cleanup(item):
        cleaned.append(item)
        if item == "first":
            raise AssertionError("loss")

    with pytest.raises(AssertionError, match="loss"):
        cleanup_all(["first", "second"], _cleanup)
    assert cleaned == ["first", "second"]


@pytest.mark.parametrize(
    "row, expected",
    [
        ({"state": "ok", "max_sa_per_sc": "2"}, 2),
        ({"state": "ok", "max_sa_per_sc": "4"}, 4),
        ({"state": "ok"}, 4),
    ],
)
def test_get_max_sa_per_sc(row, expected):
    """Read local capability and apply WPA's missing-field default."""
    command = (
        "sonic-db-cli -n asic0 STATE_DB HGETALL "
        "'MACSEC_PORT_TABLE|Ethernet0'"
    )
    host = _CommandHost({
        command: {"failed": False, "stdout": repr(row)}
    }, multi_asic=True)
    assert get_macsec_max_sa_per_sc(host, "Ethernet0") == expected


@pytest.mark.parametrize("value", ["bad", ""])
def test_get_max_sa_per_sc_rejects_unready_or_malformed(value):
    """Reject malformed values and rows that are not ready."""
    row = (
        {"state": "ok", "max_sa_per_sc": value}
        if value else {"state": "pending"})
    command = (
        "sonic-db-cli -n asic0 STATE_DB HGETALL "
        "'MACSEC_PORT_TABLE|Ethernet0'"
    )
    host = _CommandHost({
        command: {"failed": False, "stdout": repr(row)}
    }, multi_asic=True)
    with pytest.raises(ValueError):
        get_macsec_max_sa_per_sc(host, "Ethernet0")


@pytest.mark.parametrize(
    "capability, supported",
    [(2, False), (4, True), (8, False)],
)
def test_crossed_role_capability_gate(capability, supported):
    """Run peer-key-server crossed roles only at effective capability four."""
    assert crossed_role_peer_key_server_supported(capability) is supported


def test_parse_eos_profile_ckns():
    """Parse only the selected EOS profile's CKNs without exposing CAKs."""
    output = """
mac security
   profile other
      key dead 7 secret
   profile target
      key AABB 7 primary-secret
      key CCDD 7 fallback-secret fallback
"""
    assert parse_eos_profile_ckns(output, "target") == {"aabb", "ccdd"}
