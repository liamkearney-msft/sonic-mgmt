import importlib.util
from pathlib import Path

import pytest


HELPER_PATH = (
    Path(__file__).resolve().parents[2] / "macsec" / "mka_state_helper.py"
)
SPEC = importlib.util.spec_from_file_location("mka_state_helper", HELPER_PATH)
MKA_STATE_HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MKA_STATE_HELPER)

find_secret_fields = MKA_STATE_HELPER.find_secret_fields
parse_db_hash = MKA_STATE_HELPER.parse_db_hash
parse_eos_mka_participants = MKA_STATE_HELPER.parse_eos_mka_participants
validate_mka_snapshot = MKA_STATE_HELPER.validate_mka_snapshot


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
        "authenticated": "true",
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
        "participant": "true",
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


def test_parse_db_hash_rejects_partial_pair():
    """Reject malformed line-pair output rather than fabricating a value."""
    with pytest.raises(ValueError):
        parse_db_hash("field\nvalue\norphan")


def test_validate_primary_fallback_snapshot():
    """Accept a healthy two-participant snapshot with primary ownership."""
    participants = {
        "aabb": _participant("true", "true"),
        "ccdd": _participant("false", "false"),
    }
    assert validate_mka_snapshot(
        _session(), participants, _profile(), "AABB") == []


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
    """Normalize established EOS participant field spellings."""
    output = {
        "interfaces": {
            "Ethernet1": {
                "participants": {
                    "AABB": {
                        "success": True,
                        "electedSelf": False,
                        "defaultActor": True,
                        "principalActor": True,
                        "details": {
                            "livePeerList": ["peer"],
                            "sakTransmit": True,
                        },
                    },
                    "CCDD": {
                        "Success": "Yes",
                        "Elected-Self": "No",
                        "Default": "No",
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
        "active": True,
        "is_principal": True,
        "is_primary": True,
        "is_key_server": False,
        "live_peers": 1,
        "sak_transmit": True,
    }
    assert participants["ccdd"]["active"]
    assert not participants["ccdd"]["is_primary"]
    assert participants["ccdd"]["live_peers"] == 1
