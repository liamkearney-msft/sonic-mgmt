import ast
import json
import re
import secrets
from pathlib import Path

import pytest
from passlib.hash import cisco_type7


HELPER_PATH = (
    Path(__file__).resolve().parents[2] / "macsec" / "macsec_config_helper.py"
)
PROFILE_PATH = HELPER_PATH.with_name("profile.json")


def _load_profile_helpers():
    source = HELPER_PATH.read_text()
    tree = ast.parse(source)
    names = {
        "_build_macsec_profile_options",
        "_build_eos_macsec_profile_lines",
        "_eos_macsec_key_line",
        "_parse_wpa_global_socket",
        "macsec_profile_has_fallback",
        "ensure_macsec_profile_fallback",
        "generate_macsec_key_pair",
        "generate_macsec_profile",
        "generate_per_interface_macsec_profile",
        "generate_per_interface_macsec_profiles",
    }
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    module = ast.Module(body=nodes, type_ignores=[])
    namespace = {
        "re": re,
        "secrets": secrets,
        "cisco_type7": cisco_type7,
    }
    exec(compile(module, str(HELPER_PATH), "exec"), namespace)
    return namespace


PROFILE_HELPERS = _load_profile_helpers()
_build_macsec_profile_options = PROFILE_HELPERS[
    "_build_macsec_profile_options"]
_build_eos_macsec_profile_lines = PROFILE_HELPERS[
    "_build_eos_macsec_profile_lines"]
_eos_macsec_key_line = PROFILE_HELPERS["_eos_macsec_key_line"]
_parse_wpa_global_socket = PROFILE_HELPERS["_parse_wpa_global_socket"]
macsec_profile_has_fallback = PROFILE_HELPERS[
    "macsec_profile_has_fallback"]
ensure_macsec_profile_fallback = PROFILE_HELPERS[
    "ensure_macsec_profile_fallback"]
generate_macsec_profile = PROFILE_HELPERS["generate_macsec_profile"]
generate_per_interface_macsec_profile = PROFILE_HELPERS[
    "generate_per_interface_macsec_profile"]
generate_per_interface_macsec_profiles = PROFILE_HELPERS[
    "generate_per_interface_macsec_profiles"]


def test_build_profile_options_with_fallback():
    """Render both CAK/CKN pairs using the existing profile CLI fields."""
    options = _build_macsec_profile_options(
        64, "GCM-AES-128", "primary-cak", "aabb", "security", "true",
        fallback_cak="fallback-cak", fallback_ckn="ccdd")
    assert "--primary_cak primary-cak" in options
    assert "--primary_ckn aabb" in options
    assert "--fallback_cak fallback-cak" in options
    assert "--fallback_ckn ccdd" in options
    assert "--send_sci " in options


@pytest.mark.parametrize(
    "fallback_cak, fallback_ckn",
    [("fallback-cak", None), (None, "ccdd")],
)
def test_build_profile_options_requires_fallback_pair(
        fallback_cak, fallback_ckn):
    """Reject half-configured fallback credentials in test infrastructure."""
    with pytest.raises(ValueError):
        _build_macsec_profile_options(
            64, "GCM-AES-128", "primary-cak", "aabb", "security", "true",
            fallback_cak=fallback_cak, fallback_ckn=fallback_ckn)


def test_build_profile_options_rejects_duplicate_ckn():
    """Reject primary and fallback participants with the same CKN."""
    with pytest.raises(ValueError):
        _build_macsec_profile_options(
            64, "GCM-AES-128", "primary-cak", "AABB", "security", "true",
            fallback_cak="fallback-cak", fallback_ckn="aabb")


@pytest.mark.parametrize(
    "cipher_suite, ckn_length, cak_length",
    [
        ("GCM-AES-128", 32, 66),
        ("GCM-AES-XPN-256", 64, 130),
    ],
)
def test_generate_fallback_profile_key_lengths(
        cipher_suite, ckn_length, cak_length):
    """Generate distinct correctly-sized primary and fallback key pairs."""
    profile = generate_macsec_profile(
        "Ethernet0", cipher_suite=cipher_suite, include_fallback=True)
    assert len(profile["primary_ckn"]) == ckn_length
    assert len(profile["fallback_ckn"]) == ckn_length
    assert len(profile["primary_cak"]) == cak_length
    assert len(profile["fallback_cak"]) == cak_length
    assert profile["primary_ckn"] != profile["fallback_ckn"]
    assert profile["primary_cak"] != profile["fallback_cak"]


@pytest.mark.parametrize("base_has_fallback", [False, True])
def test_per_interface_profile_has_unique_fallback_by_default(
        base_has_fallback):
    """Generate dual-CA per-interface profiles for every base profile."""
    base_profile = {
        "cipher_suite": "GCM-AES-128",
        "priority": 64,
        "policy": "security",
        "send_sci": "true",
        "rekey_period": 30,
    }
    if base_has_fallback:
        base_profile.update({
            "fallback_cak": "static-fallback-cak",
            "fallback_ckn": "static-fallback-ckn",
        })

    first = generate_per_interface_macsec_profile(
        "Ethernet0", base_profile)
    second = generate_per_interface_macsec_profile(
        "Ethernet4", base_profile)

    for profile in (first, second):
        assert macsec_profile_has_fallback(profile)
        assert profile["primary_ckn"] != profile["fallback_ckn"]
        for field in (
                "cipher_suite", "priority", "policy", "send_sci",
                "rekey_period"):
            assert profile[field] == base_profile[field]

    all_caks = {
        first["primary_cak"], first["fallback_cak"],
        second["primary_cak"], second["fallback_cak"],
    }
    all_ckns = {
        first["primary_ckn"], first["fallback_ckn"],
        second["primary_ckn"], second["fallback_ckn"],
    }
    assert len(all_caks) == 4
    assert len(all_ckns) == 4
    if base_has_fallback:
        assert first["fallback_cak"] != base_profile["fallback_cak"]
        assert second["fallback_ckn"] != base_profile["fallback_ckn"]


def test_per_interface_profile_set_is_collision_free():
    """Generate unique primary/fallback CAK and CKN values for every port."""
    profiles = generate_per_interface_macsec_profiles(
        ["Ethernet0", "Ethernet4", "Ethernet8"],
        {
            "cipher_suite": "GCM-AES-128",
            "priority": 64,
            "policy": "security",
            "send_sci": "true",
        },
    )
    caks = [
        profile[field]
        for profile in profiles.values()
        for field in ("primary_cak", "fallback_cak")
    ]
    ckns = [
        profile[field]
        for profile in profiles.values()
        for field in ("primary_ckn", "fallback_ckn")
    ]
    assert len(caks) == len(set(caks)) == 6
    assert len(ckns) == len(set(ckns)) == 6


def test_per_interface_profile_reuses_existing_fallback_pair():
    """Preserve a complete fallback pair when replacing one port profile."""
    base_profile = {
        "cipher_suite": "GCM-AES-128",
        "priority": 64,
        "policy": "integrity",
        "send_sci": "false",
        "rekey_period": 0,
    }
    existing_profile = {
        "fallback_cak": "existing-fallback-cak",
        "fallback_ckn": "existing-fallback-ckn",
    }
    profile = generate_per_interface_macsec_profile(
        "Ethernet0", base_profile, existing_profile)
    assert profile["fallback_cak"] == existing_profile["fallback_cak"]
    assert profile["fallback_ckn"] == existing_profile["fallback_ckn"]
    assert profile["primary_cak"] != profile["fallback_cak"]
    assert profile["primary_ckn"] != profile["fallback_ckn"]


@pytest.mark.parametrize(
    "existing_profile",
    [
        {"fallback_cak": "partial"},
        {"fallback_ckn": "partial"},
    ],
)
def test_per_interface_profile_rejects_partial_existing_fallback(
        existing_profile):
    """Reject a partially configured existing per-interface fallback."""
    base_profile = {
        "cipher_suite": "GCM-AES-128",
        "priority": 64,
        "policy": "security",
        "send_sci": "true",
    }
    with pytest.raises(ValueError):
        generate_per_interface_macsec_profile(
            "Ethernet0", base_profile, existing_profile)


@pytest.mark.parametrize(
    "base_profile",
    [
        {
            "cipher_suite": "GCM-AES-128",
            "priority": 64,
            "policy": "security",
            "send_sci": "true",
            "fallback_cak": "partial",
        },
        {
            "cipher_suite": "GCM-AES-128",
            "priority": 64,
            "policy": "security",
            "send_sci": "true",
            "fallback_ckn": "partial",
        },
    ],
)
def test_per_interface_profile_rejects_partial_base_fallback(base_profile):
    """Reject partially configured static fallback input."""
    with pytest.raises(ValueError):
        generate_per_interface_macsec_profile("Ethernet0", base_profile)


def test_ensure_fallback_profile_reuses_existing_pair():
    """Preserve an existing fallback pair without generating a replacement."""
    profile = {
        "cipher_suite": "GCM-AES-128",
        "fallback_cak": "existing-cak",
        "fallback_ckn": "existing-ckn",
    }
    ensured, generated = ensure_macsec_profile_fallback(profile)
    assert not generated
    assert ensured == profile
    assert ensured is not profile


def test_ensure_fallback_profile_adds_only_missing_pair():
    """Add a fallback pair while preserving all existing profile fields."""
    profile = {
        "name": "profile",
        "cipher_suite": "GCM-AES-128",
        "primary_cak": "primary-cak",
        "primary_ckn": "primary-ckn",
    }
    ensured, generated = ensure_macsec_profile_fallback(profile)
    assert generated
    assert ensured["primary_cak"] == profile["primary_cak"]
    assert ensured["primary_ckn"] == profile["primary_ckn"]
    assert macsec_profile_has_fallback(ensured)


def test_eos_fallback_key_rotation_lines_are_exact():
    """Build EOS add-first and full-form key deletion commands."""
    assert _eos_macsec_key_line(
        "new-ckn", "new-cak", is_fallback=True
    ) == "key new-ckn 7 new-cak fallback"
    assert _eos_macsec_key_line(
        "old-ckn", "old-cak", is_fallback=True, remove=True
    ) == "no key old-ckn 7 old-cak fallback"


def test_build_eos_profile_lines_with_fallback():
    """Render primary and fallback keys using EOS encrypted-key syntax."""
    assert _build_eos_macsec_profile_lines(
        64, "GCM-AES-XPN-256", "primary-cak", "primary-ckn", "true",
        rekey_period=60, fallback_cak="fallback-cak",
        fallback_ckn="fallback-ckn",
    ) == [
        "cipher aes256-gcm-xpn",
        "key primary-ckn 7 primary-cak",
        "key fallback-ckn 7 fallback-cak fallback",
        "mka key-server priority 64",
        "mka session rekey-period 60",
        "sci",
    ]


def test_static_fallback_profile_runs_in_normal_profile_sweep():
    """Keep an explicit dual-CA profile in the ordinary profile catalog."""
    profiles = json.loads(PROFILE_PATH.read_text())
    profile = profiles["MACSEC_PROFILE_FALLBACK"]
    assert macsec_profile_has_fallback(profile)
    assert profile["primary_ckn"].lower() != profile["fallback_ckn"].lower()
    integrity_profile = profiles["MACSEC_PROFILE_FALLBACK_INTEGRITY"]
    assert integrity_profile["policy"] == "integrity"
    assert macsec_profile_has_fallback(integrity_profile)


@pytest.mark.parametrize(
    "socket_output, process_output, expected",
    [
        ("/run/wpa/global\n", "", "/run/wpa/global"),
        ("", "wpa_supplicant -g /run/wpa/global -i Ethernet0",
         "/run/wpa/global"),
        ("", "wpa_supplicant -g/run/wpa/global -iEthernet0",
         "/run/wpa/global"),
        ("", "wpa_supplicant -iEthernet0", ""),
    ],
)
def test_parse_wpa_global_socket(socket_output, process_output, expected):
    """Discover the runtime control socket without a hard-coded path."""
    assert _parse_wpa_global_socket(
        socket_output, process_output) == expected
