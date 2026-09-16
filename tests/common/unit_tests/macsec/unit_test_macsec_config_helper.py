import ast
import secrets
from pathlib import Path

import pytest
from passlib.hash import cisco_type7


HELPER_PATH = (
    Path(__file__).resolve().parents[2] / "macsec" / "macsec_config_helper.py"
)


def _load_profile_helpers():
    source = HELPER_PATH.read_text()
    tree = ast.parse(source)
    names = {
        "_build_macsec_profile_options",
        "generate_macsec_key_pair",
        "generate_macsec_profile",
    }
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    module = ast.Module(body=nodes, type_ignores=[])
    namespace = {
        "secrets": secrets,
        "cisco_type7": cisco_type7,
    }
    exec(compile(module, str(HELPER_PATH), "exec"), namespace)
    return namespace


PROFILE_HELPERS = _load_profile_helpers()
_build_macsec_profile_options = PROFILE_HELPERS[
    "_build_macsec_profile_options"]
generate_macsec_profile = PROFILE_HELPERS["generate_macsec_profile"]


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
