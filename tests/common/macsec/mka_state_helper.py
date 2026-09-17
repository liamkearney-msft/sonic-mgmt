import ast
import json


MKA_SESSION_TABLE = "MACSEC_MKA_SESSION_TABLE"
MKA_PARTICIPANT_TABLE = "MACSEC_MKA_PARTICIPANT_TABLE"

REQUIRED_SESSION_FIELDS = {
    "profile",
    "kay_status",
    "authenticated",
    "secured",
    "failed",
    "actor_sci",
    "key_server_sci",
    "actor_priority",
    "key_server_priority",
    "is_key_server",
    "keys_distributed",
    "keys_received",
    "mka_hello_time_ms",
    "query_status",
    "last_updated",
    "config_status",
}

REQUIRED_PARTICIPANT_FIELDS = {
    "participant_index",
    "mi",
    "mn",
    "active",
    "participant",
    "retain",
    "is_principal",
    "is_primary",
    "live_peers",
    "potential_peers",
    "is_key_server",
    "is_elected",
}

SECRET_FIELD_NAMES = {
    "primary_cak",
    "fallback_cak",
    "cak",
    "sak",
    "ick",
    "kek",
    "auth_key",
}


def _normalized_mapping(mapping):
    return {
        "".join(char for char in str(key).lower() if char.isalnum()): value
        for key, value in mapping.items()
    }


def _mapping_value(mapping, *names):
    normalized = _normalized_mapping(mapping)
    for name in names:
        value = normalized.get(
            "".join(char for char in name.lower() if char.isalnum()))
        if value is not None:
            return value
    return None


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "1")


def parse_eos_mka_participants(output, interface):
    """Normalize cEOS participant JSON across established field spellings."""
    interfaces = _mapping_value(output, "interfaces")
    if not isinstance(interfaces, dict):
        return {}

    interface_state = next(
        (
            state for name, state in interfaces.items()
            if name.lower() == interface.lower()
        ),
        None,
    )
    if not isinstance(interface_state, dict):
        return {}

    raw_participants = _mapping_value(interface_state, "participants")
    if not isinstance(raw_participants, dict):
        return {}

    participants = {}
    for ckn, participant in raw_participants.items():
        if not isinstance(participant, dict):
            continue
        details = _mapping_value(participant, "details")
        if not isinstance(details, dict):
            details = {}
        live_peers = _mapping_value(
            participant, "livePeers", "livePeerList")
        if live_peers is None:
            live_peers = _mapping_value(
                details, "livePeers", "livePeerList")
        if isinstance(live_peers, (list, tuple, dict)):
            live_peers = len(live_peers)
        try:
            live_peers = int(live_peers or 0)
        except (TypeError, ValueError):
            live_peers = 0

        participants[str(ckn).lower()] = {
            "active": _as_bool(_mapping_value(
                participant, "success", "active")),
            "is_principal": _as_bool(_mapping_value(
                participant, "principalActor", "principal")),
            "is_primary": _as_bool(_mapping_value(
                participant, "defaultActor", "default")),
            "is_key_server": _as_bool(_mapping_value(
                participant, "electedSelf", "isKeyServer")),
            "live_peers": live_peers,
            "sak_transmit": _as_bool(_mapping_value(
                details, "sakTransmit")),
        }
    return participants


def mka_state_cli_supported(host):
    """Return whether the image exposes MKA operational-state CLI."""
    profile_help = host.command(
        "config macsec profile add --help", module_ignore_errors=True)
    show_help = host.command(
        "show macsec --help", module_ignore_errors=True)
    text = "{}\n{}\n{}\n{}".format(
        profile_help.get("stdout", ""), profile_help.get("stderr", ""),
        show_help.get("stdout", ""), show_help.get("stderr", ""))
    return "--fallback_cak" in text and "--mka" in text


def parse_db_hash(output):
    """Parse sonic-db-cli HGETALL output into a string dictionary."""
    output = output.strip()
    if not output:
        return {}

    for parser in (json.loads, ast.literal_eval):
        try:
            value = parser(output)
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, dict):
            return {str(key): str(item) for key, item in value.items()}

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) % 2:
        raise ValueError(
            "Malformed HGETALL output with an odd number of lines")
    return dict(zip(lines[::2], lines[1::2]))


def get_namespace_option(host, interface):
    """Return the sonic-db-cli namespace option for *interface*."""
    if not host.is_multi_asic:
        return ""
    asic = host.get_port_asic_instance(interface)
    namespace = host.get_namespace_from_asic_id(asic.asic_index)
    return "-n {}".format(namespace)


def _read_hash(host, namespace_option, database, key):
    command = "sonic-db-cli {} {} HGETALL '{}'".format(
        namespace_option, database, key)
    result = host.command(command, module_ignore_errors=True)
    if result.get("failed"):
        return {}
    return parse_db_hash(result.get("stdout", ""))


def get_macsec_profile_config(host, interface, profile_name):
    """Read one namespace-local MACSEC_PROFILE row."""
    return _read_hash(
        host, get_namespace_option(host, interface), "CONFIG_DB",
        "MACSEC_PROFILE|{}".format(profile_name))


def get_mka_state(host, interface):
    """Return the MKA session row and participant rows for *interface*."""
    namespace_option = get_namespace_option(host, interface)
    session = _read_hash(
        host, namespace_option, "STATE_DB",
        "{}|{}".format(MKA_SESSION_TABLE, interface))

    pattern = "{}|{}|*".format(MKA_PARTICIPANT_TABLE, interface)
    command = "sonic-db-cli {} STATE_DB KEYS '{}'".format(
        namespace_option, pattern)
    result = host.command(command, module_ignore_errors=True)
    keys = result.get("stdout_lines", []) if not result.get("failed") else []

    participants = {}
    for key in keys:
        key = key.strip()
        if not key:
            continue
        ckn = key.rsplit("|", 1)[-1].lower()
        participants[ckn] = _read_hash(
            host, namespace_option, "STATE_DB", key)
    return session, participants


def validate_mka_snapshot(session, participants, profile,
                          expected_principal_ckn=None,
                          require_all_live=True):
    """Return validation errors for a healthy primary/fallback snapshot."""
    errors = []
    missing_session = REQUIRED_SESSION_FIELDS.difference(session)
    if missing_session:
        errors.append("missing session fields: {}".format(
            sorted(missing_session)))

    expected_session = {
        "profile": profile["name"],
        "kay_status": "active",
        "authenticated": "true",
        "secured": "true",
        "failed": "false",
        "query_status": "ok",
        "config_status": "in-sync",
    }
    for field, expected in expected_session.items():
        if session.get(field) != expected:
            errors.append("{}={!r}, expected {!r}".format(
                field, session.get(field), expected))

    expected_roles = {
        profile["primary_ckn"].lower(): "true",
    }
    if profile.get("fallback_ckn"):
        expected_roles[profile["fallback_ckn"].lower()] = "false"

    if set(participants) != set(expected_roles):
        errors.append("participant CKNs {}, expected {}".format(
            sorted(participants), sorted(expected_roles)))

    principals = []
    for ckn, is_primary in expected_roles.items():
        participant = participants.get(ckn, {})
        missing_participant = REQUIRED_PARTICIPANT_FIELDS.difference(
            participant)
        if missing_participant:
            errors.append("{} missing fields: {}".format(
                ckn, sorted(missing_participant)))
        if participant.get("is_primary") != is_primary:
            errors.append("{} is_primary={!r}, expected {!r}".format(
                ckn, participant.get("is_primary"), is_primary))
        if participant.get("active") != "true":
            errors.append("{} is not active".format(ckn))
        live_peers = int(participant.get("live_peers", "0"))
        principal_ckn = (expected_principal_ckn or "").lower()
        if ((require_all_live or ckn == principal_ckn)
                and live_peers < 1):
            errors.append("{} has no live peer".format(ckn))
        if participant.get("is_principal") == "true":
            principals.append(ckn)

    if len(principals) != 1:
        errors.append("principal CKNs {}, expected exactly one".format(
            principals))
    if (expected_principal_ckn is not None and
            principals != [expected_principal_ckn.lower()]):
        errors.append("principal CKNs {}, expected {}".format(
            principals, expected_principal_ckn.lower()))
    return errors


def find_secret_fields(value):
    """Return paths whose field names would expose MACsec key material."""
    findings = []

    def _walk(item, path):
        if isinstance(item, dict):
            for key, nested in item.items():
                nested_path = path + [str(key)]
                if str(key).lower() in SECRET_FIELD_NAMES:
                    findings.append(".".join(nested_path))
                _walk(nested, nested_path)
        elif isinstance(item, (list, tuple)):
            for index, nested in enumerate(item):
                _walk(nested, path + [str(index)])

    _walk(value, [])
    return findings
