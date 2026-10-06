import ast
import json
import math
import re
import logging
import shlex
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

MKA_SESSION_TABLE = "MACSEC_MKA_SESSION_TABLE"
MKA_PARTICIPANT_TABLE = "MACSEC_MKA_PARTICIPANT_TABLE"
MACSEC_PORT_TABLE = "MACSEC_PORT_TABLE"
MACSEC_EGRESS_SC_TABLE = "MACSEC_EGRESS_SC_TABLE"
MACSEC_EGRESS_SA_TABLE = "MACSEC_EGRESS_SA_TABLE"
MACSEC_INGRESS_SC_TABLE = "MACSEC_INGRESS_SC_TABLE"
MACSEC_INGRESS_SA_TABLE = "MACSEC_INGRESS_SA_TABLE"

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
        success_value = _mapping_value(participant, "success")
        active_value = _mapping_value(participant, "active")
        success = _as_bool(
            success_value if success_value is not None else active_value)
        active = _as_bool(
            active_value if active_value is not None else success_value)
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
            "success": success,
            "active": active,
            "failed": _as_bool(_mapping_value(
                participant, "failed", "failure")),
            "is_principal": _as_bool(_mapping_value(
                participant, "principalActor", "principal")),
            "default_actor": _as_bool(_mapping_value(
                participant, "defaultActor", "default")),
            "is_key_server": _as_bool(_mapping_value(
                participant, "electedSelf", "isKeyServer")),
            "live_peers": live_peers,
            "sak_transmit": _as_bool(_mapping_value(
                details, "sakTransmit")),
        }
    return participants


def validate_eos_mka_participants(
        participants, profile, controlled_port,
        expected_principal=None, require_all_live=True):
    """Validate operational EOS peer state without ownership flags."""
    errors = []
    primary_ckn = profile["primary_ckn"].lower()
    fallback_ckn = profile["fallback_ckn"].lower()
    expected_ckns = {primary_ckn, fallback_ckn}

    if not controlled_port:
        errors.append("controlled port is not open")

    if set(participants) != expected_ckns:
        errors.append("participant CKNs {}, expected {}".format(
            sorted(participants), sorted(expected_ckns)))

    for ckn in expected_ckns:
        participant = participants.get(ckn, {})
        if require_all_live or ckn == expected_principal:
            if not participant.get("success"):
                errors.append("{} is not successful".format(ckn))
            if not participant.get("active"):
                errors.append("{} is not active".format(ckn))
            if participant.get("failed"):
                errors.append("{} is failed".format(ckn))
            if participant.get("live_peers", 0) < 1:
                errors.append("{} has no live peer".format(ckn))
    return errors


def parse_eos_profile_ckns(output, profile_name):
    """Return configured CKNs for one EOS MACsec profile without key data."""
    ckns = set()
    in_profile = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("profile "):
            in_profile = stripped.split(None, 1)[1] == profile_name
            continue
        if in_profile and stripped.startswith("key "):
            match = re.match(r"key\s+(\S+)\s+7\s+\S+", stripped)
            if match:
                ckns.add(match.group(1).lower())
    return ckns


def _mka_show_result_supported(result):
    """Recognize absent MKA syntax without hiding operational CLI failures."""
    output = "{}\n{}".format(
        result.get("stdout", ""), result.get("stderr", "")).lower()
    if re.search(
            r"(?:no such option|unknown option|unrecognized (?:option|arguments)|"
            r"invalid option)\s*:?\s*['\"]?--mka\b", output):
        return False
    if result.get("failed") or result.get("rc", 0) != 0:
        raise RuntimeError("show macsec --mka failed: {}".format(output.strip()))
    return True


def mka_state_cli_supported(host):
    """Return whether the canonical MKA state command is supported."""
    result = host.command(
        "show macsec --mka",
        module_ignore_errors=True,
        verbose=False,
    )
    return _mka_show_result_supported(result)


def parse_mka_timestamp(value):
    """Require the HLD's UTC, timezone-qualified successful query timestamp."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("MKA timestamp must be UTC: {!r}".format(value))
    return parsed


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
    if result.get("failed") or result.get("rc", 0) != 0:
        raise RuntimeError(
            "Unable to read {} HGETALL for {}".format(database, key))
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
    if result.get("failed") or result.get("rc", 0) != 0:
        raise RuntimeError(
            "Unable to read STATE_DB KEYS for {}".format(interface))
    keys = result.get("stdout_lines", [])

    participants = {}
    for key in keys:
        key = key.strip()
        if not key:
            continue
        ckn = key.rsplit("|", 1)[-1].lower()
        participants[ckn] = _read_hash(
            host, namespace_option, "STATE_DB", key)
    return session, participants


def _get_macsec_sc_state(host, interface, sc_table, sa_table):
    """Enumerate observed SCs and SAs without inferring a peer MAC or SCI."""
    namespace_option = get_namespace_option(host, interface)
    pattern = "{}:{}:*".format(sc_table, interface)
    result = host.command(
        "sonic-db-cli {} APPL_DB KEYS '{}'".format(
            namespace_option, pattern),
        module_ignore_errors=True,
        verbose=False,
    )
    if result.get("failed") or result.get("rc", 0) != 0:
        raise RuntimeError(
            "Unable to read APPL_DB {} KEYS for {}".format(
                sc_table, interface))
    keys = result.get("stdout_lines", [])
    prefix = "{}:{}:".format(sc_table, interface)
    entries = []
    for key in sorted(key.strip() for key in keys if key.strip()):
        if not key.startswith(prefix):
            raise ValueError("Unexpected APPL_DB SC key for {}".format(interface))
        sci = key[len(prefix):]
        sc = _read_hash(host, namespace_option, "APPL_DB", key)
        sa_prefix = "{}:{}:{}:".format(sa_table, interface, sci)
        sa_result = host.command(
            "sonic-db-cli {} APPL_DB KEYS '{}*'".format(
                namespace_option, sa_prefix),
            module_ignore_errors=True, verbose=False)
        if sa_result.get("failed") or sa_result.get("rc", 0) != 0:
            raise RuntimeError(
                "Unable to read APPL_DB {} KEYS for {}".format(
                    sa_table, interface))
        sas = {}
        for sa_key in sa_result.get("stdout_lines", []):
            sa_key = sa_key.strip()
            if not sa_key:
                continue
            if not sa_key.startswith(sa_prefix):
                raise ValueError("Unexpected APPL_DB SA key for {}".format(interface))
            an = int(sa_key[len(sa_prefix):])
            if an in sas:
                raise ValueError("Duplicate APPL_DB SA AN for {}".format(interface))
            sas[an] = _read_hash(
                host, namespace_option, "APPL_DB", sa_key)
        entries.append({
            "key": key,
            "sci": sci,
            "sc": sc,
            "sas": sas,
        })
    return entries


def get_macsec_ingress_sc_state(host, interface):
    """Enumerate actual ingress SC/SAs for a namespace-local MACsec port."""
    return _get_macsec_sc_state(
        host, interface, MACSEC_INGRESS_SC_TABLE, MACSEC_INGRESS_SA_TABLE)


_SNAPSHOT_SCRIPT = """
import json
import sys
from swsscommon.swsscommon import SonicV2Connector

ports, profile = json.loads(sys.argv[1])
rows = {}
connectors = {}
for port, namespace in ports:
    if namespace not in connectors:
        connector = SonicV2Connector(
            use_unix_socket_path=True, namespace=namespace)
        for database in ("STATE_DB", "APPL_DB", "CONFIG_DB"):
            connector.connect(getattr(connector, database))
        connectors[namespace] = connector
    connector = connectors[namespace]

    def query(db, key):
        try:
            value = connector.get_all(getattr(connector, db), key)
        except Exception as error:
            raise RuntimeError(
                "{} HGETALL failed on {} ({})".format(db, port, namespace)) from error
        if value is not None and not isinstance(value, dict):
            raise ValueError("{} HGETALL returned invalid data on {}".format(db, port))
        return json.dumps(value or {})

    def keys(db, pattern):
        try:
            value = connector.keys(getattr(connector, db), pattern)
        except Exception as error:
            raise RuntimeError(
                "{} KEYS failed on {} ({})".format(db, port, namespace)) from error
        if value is not None and not isinstance(value, (list, tuple)):
            raise ValueError("{} KEYS returned invalid data on {}".format(db, port))
        return value or []

    participant_prefix = "MACSEC_MKA_PARTICIPANT_TABLE|{}|".format(port)
    participants = {}
    for key in keys("STATE_DB", participant_prefix + "*"):
        if not key.startswith(participant_prefix) or key in participants:
            raise ValueError("Unexpected participant key on {}".format(port))
        participants[key] = query("STATE_DB", key)

    appl = {}
    for key in keys("APPL_DB", "MACSEC_*_TABLE:{}:*".format(port)):
        if key in appl:
            raise ValueError("Duplicate MACsec APPL_DB key on {}".format(port))
        appl[key] = query("APPL_DB", key)

    rows[port] = {
        "session": query("STATE_DB",
                         "MACSEC_MKA_SESSION_TABLE|{}".format(port)),
        "participants": participants,
        "profile": query("CONFIG_DB",
                         "MACSEC_PROFILE|{}".format(profile)),
        "appl_port": query("APPL_DB",
                           "MACSEC_PORT_TABLE:{}".format(port)),
        "appl": appl,
    }
print(json.dumps(rows))
"""


def get_macsec_snapshot_rows(host, ports, profile_name):
    """Collect namespace-local MACsec rows in one serialized host invocation."""
    ports = tuple(ports)
    if not ports:
        return {}
    specifications = [
        (port, get_namespace_option(host, port).split()[-1]
         if host.is_multi_asic else "")
        for port in ports
    ]
    command = "python3 -c {} {}".format(
        shlex.quote(_SNAPSHOT_SCRIPT),
        shlex.quote(json.dumps((specifications, profile_name))))
    result = host.command(
        command, module_ignore_errors=True, verbose=False)
    if result.get("failed") or result.get("rc", 0) != 0:
        detail = result.get("stderr", "").strip().splitlines()
        raise RuntimeError(
            "Unable to collect MACsec snapshot rows for {}: {}".format(
                ports, detail[-1] if detail else "remote command failed"))
    try:
        raw = json.loads(result["stdout"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Malformed MACsec snapshot response") from error
    if not isinstance(raw, dict) or set(raw) != set(ports):
        raise ValueError("MACsec snapshot response is missing ports")

    parsed = {}
    for port in ports:
        row = raw[port]
        participants = {}
        participant_prefix = "{}|{}|".format(MKA_PARTICIPANT_TABLE, port)
        for key, value in row["participants"].items():
            if not key.startswith(participant_prefix):
                raise ValueError("Unexpected participant key on {}".format(port))
            ckn = key[len(participant_prefix):].lower()
            if not ckn or ckn in participants:
                raise ValueError("Duplicate or empty participant CKN on {}".format(port))
            participants[ckn] = parse_db_hash(value)

        entries = {"egress": {}, "ingress": {}}
        prefixes = {
            "egress": (
                "{}:{}:".format(MACSEC_EGRESS_SC_TABLE, port),
                "{}:{}:".format(MACSEC_EGRESS_SA_TABLE, port)),
            "ingress": (
                "{}:{}:".format(MACSEC_INGRESS_SC_TABLE, port),
                "{}:{}:".format(MACSEC_INGRESS_SA_TABLE, port)),
        }
        for key, value in row["appl"].items():
            for direction, (sc_prefix, sa_prefix) in prefixes.items():
                if key.startswith(sc_prefix):
                    sci = key[len(sc_prefix):]
                    entry = entries[direction].setdefault(
                        sci, {"key": key, "sci": sci, "sc": {}, "sas": {}})
                    if entry["sc"]:
                        raise ValueError("Duplicate MACsec SC on {}".format(port))
                    entry["sc"] = parse_db_hash(value)
                    break
                if key.startswith(sa_prefix):
                    sci, separator, an_text = key[len(sa_prefix):].rpartition(":")
                    if not separator:
                        raise ValueError("Malformed MACsec SA key on {}".format(port))
                    an = int(an_text)
                    entry = entries[direction].setdefault(
                        sci, {"key": sc_prefix + sci, "sci": sci, "sc": {}, "sas": {}})
                    if an in entry["sas"]:
                        raise ValueError("Duplicate MACsec SA on {}".format(port))
                    entry["sas"][an] = parse_db_hash(value)
                    break
            else:
                raise ValueError("Unexpected MACsec APPL_DB key on {}".format(port))
        parsed[port] = {
            "session": parse_db_hash(row["session"]),
            "participants": participants,
            "profile": parse_db_hash(row["profile"]),
            "appl_port": parse_db_hash(row["appl_port"]),
            "egress": list(entries["egress"].values()),
            "ingress": list(entries["ingress"].values()),
        }
    return parsed


def validate_point_to_point_ingress_sc(entries):
    """Validate exactly one ingress SC with at least one active keyed SA."""
    if len(entries) != 1:
        return [
            "expected one ingress SC, found {}: {}".format(
                len(entries),
                [entry.get("key") for entry in entries],
            )
        ]
    entry = entries[0]
    if not entry.get("sc"):
        return ["ingress SC {} is missing".format(entry.get("sci"))]
    active_sas = [
        (an, sa) for an, sa in entry.get("sas", {}).items()
        if sa.get("active") == "true"
    ]
    if not active_sas:
        return [
            "ingress SC {} has no active SA; ANs={}".format(
                entry.get("sci"),
                sorted(entry.get("sas", {})),
            )
        ]
    if any(not sa.get("sak") for _, sa in active_sas):
        return [
            "ingress SC {} has an active SA without a SAK".format(
                entry.get("sci"))
        ]
    return []


def mka_hello_timeout_seconds(session, intervals, default_hello_ms=2000):
    """Return a protocol-aware timeout for the requested hello intervals."""
    value = session.get("mka_hello_time_ms")
    if value in (None, ""):
        hello_ms = default_hello_ms
    else:
        try:
            hello_ms = int(value)
        except (TypeError, ValueError):
            raise ValueError(
                "Invalid mka_hello_time_ms {!r}".format(value))
    if hello_ms <= 0:
        raise ValueError(
            "Invalid mka_hello_time_ms {!r}".format(value))
    return max(1, int(math.ceil(intervals * hello_ms / 1000.0)))


def get_macsec_max_sa_per_sc(host, interface):
    """Read max-SA capability after the namespace-local port is OK."""
    namespace_option = get_namespace_option(host, interface)
    row = _read_hash(
        host, namespace_option, "STATE_DB",
        "{}|{}".format(MACSEC_PORT_TABLE, interface))
    if not row or row.get("state") != "ok":
        raise ValueError(
            "MACsec port state is not ready on {}".format(interface))
    value = row.get("max_sa_per_sc")
    if value in (None, ""):
        return 4
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(
            "Invalid max_sa_per_sc {!r} on {}".format(value, interface))


def crossed_role_peer_key_server_supported(max_sa_per_sc):
    """Return whether WPA permits the peer-key-server crossed-role scenario."""
    return max_sa_per_sc == 4


def select_independent_port_pair(ports, scope_by_port):
    """Pick two ports with distinct peer/profile scopes."""
    ports = list(ports)
    for index, unsafe_port in enumerate(ports):
        for safe_port in ports[index + 1:]:
            if scope_by_port[unsafe_port] != scope_by_port[safe_port]:
                return unsafe_port, safe_port
    return None


def validate_multi_port_alternate_state(
        participants_by_port, alternate_ckn, unsafe_port, safe_ports,
        peer_participants_by_port=None,
        peer_configured_ckns_by_port=None):
    """Validate one unsafe and independently healthy safe alternate set."""
    errors = []
    alternate_ckn = alternate_ckn.lower()
    unsafe = participants_by_port.get(unsafe_port, {}).get(
        alternate_ckn, {})
    if int(unsafe.get("live_peers", "0")) > 0:
        errors.append(
            "{} alternate retains a live peer".format(unsafe_port))
    peer_participants_by_port = peer_participants_by_port or {}
    peer_configured_ckns_by_port = peer_configured_ckns_by_port or {}
    if alternate_ckn in peer_configured_ckns_by_port.get(
            unsafe_port, set()):
        errors.append(
            "{} peer still configures the unsafe alternate".format(
                unsafe_port))
    if alternate_ckn in peer_participants_by_port.get(unsafe_port, {}):
        errors.append(
            "{} peer still has the unsafe alternate".format(unsafe_port))
    for port in safe_ports:
        participant = participants_by_port.get(port, {}).get(
            alternate_ckn, {})
        if participant.get("active") != "true":
            errors.append("{} alternate is not active".format(port))
        if int(participant.get("live_peers", "0")) < 1:
            errors.append("{} alternate has no live peer".format(port))
        peer_participant = peer_participants_by_port.get(
            port, {}).get(alternate_ckn, {})
        if (peer_configured_ckns_by_port
                and alternate_ckn not in
                peer_configured_ckns_by_port.get(port, set())):
            errors.append(
                "{} peer alternate is not configured".format(port))
        if peer_participants_by_port:
            if not peer_participant.get("success"):
                errors.append(
                    "{} peer alternate is not successful".format(port))
            if not peer_participant.get("active"):
                errors.append(
                    "{} peer alternate is not active".format(port))
            if peer_participant.get("live_peers", 0) < 1:
                errors.append(
                    "{} peer alternate has no live peer".format(port))
    return errors


def macsecmgrd_restart_ready(old_pids, new_pids, supervisor_output):
    """Return whether supervisor reports RUNNING with a different live PID."""
    return (
        "RUNNING" in supervisor_output
        and bool(new_pids)
        and set(new_pids).isdisjoint(set(old_pids))
    )


def cleanup_all(items, cleanup):
    """Run cleanup for every item and re-raise the first failure afterward."""
    first_error = None
    for item in items:
        try:
            cleanup(item)
        except BaseException as error:
            if first_error is None:
                first_error = error
            else:
                logger.error("Additional MACsec cleanup failure: %r", error)
    if first_error is not None:
        raise first_error


def validate_mka_snapshot(session, participants, profile,
                          expected_principal_ckn=None,
                          require_all_live=True,
                          require_principal=True):
    """Return validation errors for a healthy primary/fallback snapshot."""
    errors = []
    missing_session = REQUIRED_SESSION_FIELDS.difference(session)
    if missing_session:
        errors.append("missing session fields: {}".format(
            sorted(missing_session)))

    expected_session = {
        "profile": profile["name"],
        "kay_status": "active",
        "authenticated": "false",
        "secured": "true",
        "failed": "false",
        "query_status": "ok",
        "config_status": "in-sync",
    }
    for field, expected in expected_session.items():
        if session.get(field) != expected:
            errors.append("{}={!r}, expected {!r}".format(
                field, session.get(field), expected))

    for field in ("actor_sci", "key_server_sci"):
        if not re.fullmatch(r"[0-9a-f]{16}", session.get(field, "")):
            errors.append("{} is not a normalized SCI".format(field))
    try:
        parse_mka_timestamp(session.get("last_updated", ""))
    except (ValueError, TypeError, AttributeError):
        errors.append("last_updated is not an ISO UTC timestamp")
    for field in (
            "actor_priority", "key_server_priority", "keys_distributed",
            "keys_received", "mka_hello_time_ms"):
        if not re.fullmatch(r"\d+", session.get(field, "")):
            errors.append("{} is not an unsigned integer".format(field))
    if session.get("is_key_server") not in ("true", "false"):
        errors.append("is_key_server is not a normalized boolean")

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
        for field in ("participant_index", "mn", "live_peers", "potential_peers"):
            if not re.fullmatch(r"\d+", participant.get(field, "")):
                errors.append("{} {} is not an unsigned integer".format(ckn, field))
        for field in ("active", "retain", "is_principal", "is_primary", "is_key_server", "is_elected"):
            if participant.get(field) not in ("true", "false"):
                errors.append("{} {} is not a normalized boolean".format(ckn, field))
        if not re.fullmatch(r"[0-9a-f]{24}", participant.get("mi", "")):
            errors.append("{} MI is not normalized".format(ckn))
        live_peers = int(participant["live_peers"]) if re.fullmatch(
            r"\d+", participant.get("live_peers", "")) else 0
        principal_ckn = (expected_principal_ckn or "").lower()
        if ((require_all_live or ckn == principal_ckn)
                and live_peers < 1):
            errors.append("{} has no live peer".format(ckn))
        if participant.get("is_principal") == "true":
            principals.append(ckn)

    if require_principal:
        if len(principals) != 1:
            errors.append("principal CKNs {}, expected exactly one".format(
                principals))
        if (expected_principal_ckn is not None
                and principals != [expected_principal_ckn.lower()]):
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
