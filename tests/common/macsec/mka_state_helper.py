import ast
import json
import math
import re


MKA_SESSION_TABLE = "MACSEC_MKA_SESSION_TABLE"
MKA_PARTICIPANT_TABLE = "MACSEC_MKA_PARTICIPANT_TABLE"
MACSEC_PORT_TABLE = "MACSEC_PORT_TABLE"
MACSEC_INGRESS_SC_TABLE = "MACSEC_INGRESS_SC_TABLE"
MACSEC_INGRESS_SA_TABLE = "MACSEC_INGRESS_SA_TABLE"
MACSEC_EGRESS_SA_TABLE = "MACSEC_EGRESS_SA_TABLE"
MACSEC_APPL_PORT_TABLE = "MACSEC_PORT_TABLE"

REQUIRED_SESSION_FIELDS = {
    "profile",
    "kay_status",
    "authenticated",
    "secured",
    "failed",
    "actor_sci",
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
        participants, profile, controlled_port):
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


def eos_key_replacement_status(
        configured_ckns, participants, old_ckn, new_ckn,
        required_live_ckns=(), controlled_port=True,
        expected_configured_ckns=None):
    """Classify whether an EOS key replacement reached the required runtime."""
    old_ckn = old_ckn.lower()
    new_ckn = new_ckn.lower()
    required_live_ckns = {ckn.lower() for ckn in required_live_ckns}
    errors = []

    if expected_configured_ckns is not None:
        expected_configured_ckns = {
            ckn.lower() for ckn in expected_configured_ckns}
        if configured_ckns != expected_configured_ckns:
            errors.append("configured CKNs {}, expected {}".format(
                sorted(configured_ckns),
                sorted(expected_configured_ckns)))
    if old_ckn in configured_ckns:
        errors.append("old CKN remains in running config")
    if new_ckn not in configured_ckns:
        errors.append("new CKN missing from running config")
    if old_ckn in participants:
        errors.append("old CKN remains in runtime participants")
    if new_ckn not in participants:
        errors.append("new CKN missing from runtime participants")
    if required_live_ckns and not controlled_port:
        errors.append("controlled port is not open")
    for ckn in required_live_ckns:
        participant = participants.get(ckn, {})
        if not participant.get("success"):
            errors.append("{} is not successful".format(ckn))
        if not participant.get("active"):
            errors.append("{} is not active".format(ckn))
        if participant.get("failed"):
            errors.append("{} is failed".format(ckn))
        if participant.get("live_peers", 0) < 1:
            errors.append("{} has no live peer".format(ckn))
    return errors


def eos_key_deletion_status(
        configured_ckns, participants, deleted_ckn,
        remaining_ckns, controlled_port=True):
    """Validate deleted EOS actor state and operational survivors."""
    deleted_ckn = deleted_ckn.lower()
    remaining_ckns = {ckn.lower() for ckn in remaining_ckns}
    errors = []
    if configured_ckns != remaining_ckns:
        errors.append("configured CKNs {}, expected {}".format(
            sorted(configured_ckns), sorted(remaining_ckns)))
    if deleted_ckn in participants:
        errors.append("deleted CKN remains in runtime participants")
    if remaining_ckns and not controlled_port:
        errors.append("controlled port is not open")
    for ckn in remaining_ckns:
        participant = participants.get(ckn, {})
        if not participant.get("success"):
            errors.append("{} is not successful".format(ckn))
        if not participant.get("active"):
            errors.append("{} is not active".format(ckn))
        if participant.get("failed"):
            errors.append("{} is failed".format(ckn))
        if participant.get("live_peers", 0) < 1:
            errors.append("{} has no live peer".format(ckn))
    return errors


def _mka_show_result_supported(result):
    """Return whether canonical MKA output comes from a recognized command."""
    if result.get("failed", False) or result.get("rc", 0) != 0:
        return False

    output = "{}\n{}".format(
        result.get("stdout", ""), result.get("stderr", "")).lower()
    unsupported_markers = (
        "command not found",
        "invalid option",
        "no such option",
        "unrecognized option",
        "unrecognized arguments",
        "unknown option",
        "unknown command",
    )
    return not any(marker in output for marker in unsupported_markers)


def mka_state_cli_supported(host):
    """Return whether the canonical MKA state command is supported."""
    result = host.command(
        "show macsec --mka",
        module_ignore_errors=True,
        verbose=False,
    )
    return _mka_show_result_supported(result)


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


def get_macsec_ingress_sc_state(host, interface):
    """Enumerate actual ingress SC/SAs for a namespace-local MACsec port."""
    namespace_option = get_namespace_option(host, interface)
    pattern = "{}:{}:*".format(MACSEC_INGRESS_SC_TABLE, interface)
    result = host.command(
        "sonic-db-cli {} APPL_DB KEYS '{}'".format(
            namespace_option, pattern),
        module_ignore_errors=True,
        verbose=False,
    )
    keys = result.get("stdout_lines", []) if not result.get("failed") else []
    prefix = "{}:{}:".format(MACSEC_INGRESS_SC_TABLE, interface)
    entries = []
    for key in sorted(key.strip() for key in keys if key.strip()):
        if not key.startswith(prefix):
            continue
        sci = key[len(prefix):]
        sc = _read_hash(host, namespace_option, "APPL_DB", key)
        sas = {}
        for an in range(4):
            sa_key = "{}:{}:{}:{}".format(
                MACSEC_INGRESS_SA_TABLE, interface, sci, an)
            sa = _read_hash(
                host, namespace_option, "APPL_DB", sa_key)
            if sa:
                sas[an] = sa
        entries.append({
            "key": key,
            "sci": sci,
            "sc": sc,
            "sas": sas,
        })
    return entries


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


def fresh_mka_state_published(session, previous_last_updated):
    """Return whether a fresh, usable MKA snapshot was published."""
    return (
        session.get("query_status") == "ok"
        and session.get("config_status") == "in-sync"
        and bool(session.get("last_updated"))
        and session.get("last_updated") != previous_last_updated
    )


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


def remaining_link_items(links, selected_port):
    """Return non-selected links without mutating selected-link identity."""
    return [
        (candidate_port, candidate_neighbor)
        for candidate_port, candidate_neighbor in links.items()
        if candidate_port != selected_port
    ]


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


def macsecmgrd_restart_command(container):
    """Build the deterministic supervisor restart command."""
    return "docker exec {} supervisorctl restart macsecmgrd".format(
        container)


def quiescence_budget_seconds(
        settle_seconds, snapshot_seconds, poll_seconds, stable_polls=2):
    """Budget settle time plus enough measured time for stable snapshots."""
    sample_seconds = max(snapshot_seconds, poll_seconds)
    return max(1, int(math.ceil(
        settle_seconds + (stable_polls + 1) * sample_seconds)))


def get_macsec_teardown_state(host, interface):
    """Return non-secret port enable and SA-key state for teardown checks."""
    namespace_option = get_namespace_option(host, interface)
    port = _read_hash(
        host, namespace_option, "APPL_DB",
        "{}:{}".format(MACSEC_APPL_PORT_TABLE, interface))
    state = {"port_enable": port.get("enable"), "egress_sa_keys": [],
             "ingress_sa_keys": []}
    for direction, table in (
            ("egress_sa_keys", MACSEC_EGRESS_SA_TABLE),
            ("ingress_sa_keys", MACSEC_INGRESS_SA_TABLE)):
        result = host.command(
            "sonic-db-cli {} APPL_DB KEYS '{}:{}:*'".format(
                namespace_option, table, interface),
            module_ignore_errors=True,
            verbose=False,
        )
        state[direction] = sorted(
            key.strip() for key in result.get("stdout_lines", [])
            if key.strip())
    return state


def classify_macsec_teardown(
        participants, port_enable, egress_sa_keys, ingress_sa_keys,
        teardown_log_seen):
    """Classify the first failed layer in no-live-CA teardown."""
    live = {
        ckn: int(participant.get("live_peers", "0"))
        for ckn, participant in participants.items()
    }
    if any(count > 0 for count in live.values()):
        return "live-peers-remain"
    if port_enable != "false":
        return "controlled-port-propagation"
    if egress_sa_keys or ingress_sa_keys:
        return "secy-orch-sa-teardown"
    if not teardown_log_seen:
        return "complete-without-observed-log"
    return "complete"


def classify_published_peer_teardown(
        session, participants, port_enable, egress_sa_keys,
        ingress_sa_keys, controlled_port, expected_profile,
        expected_ckns, previous_last_updated):
    """Classify the first incomplete layer in published peer teardown."""
    if (
            session.get("profile") != expected_profile
            or session.get("query_status") != "ok"
            or session.get("config_status") != "in-sync"
            or not session.get("last_updated")
            or session.get("last_updated") == previous_last_updated):
        return "publication-pending"
    if set(participants) != set(expected_ckns):
        return "participant-set-mismatch"
    if any(
            participant.get("active") != "true"
            for participant in participants.values()):
        return "participant-inactive"
    if any(
            int(participant.get("live_peers", "0")) > 0
            for participant in participants.values()):
        return "live-peers-remain"
    if session.get("secured") != "false":
        return "published-secured-state"
    if port_enable != "false":
        return "controlled-port-propagation"
    if egress_sa_keys or ingress_sa_keys:
        return "secy-orch-sa-teardown"
    if controlled_port:
        return "controlled-port-helper-inconsistency"
    return "complete"


def validate_lifecycle_cleanup_state(
        session, previous_last_updated, process_ready, controlled_port,
        egress_sc, egress_sas, ingress_scs):
    """Validate fresh MKA/process/SC-SA state after explicit cleanup."""
    errors = []
    if session.get("query_status") != "ok":
        errors.append("query_status is not ok")
    if session.get("config_status") != "in-sync":
        errors.append("config_status is not in-sync")
    last_updated = session.get("last_updated")
    if not last_updated:
        errors.append("last_updated is missing")
    elif last_updated == previous_last_updated:
        errors.append("last_updated did not refresh")
    if not process_ready:
        errors.append("MACsec service process is not healthy")
    if not controlled_port:
        errors.append("controlled port is not open")

    errors.extend(validate_point_to_point_ingress_sc(ingress_scs))
    if not egress_sc:
        errors.append("egress SC is missing")
        return errors
    try:
        encoding_an = int(egress_sc.get("encoding_an"))
    except (TypeError, ValueError):
        errors.append("egress encoding AN is invalid")
        return errors
    active_sa = egress_sas.get(encoding_an, {})
    if not active_sa:
        errors.append(
            "egress SA for encoding AN {} is missing".format(encoding_an))
    elif not active_sa.get("sak"):
        errors.append(
            "egress SA for encoding AN {} has no SAK".format(encoding_an))
    return errors


def cleanup_all(items, cleanup):
    """Run cleanup for every item and re-raise the first failure afterward."""
    first_error = None
    for item in items:
        try:
            cleanup(item)
        except Exception as error:
            if first_error is None:
                first_error = error
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
