import math
import re


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


def parse_eos_profile_rekey_period(output, profile_name):
    """Read one EOS profile's configured rekey period, if present."""
    in_profile = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("profile "):
            in_profile = stripped.split(None, 1)[1] == profile_name
            continue
        if in_profile and stripped.startswith("mka session rekey-period "):
            value = stripped.rsplit(None, 1)[-1]
            if not value.isdigit() or int(value) <= 0:
                raise ValueError("Invalid EOS periodic rekey interval")
            return int(value)
    return None


def parse_eos_profile_priority(output, profile_name):
    """Read one EOS profile's key-server priority."""
    in_profile = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("profile "):
            in_profile = stripped.split(None, 1)[1] == profile_name
            continue
        if in_profile and stripped.startswith("mka key-server priority "):
            value = stripped.rsplit(None, 1)[-1]
            if not value.isdigit() or not 0 <= int(value) <= 255:
                raise ValueError("Invalid EOS key-server priority")
            return int(value)
    return None


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


def show_macsec_output(host, port, *options):
    namespace = get_namespace_option(host, port)
    command = "show macsec {} {}".format(
        namespace, " ".join(options)).strip()
    result = host.command(command, module_ignore_errors=True, verbose=False)
    if result.get("failed") or result.get("rc", 0) != 0:
        raise RuntimeError("MACsec operational command failed: {}".format(command))
    return result.get("stdout", "")


def get_mka_status(host, port):
    """Read detailed per-port MKA status."""
    output = show_macsec_output(host, port, "--mka", port)
    if output.strip() == "MACsec MKA session state for {} is missing".format(port):
        return None
    lines = output.splitlines()
    labels = {
        "Interface": "interface",
        "Profile": "profile",
        "PAE KaY status": "kay",
        "Controlled port mode": "mode",
        "Query status": "query",
        "Config status": "config",
        "MKA hello time": "hello",
        "Local key server": "local_key_server",
    }
    status = {}
    for line in lines:
        key, separator, value = line.partition(":")
        if separator and key.strip() in labels:
            status[labels[key.strip()]] = value.strip()
    if (status.get("interface") != port
            or set(status) != set(labels.values())):
        raise ValueError("Incomplete MKA status for {}".format(port))
    status["fresh"] = "retained" not in output.lower()
    header = next(
        (index for index, line in enumerate(lines) if line.split()[:4] ==
         ["CKN", "Role", "Principal", "Active"]), None)
    participants = {}
    if header is not None:
        if header + 1 >= len(lines) or not re.fullmatch(r"[- ]+", lines[header + 1]):
            raise ValueError("Invalid MKA participant table on {}".format(port))
        spans = [match.span() for match in re.finditer(r"-+", lines[header + 1])]
        if len(spans) < 5:
            raise ValueError("Incomplete MKA participant columns on {}".format(port))
        for line in lines[header + 2:]:
            if not line.strip():
                break
            values = [line[start:spans[index + 1][0]].strip()
                      for index, (start, _) in enumerate(spans[:-1])]
            values.append(line[spans[-1][0]:].strip())
            ckn, role, principal, active, live = values[:5]
            if (not re.fullmatch(r"[0-9a-fA-F]{32}(?:[0-9a-fA-F]{32})?", ckn)
                    or role not in ("primary", "fallback")
                    or principal not in ("true", "false")
                    or active not in ("true", "false")
                    or not live.isdigit()
                    or ckn.lower() in participants):
                raise ValueError("Malformed MKA participant on {}".format(port))
            participants[ckn.lower()] = {
                "role": role,
                "principal": principal == "true",
                "active": active == "true",
                "live": int(live),
            }
    elif "No MACsec MKA participant state found" not in output:
        raise ValueError("Missing MKA participant table on {}".format(port))
    status["participants"] = participants
    return status


def get_namespace_option(host, interface):
    """Return the namespace option for interface-scoped MACsec commands."""
    if not host.is_multi_asic:
        return ""
    asic = host.get_port_asic_instance(interface)
    namespace = host.get_namespace_from_asic_id(asic.asic_index)
    return "-n {}".format(namespace)


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
