import json
import ipaddress
import logging
import re
import shlex
import sys
import time
from contextlib import AbstractContextManager, contextmanager

import pytest
from passlib.hash import cisco_type7

from tests.common.devices.eos import EosHost
from tests.common.helpers.dut_utils import (
    restart_service_with_startlimit_guard,
)
from tests.common.macsec.fallback_cak_helper import (
    peer_adapter,
    peer_adapters,
    read_link_snapshot,
)
from tests.common.macsec.mka_state_helper import get_macsec_snapshot_rows
from tests.common.macsec.macsec_config_helper import (
    delete_macsec_profile,
    disable_macsec_port,
    enable_macsec_port,
    generate_macsec_key_pair,
    set_macsec_profile,
    update_macsec_profile_key as _profile_update,
    restore_macsec_profile_key,
)
from tests.common.macsec.failure_safe_cleanup import FailureSafeCleanup
from tests.common.macsec.macsec_helper import (
    get_ipnetns_prefix,
    get_macsec_counters,
)
from tests.common.macsec.macsec_platform_helper import find_portchannel_from_member, get_portchannel
from tests.common.macsec.mka_state_helper import (
    cleanup_all,
    crossed_role_peer_key_server_supported,
    find_secret_fields,
    get_macsec_max_sa_per_sc,
    get_macsec_profile_config,
    get_mka_state,
    get_namespace_option,
    macsecmgrd_restart_ready,
    mka_hello_timeout_seconds,
    mka_state_cli_supported,
    parse_db_hash,
    select_independent_port_pair,
    validate_multi_port_alternate_state,
    parse_mka_timestamp,
)
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("t0", "t2", "lrh", "urh", "t0-sonic"),
]

FALLBACK_PROFILE = "MACSEC_PROFILE_FALLBACK"
MKA_TIMEOUT = 30
MKA_CONVERGE_TIMEOUT = 180
MKA_STATE_PUBLISH_TIMEOUT = 60
STRESS_ROTATIONS = 10
SA_RETIRE_TIMEOUT = 20

NATIVE_COUNTER = re.compile(
    r"^(SAI_MACSEC_(?:PORT|SC|SA)_(?:STAT_[A-Z0-9_]+|ATTR_CURRENT_XPN))\s+(\d+)$")
PORT_COUNTER_FIELDS = (
    "SAI_PORT_STAT_IF_IN_DISCARDS",
    "SAI_PORT_STAT_IF_IN_ERRORS",
    "SAI_PORT_STAT_IF_OUT_DISCARDS",
    "SAI_PORT_STAT_IF_OUT_ERRORS",
)
KERNEL_RX_FIELDS = frozenset((
    "InPktsBadTag", "InPktsUnknownSCI", "InPktsNoSA",
    "InPktsNoTag", "InPktsNoSCI", "InPktsOverrun",
    "InPktsInvalid", "InPktsLate", "InPktsNotValid",
    "InPktsDelayed", "InPktsUnchecked",
    "InPktsNotUsingSA", "InPktsUnusedSA", "InPktsOK",
    "InOctetsDecrypted", "InOctetsValidated",
))


def _profile_kwargs(profile, priority=None):
    return {
        "priority": profile["priority"] if priority is None else priority,
        "cipher_suite": profile["cipher_suite"],
        "primary_cak": profile["primary_cak"],
        "primary_ckn": profile["primary_ckn"],
        "policy": profile["policy"],
        "send_sci": profile["send_sci"],
        "rekey_period": profile["rekey_period"],
        "fallback_cak": profile.get("fallback_cak"),
        "fallback_ckn": profile.get("fallback_ckn"),
    }


def _assert_key_material_absent(text, profile):
    text = text.lower()
    for field in ("primary_cak", "fallback_cak"):
        encoded = profile[field]
        decoded = cisco_type7.decode(encoded)
        if encoded.lower() in text:
            pytest.fail("Encoded {} key material was exposed".format(field))
        if decoded.lower() in text:
            pytest.fail("Decoded {} key material was exposed".format(field))


def _assert_profile_unchanged(before, after, description):
    unchanged = (
        set(after) == set(before)
        and all(after.get(field) == value
                for field, value in before.items())
    )
    assert unchanged, "{} changed MACsec profile state".format(description)


def _set_profile(host, name, profile, priority=None, namespace_option=None):
    set_macsec_profile(
        host, name, namespace_option=namespace_option, **_profile_kwargs(profile, priority=priority))


def _protocol_timeout(environment, port, intervals):
    session, _ = get_mka_state(environment["duthost"], port)
    return mka_hello_timeout_seconds(session, intervals)


def _snapshot(environment, port):
    return read_link_snapshot(
        environment["duthost"],
        port,
        environment["profile"]["name"],
    )


def _snapshots(environment, ports):
    ports = tuple(ports)
    rows = get_macsec_snapshot_rows(
        environment["duthost"], ports, environment["profile"]["name"])
    return {
        port: read_link_snapshot(
            environment["duthost"], port,
            environment["profile"]["name"], rows=rows[port])
        for port in ports
    }


def _counter_result(host, command):
    result = host.command(command, module_ignore_errors=True, verbose=False)
    if result.get("failed") or result.get("rc", 0) != 0:
        raise RuntimeError("Unable to read MACsec diagnostic counters with {}".format(command))
    return result.get("stdout", "")


def _native_counter_sections(output):
    """Extract only numeric MACsec counters; never retain CLI key material."""
    sections = {"port": {}, "egress_sc": {}, "egress_sa": {},
                "ingress_sc": {}, "ingress_sa": {}}
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("MACsec port("):
            current = ("port", "port")
        else:
            heading = re.match(
                r"MACsec (Egress|Ingress) (SC|SA) \(([^)]+)\)", stripped)
            if heading:
                scope = "{}_{}".format(
                    heading.group(1).lower(), heading.group(2).lower())
                current = scope, "sample_{}".format(len(sections[scope]) + 1)
        if not current or not re.match(
                r"SAI_MACSEC_(?:PORT|SC|SA)_(?:STAT_|ATTR_CURRENT_XPN\b)",
                stripped):
            continue
        match = NATIVE_COUNTER.fullmatch(stripped)
        if not match:
            raise ValueError("Malformed MACsec numeric counter in {}".format(
                current[0]))
        scope, identity = current
        bucket = sections[scope].setdefault(identity, {})
        if match.group(1) in bucket:
            raise ValueError("Duplicate MACsec counter in {}".format(scope))
        bucket[match.group(1)] = int(match.group(2))
    return {
        scope: values if values else {"unsupported": "no native counters published"}
        for scope, values in sections.items()
    }


def _asic_interface_counters(host, namespace, name, portchannel=False):
    mapping = "COUNTERS_LAG_NAME_MAP" if portchannel else "COUNTERS_PORT_NAME_MAP"
    oid = _counter_result(
        host, "sonic-db-cli {} COUNTERS_DB HGET {} {}".format(
            namespace, shlex.quote(mapping), shlex.quote(name))).strip()
    if not oid:
        return {"unsupported": "{} has no COUNTERS_DB object".format(name)}
    if not re.fullmatch(r"oid:0x[0-9a-fA-F]+", oid):
        raise ValueError("Invalid COUNTERS_DB object ID for {}".format(name))
    row = parse_db_hash(_counter_result(
        host, "sonic-db-cli {} COUNTERS_DB HGETALL {}".format(
            namespace, shlex.quote("COUNTERS:{}".format(oid)))))
    fields = PORT_COUNTER_FIELDS
    counters = {}
    for field in fields:
        if field not in row:
            continue
        if not row[field].isdigit():
            raise ValueError("Non-numeric interface diagnostic counter {} on {}".format(
                field, name))
        counters[field] = int(row[field])
    return {
        "object": oid,
        "values": counters,
        "unsupported_fields": sorted(set(fields) - counters.keys()),
        "unsupported": None if counters else (
            "LAG object has no published port drop/error fields" if portchannel
            else "drop/error fields not published"),
    }


def _kernel_rx_counters(value):
    """Allowlist numeric receive stats; never return raw netlink key material."""
    if isinstance(value, list):
        return [_kernel_rx_counters(item) for item in value]
    if not isinstance(value, dict):
        return {}
    result = {
        key: _counter_number(item, key) if key in KERNEL_RX_FIELDS
        else _kernel_rx_counters(item)
        for key, item in value.items()
        if key in KERNEL_RX_FIELDS or (
            key in ("rx_sc", "sa_list") and isinstance(item, (dict, list)))
    }
    for identity in ("sci", "an", "pn"):
        item = value.get(identity)
        if identity == "sci" and isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F:]{1,24}", item):
            result[identity] = item
        elif identity in ("an", "pn") and isinstance(item, int) and not isinstance(item, bool) and item >= 0:
            result[identity] = item
    if "ifname" in value:
        expected = ("InPktsBadTag", "InPktsUnknownSCI", "InPktsNoSA",
                    "InPktsNoTag", "InPktsNoSCI", "InPktsOverrun")
    elif "sci" in value:
        expected = (
            "InPktsInvalid", "InPktsLate", "InPktsNotValid",
            "InPktsNotUsingSA", "InPktsUnusedSA", "InPktsOK",
            "InPktsDelayed", "InPktsUnchecked",
        )
    elif "an" in value:
        expected = (
            "InPktsInvalid", "InPktsLate", "InPktsNotValid",
            "InPktsNotUsingSA", "InPktsUnusedSA", "InPktsOK",
        )
    else:
        expected = ()
    missing = sorted(set(expected) - value.keys())
    if missing:
        result["unsupported_fields"] = missing
    return result


def _counter_number(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Invalid kernel diagnostic counter {}".format(field))
    return value


def _kernel_counter_snapshot(host, port):
    prefix = get_ipnetns_prefix(host, port) + " "
    links_result = host.command(prefix + "ip -j -d link show",
                                module_ignore_errors=True, verbose=False)
    if links_result.get("rc", 0) != 0 or links_result.get("failed"):
        if "invalid option" in links_result.get("stderr", "").lower():
            return {"unsupported": "kernel ip link JSON unavailable"}
        raise RuntimeError("Unable to read kernel MACsec link identities on {}".format(port))
    links = json.loads(links_result["stdout"])
    if not isinstance(links, list) or any(not isinstance(link, dict) for link in links):
        raise ValueError("Invalid kernel MACsec link identities on {}".format(port))
    underlay = next((link for link in links if link.get("ifname") == port), None)
    devices = [link for link in links
               if link.get("linkinfo", {}).get("info_kind") == "macsec"]
    if not devices:
        return {"unsupported": "no kernel MACsec netdevices"}
    matched = [link for link in devices if underlay is not None
               and link.get("link_index") is not None
               and link.get("link_index") == underlay.get("ifindex")
               and isinstance(link.get("ifname"), str)]
    result = host.command(prefix + "ip -j -s macsec show",
                          module_ignore_errors=True, verbose=False)
    if result.get("rc", 0) != 0 or result.get("failed"):
        stderr = result.get("stderr", "").lower()
        if ("operation not supported" in stderr
                or "macsec" in stderr and "unknown" in stderr):
            return {"unsupported": "kernel MACsec counters not supported"}
        raise RuntimeError("Unable to read kernel MACsec counters on {}".format(port))
    stats = json.loads(result["stdout"])
    if not isinstance(stats, list):
        raise ValueError("Invalid kernel MACsec counters on {}".format(port))
    observations = {}
    for device in devices:
        if not isinstance(device.get("ifname"), str):
            raise ValueError("Invalid kernel MACsec device name on {}".format(port))
        name = device["ifname"]
        entries = [entry for entry in stats if isinstance(entry, dict)
                   and entry.get("ifname") == name]
        observations[name] = {
            "ifindex": device.get("ifindex"),
            "underlay_ifindex": device.get("link_index"),
            "rx": [_kernel_rx_counters(entry) for entry in entries],
            "unsupported": None if entries else "kernel MACsec RX stats not published",
            "port_attribution": "selected port" if device in matched else "unmapped namespace device",
        }
    return {"devices": observations,
            "comparability": "absolute only; SC/SA generation not established"}


def _kernel_link_counters(host, port, name):
    command = get_ipnetns_prefix(host, port) + " ip -j -s link show dev " + shlex.quote(name)
    result = host.command(command, module_ignore_errors=True, verbose=False)
    if result.get("rc", 0) != 0 or result.get("failed"):
        if "does not exist" in result.get("stderr", "").lower():
            return {"unsupported": "kernel link absent in selected namespace"}
        raise RuntimeError("Unable to read kernel link counters on {}".format(name))
    parsed = json.loads(result["stdout"])
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        raise ValueError("Invalid kernel link counters on {}".format(name))
    link = parsed[0]
    stats = link.get("stats64", link.get("stats", {}))
    return {
        "ifindex": link.get("ifindex"),
        "underlay_ifindex": link.get("link_index"),
        "values": {
            direction: {
                key: _counter_number(values[key], key)
                for key in ("dropped", "errors") if key in values
            }
            for direction in ("rx", "tx")
            for values in [stats.get(direction, {})]
        },
        "unsupported_fields": {
            direction: sorted({"dropped", "errors"} - set(stats.get(direction, {})))
            for direction in ("rx", "tx")
        },
        "comparability": "absolute only; kernel interface generation not established",
    }


def _rotation_counter_snapshot(environment, ports):
    host = environment["duthost"]
    portchannels = get_portchannel(host)
    observations = {}
    for port in ports:
        namespace = get_namespace_option(host, port)
        result = host.command(
            "show macsec {}".format(shlex.quote(port)),
            module_ignore_errors=True, verbose=False)
        if result.get("failed") or result.get("rc", 0) != 0:
            message = "{}\n{}".format(
                result.get("stdout", ""), result.get("stderr", ""))
            if re.search(r"(?:no such|unknown|unrecognized) command", message, re.IGNORECASE):
                native = {"unsupported": "native MACsec counter command unavailable"}
            else:
                raise RuntimeError("Unable to read native MACsec counters on {}".format(port))
        else:
            native = _native_counter_sections(result.get("stdout", ""))
            if not result.get("stdout", "").strip():
                native = {"unsupported": "native MACsec counters not published"}
        interface = {"port": _asic_interface_counters(host, namespace, port)}
        pc = find_portchannel_from_member(port, portchannels)
        if pc:
            interface["portchannel"] = _asic_interface_counters(
                host, namespace, pc["name"], portchannel=True)
        kernel_links = {"port": _kernel_link_counters(host, port, port)}
        if pc:
            kernel_links["portchannel"] = _kernel_link_counters(host, port, pc["name"])
        observations[port] = {
            "namespace": namespace or "default",
            "native": native,
            "interface": interface,
            "kernel_links": kernel_links,
            "kernel": _kernel_counter_snapshot(host, port),
        }
    return observations


def _counter_comparison(before, after):
    deltas = {}
    for port, current in after.items():
        previous = before[port]
        port_result = {}
        for scope, values in current["interface"].items():
            baseline = previous["interface"].get(scope)
            if (current["namespace"] != previous["namespace"]
                    or baseline is None or "object" not in baseline
                    or "object" not in values
                    or baseline["object"] != values["object"]):
                port_result[scope] = {"not_comparable": "namespace/object changed or unavailable"}
                continue
            common = baseline["values"].keys() & values["values"].keys()
            port_result[scope] = {
                field: (values["values"][field] - baseline["values"][field]
                        if values["values"][field] >= baseline["values"][field]
                        else "not_comparable: counter reset")
                for field in sorted(common)
            }
            for field in baseline["values"].keys() ^ values["values"].keys():
                port_result[scope][field] = "not_comparable: counter field absent at one boundary"
            if not common:
                port_result[scope]["not_comparable"] = "counter fields unavailable"
        deltas[port] = {
            "namespace": current["namespace"],
            "interface": port_result,
            "native": {"not_comparable":
                       "SA/SC object identity not published; absolute counters only"},
            "kernel": {"not_comparable":
                       "kernel SC/SA generation not established; absolute counters only"},
        }
    return deltas


def _wait_link_protected(
        environment, port, principal_ckn, timeout=MKA_STATE_PUBLISH_TIMEOUT,
        require_all_live=True):
    errors = [None]

    def _ready():
        errors[0] = _snapshot(environment, port).protected_errors(
            environment["profile"],
            principal_ckn,
            require_all_live=require_all_live,
        )
        return not errors[0]

    assert wait_until(timeout, 2, 0, _ready), (
        "Link {} did not become protected by {}: {}"
    ).format(port, principal_ckn, errors[0])


def _wait_environment(
        environment, principal_ckn, timeout=MKA_STATE_PUBLISH_TIMEOUT):
    deadline = time.monotonic() + timeout
    errors = {}
    ports = tuple(environment["links"])
    while time.monotonic() < deadline:
        snapshots = _snapshots(environment, ports)
        errors = {
            port: problems
            for port, snapshot in snapshots.items()
            if (problems := snapshot.protected_errors(
                environment["profile"], principal_ckn))
        }
        if not errors and time.monotonic() < deadline:
            return
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise AssertionError("MACsec environment did not recover: {}".format(errors))


def _wait_rotation_settled(
        environment, port, before, principal_ckn,
        require_rekey=True, require_all_live=True):
    _wait_rotations_settled(
        environment, {port: before}, principal_ckn,
        require_rekey=require_rekey, require_all_live=require_all_live)


def _wait_rotations_settled(
        environment, before, principal_ckn, require_rekey=True,
        require_all_live=True, check_peers=False, published=None,
        on_dut_settled=None):
    """Settle all DUT links, then inspect peers and revalidate the DUT."""
    settle = {
        port: mka_hello_timeout_seconds(snapshot.session, 3)
        for port, snapshot in before.items()
    }
    hello = {
        port: mka_hello_timeout_seconds(snapshot.session, 1)
        for port, snapshot in before.items()
    }
    started = time.monotonic()
    deadline = started + max(settle.values()) + SA_RETIRE_TIMEOUT + MKA_STATE_PUBLISH_TIMEOUT
    stable = {}
    errors = {}
    dut_settled = False

    def _problems(port, snapshot):
        problems = snapshot.protected_errors(
            environment["profile"], principal_ckn, require_all_live)
        problems.extend(snapshot.rollover_errors(before[port], require_rekey))
        if published and port in published["dut"]:
            if parse_mka_timestamp(snapshot.session["last_updated"]) <= parse_mka_timestamp(
                    published["dut"][port]):
                problems.append("DUT MKA publication did not advance")
        return problems

    def _observe(port, snapshot):
        problems = _problems(port, snapshot)
        now = time.monotonic()
        key = snapshot.active_key_identity()
        previous = stable.get(port)
        settled = (
            not problems and now - started >= settle[port]
            and previous is not None and previous[0] == key
            and now - previous[1] >= hello[port])
        return port, key, now, problems, settled

    while time.monotonic() < deadline:
        snapshots = _snapshots(environment, before)
        errors = {}
        ready = 0
        for port, snapshot in snapshots.items():
            port, key, observed_at, problems, settled = _observe(port, snapshot)
            if problems or observed_at - started < settle[port]:
                stable.pop(port, None)
                errors[port] = problems
                continue
            if port not in stable or stable[port][0] != key:
                stable[port] = key, observed_at
            if settled:
                ready += 1
            else:
                errors[port] = ["SAK/participant settle interval pending"]
        if ready == len(before) and time.monotonic() < deadline:
            dut_settled = True
            break
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    assert dut_settled, "DUT rollover did not distribute/converge/retire on {}: {}".format(
        sorted(errors), errors)

    if on_dut_settled is not None:
        on_dut_settled()

    if check_peers:
        peer_deadline = time.monotonic() + 30 + 15 * len(before)
        peer_errors = {}
        for port in before:
            if time.monotonic() >= peer_deadline:
                peer_errors[port] = ["peer inspection deadline elapsed"]
                break
            adapter = peer_adapter(environment, port)
            problems = adapter.protected_errors(
                environment["peer_profiles"][port], principal_ckn,
                require_all_live=require_all_live)
            if published and port in published["peers"] and not problems:
                if parse_mka_timestamp(adapter.publication_marker()) <= parse_mka_timestamp(
                        published["peers"][port]):
                    problems.append("peer MKA publication did not advance")
            if problems:
                peer_errors[port] = problems
            if time.monotonic() >= peer_deadline:
                peer_errors[port] = peer_errors.get(port, []) + [
                    "peer inspection deadline elapsed"]
                break
        assert not peer_errors, (
            "Peer confirmation failed on {}: {}"
        ).format(sorted(peer_errors), peer_errors)

    final = _snapshots(environment, before)
    final_errors = {}
    for port, snapshot in final.items():
        problems = _problems(port, snapshot)
        if snapshot.active_key_identity() != stable[port][0]:
            problems.append("encoding SAK changed during peer inspection")
        if problems:
            final_errors[port] = problems
    assert not final_errors, "DUT regressed after peer confirmation: {}".format(
        final_errors)


def _capture_environment_last_updated(
        environment, before, peer_ports=()):
    snapshots = {
        "dut": {
            port: snapshot.session["last_updated"]
            for port, snapshot in before.items()
        },
        "peers": {},
    }
    for port in peer_ports:
        marker = peer_adapter(environment, port).publication_marker()
        if marker is not None:
            snapshots["peers"][port] = marker
    return snapshots


def _restored_environment_published(
        environment, snapshots, principal_ckn):
    observed = _snapshots(environment, environment["links"])
    results = []
    for port, dut_snapshot in observed.items():
        if (
                port in snapshots["dut"]
                and parse_mka_timestamp(dut_snapshot.session["last_updated"])
                <= parse_mka_timestamp(snapshots["dut"][port])):
            results.append(False)
            continue
        if dut_snapshot.protected_errors(
                environment["profile"], principal_ckn):
            results.append(False)
            continue
        adapter = peer_adapter(environment, port)
        if (
                port in snapshots["peers"]
                and parse_mka_timestamp(adapter.publication_marker())
                <= parse_mka_timestamp(snapshots["peers"][port])):
            results.append(False)
            continue
        if adapter.protected_errors(
                environment["peer_profiles"][port], principal_ckn):
            results.append(False)
            continue
        results.append(True)
    return all(results)


def _wait_restored_environment_published(
        environment, snapshots, principal_ckn, description):
    deadline = time.monotonic() + MKA_STATE_PUBLISH_TIMEOUT
    while time.monotonic() < deadline:
        if _restored_environment_published(
                environment, snapshots, principal_ckn):
            return
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise AssertionError("{} did not republish within three status sweeps".format(
        description))


def _wait_peer_protected(
        adapter, profile, principal_ckn,
        timeout=MKA_STATE_PUBLISH_TIMEOUT, require_all_live=True):
    errors = [None]

    def _ready():
        errors[0] = adapter.protected_errors(
            profile, principal_ckn,
            require_all_live=require_all_live)
        return not errors[0]

    assert wait_until(timeout, 2, 0, _ready), (
        "{} peer did not become protected by {}: {}; diagnostics={}"
    ).format(
        adapter.provider,
        principal_ckn,
        errors[0],
        adapter.diagnostics(),
    )


def _wait_peer_primary_removed(
        adapter, original_profile, timeout=MKA_STATE_PUBLISH_TIMEOUT):
    errors = [None]

    def _removed():
        errors[0] = adapter.primary_removed_errors(original_profile)
        return not errors[0]

    assert wait_until(timeout, 2, 0, _removed), (
        "{} peer did not remove the original primary: {}; diagnostics={}"
    ).format(adapter.provider, errors[0], adapter.diagnostics())


def _restore_deleted_primary(environment, port, adapter, primary_pair):
    errors = []
    before = None
    try:
        before = _snapshot(environment, port)
    except BaseException as error:
        errors.append(error)
    restores = [
        lambda: adapter.add_primary(primary_pair),
        lambda: _wait_link_protected(
            environment, port, environment["profile"]["primary_ckn"]),
        lambda: _wait_peer_protected(
            adapter, environment["peer_profiles"][port],
            primary_pair[1]),
    ]
    if before is not None:
        restores.append(lambda: _wait_rotation_settled(environment, port, before, primary_pair[1]))
    for restore in restores:
        try:
            restore()
        except BaseException as error:
            errors.append(error)
    if errors:
        for error in errors[1:]:
            logger.error("Additional cEOS primary restore failure: %r",
                         error)
        raise errors[0]


def _restore_rotation(
        environment, role, original_profile, peer_originals,
        new_pair, attempted_ports, fully_rotated):
    profile = environment["profile"]
    old_pair = (
        original_profile["{}_cak".format(role)],
        original_profile["{}_ckn".format(role)],
    )
    snapshots = None
    before = {}
    errors = []
    try:
        before = _snapshots(environment, environment["links"])
        snapshots = _capture_environment_last_updated(
            environment, before, peer_ports=tuple(attempted_ports))
    except BaseException as error:
        errors.append(error)

    try:
        restore_macsec_profile_key(
            environment["duthost"], profile["name"],
            old_pair[0], old_pair[1], new_pair[0], new_pair[1],
            is_fallback=role == "fallback")
    except BaseException as error:
        errors.append(error)

    profile["{}_cak".format(role)] = old_pair[0]
    profile["{}_ckn".format(role)] = old_pair[1]
    if role == "primary" and fully_rotated[0] and not errors:
        try:
            _wait_rotations_settled(
                environment, before, profile["fallback_ckn"],
                require_all_live=False)
            before = _snapshots(environment, environment["links"])
        except BaseException as error:
            errors.append(error)

    for port in attempted_ports:
        restored = peer_originals[port]
        try:
            _restore_peer_step(
                environment, port, role, restored, new_pair)
        except BaseException as error:
            errors.append(error)

    if not errors:
        try:
            if fully_rotated[0]:
                _wait_rotations_settled(
                    environment, before, original_profile["primary_ckn"],
                    require_rekey=True if role == "primary" else (
                        False if profile["rekey_period"] == 0 else None),
                    check_peers=True, published=snapshots)
            else:
                assert wait_until(
                    MKA_STATE_PUBLISH_TIMEOUT, 2, 0,
                    _environment_is_healthy, environment,
                ), "MKA did not recover after partial {} rotation".format(
                    role)
        except BaseException as error:
            errors.append(error)
    if errors:
        for error in errors[1:]:
            logger.error("Additional MACsec rotation cleanup failure: %r",
                         error)
        raise errors[0]


def _restore_peer_step(environment, port, role, old_profile, new_pair):
    adapter = peer_adapter(environment, port)
    try:
        adapter.restore_key(role, old_profile, new_pair)
    finally:
        adapter.commit_profile(old_profile)


@contextmanager
def _rotated_cak(environment, role, new_pair, selected_port, upstream_links):
    """Measure the forward replacement; verify restoration outside traffic."""
    profile = environment["profile"]
    original_profile = dict(profile)
    old_pair = (profile["{}_cak".format(role)], profile["{}_ckn".format(role)])
    peer_originals = {port: dict(value) for port, value in environment["peer_profiles"].items()}
    before = _snapshots(environment, environment["links"])
    transit_ports = (selected_port, _transit_peer(
        environment, upstream_links, selected_port))
    counter_samples = {
        "before_forward": _rotation_counter_snapshot(environment, transit_ports)}
    logger.warning("MACsec %s counter diagnostics before_forward (diagnostic only): %s",
                   role, counter_samples["before_forward"])
    attempted = []
    completed = [False]
    started = [False]
    restored = [False]

    def _record_counters(phase):
        if not started[0]:
            logger.warning("MACsec %s counter diagnostics %s (diagnostic only): "
                           "forward rotation not started", role, phase)
            return
        if phase == "after_restored" and not restored[0]:
            phase = "after_restoration_failed"
        counters = _rotation_counter_snapshot(environment, transit_ports)
        counter_samples[phase] = counters
        logger.warning("MACsec %s counter diagnostics %s (diagnostic only): %s; relative_to_before: %s",
                       role, phase, counters, _counter_comparison(
                           counter_samples["before_forward"], counters))

    def _restore_keys():
        _restore_rotation(
            environment, role, original_profile,
            peer_originals, new_pair, attempted, completed)
        restored[0] = True

    with FailureSafeCleanup("{} rotation".format(role)) as cleanup:
        cleanup.callback(_record_counters, "after_restored")
        cleanup.callback(_restore_keys)
        try:
            with _TrafficWindow(environment, upstream_links, port=selected_port) as traffic:
                started[0] = True
                _profile_update(
                    environment["duthost"], profile["name"], old_pair[0], old_pair[1],
                    new_pair[0], new_pair[1], is_fallback=role == "fallback")
                profile["{}_cak".format(role)], profile["{}_ckn".format(role)] = new_pair
                if role == "primary":
                    _wait_rotations_settled(
                        environment, before, profile["fallback_ckn"],
                        require_all_live=False)
                    before = _snapshots(environment, environment["links"])
                ports = [selected_port] + [port for port in environment["links"] if port != selected_port]
                for adapter in peer_adapters(environment, ports):
                    attempted.append(adapter.port)
                    adapter.rotate(role, old_pair, new_pair)
                require_rekey = True if role == "primary" else (
                    False if profile["rekey_period"] == 0 else None)

                def _finish_measured_rotation():
                    for port in transit_ports:
                        _wait_peer_protected(
                            peer_adapter(environment, port),
                            environment["peer_profiles"][port],
                            profile["primary_ckn"])
                    endpoint_snapshots = _snapshots(environment, transit_ports)
                    for port, snapshot in endpoint_snapshots.items():
                        assert not snapshot.protected_errors(
                            profile, profile["primary_ckn"]), (
                                "Transit link {} did not remain protected".format(port))
                        assert not snapshot.rollover_errors(before[port], require_rekey), (
                            "Transit link {} did not finish the forward SAK rollover".format(port))
                    completed[0] = True
                    traffic.assert_zero_loss()

                _wait_rotations_settled(
                    environment, before, profile["primary_ckn"],
                    require_rekey=require_rekey, check_peers=True,
                    on_dut_settled=_finish_measured_rotation)
        finally:
            if started[0]:
                body_failed = sys.exc_info()[0] is not None
                try:
                    _record_counters("after_forward")
                except BaseException:
                    if not body_failed:
                        raise
                    logger.exception("MACsec %s forward counter diagnostics failed after scenario error", role)
        yield


def _wait_link_blocked(
        environment, port, expected_ckns,
        previous_last_updated=None, timeout=MKA_STATE_PUBLISH_TIMEOUT):
    errors = [None]

    def _blocked():
        snapshot = _snapshot(environment, port)
        errors[0] = snapshot.blocked_errors(expected_ckns)
        if (
                previous_last_updated is not None
                and snapshot.session.get("last_updated")
                == previous_last_updated):
            errors[0].append("STATE_DB publication is stale")
        return not errors[0]

    assert wait_until(timeout, 2, 0, _blocked), (
        "Link {} did not block: {}"
    ).format(port, errors[0])


def _wait_peer_blocked(
        adapter, expected_ckns, previous_last_updated=None,
        timeout=MKA_STATE_PUBLISH_TIMEOUT):
    errors = [None]

    def _blocked():
        errors[0] = adapter.blocked_errors(
            expected_ckns,
            previous_last_updated=previous_last_updated)
        return not errors[0]

    assert wait_until(timeout, 2, 0, _blocked), (
        "{} peer did not block: {}"
    ).format(adapter.provider, errors[0])


def _diagnostics(environment, port):
    return {
        "dut": _snapshot(environment, port).redacted(),
        "peer": peer_adapter(environment, port).diagnostics(),
    }


def _safe_diagnostics(environment, port):
    try:
        return _diagnostics(environment, port)
    except Exception as error:
        return {"collection_error": type(error).__name__}


def _restore_mismatch(
        environment, port, adapter, original_profile, invalid_pair, role):
    profile = environment["profile"]
    principal = profile["{}_ckn".format(role)]
    require_all_live = role == "primary"
    before = None
    observation_error = None
    try:
        before = _snapshot(environment, port)
    except BaseException as error:
        observation_error = error
    try:
        adapter.restore_key(role, original_profile, invalid_pair)
        _wait_link_protected(
            environment, port, principal,
            require_all_live=require_all_live)
        _wait_peer_protected(
            adapter, original_profile, principal,
            require_all_live=require_all_live)
        if role == "primary" and before is not None:
            _wait_rotation_settled(environment, port, before, principal)
        if observation_error is not None:
            raise observation_error
    except BaseException as error:
        logger.error(
            "%s mismatch cleanup failed: %r; diagnostics=%s",
            role, error, _safe_diagnostics(environment, port))
        raise
    finally:
        adapter.commit_profile(original_profile)


@contextmanager
def _primary_mismatch(environment, port, invalid_pair):
    profile = environment["profile"]
    adapter = peer_adapter(environment, port)
    original_profile = dict(environment["peer_profiles"][port])
    original_pair = (
        original_profile["primary_cak"],
        original_profile["primary_ckn"],
    )
    mismatched_profile = adapter.profile_with_pair(
        original_profile, "primary", invalid_pair)
    before = _snapshot(environment, port)

    with FailureSafeCleanup("primary mismatch") as cleanup:
        cleanup.callback(
            _restore_mismatch, environment, port, adapter,
            original_profile, invalid_pair, "primary")
        if adapter.supports_primary_delete:
            adapter.delete_primary_if_supported(original_pair)
            _wait_link_protected(
                environment, port, profile["fallback_ckn"],
                require_all_live=False)
            _wait_peer_primary_removed(adapter, original_profile)
            adapter.add_primary(invalid_pair)
        else:
            adapter.rotate(
                "primary",
                original_pair,
                invalid_pair,
                commit=False,
                base_profile=original_profile,
            )

        _wait_link_protected(
            environment, port, profile["fallback_ckn"],
            require_all_live=False)
        _wait_peer_protected(
            adapter,
            mismatched_profile,
            profile["fallback_ckn"],
            require_all_live=False,
        )
        adapter.commit_profile(mismatched_profile)
        _wait_rotation_settled(
            environment, port, before, profile["fallback_ckn"], require_all_live=False)
        yield adapter


@contextmanager
def _ceos_fallback_mismatch(
        environment, port, adapter, invalid_pair):
    profile = environment["profile"]
    original_profile = dict(environment["peer_profiles"][port])
    original_pair = (
        original_profile["fallback_cak"],
        original_profile["fallback_ckn"],
    )
    mismatched_profile = adapter.profile_with_pair(
        original_profile, "fallback", invalid_pair)
    previous_last_updated = _snapshot(
        environment, port).session.get("last_updated")

    with FailureSafeCleanup("fallback mismatch") as cleanup:
        cleanup.callback(
            _restore_mismatch, environment, port, adapter,
            original_profile, invalid_pair, "fallback")
        adapter.delete_fallback(original_pair)
        _wait_link_blocked(
            environment, port,
            (profile["primary_ckn"], profile["fallback_ckn"]),
            previous_last_updated=previous_last_updated)
        adapter.add_fallback(invalid_pair)
        _wait_link_blocked(
            environment, port,
            (profile["primary_ckn"], profile["fallback_ckn"]))
        _wait_peer_blocked(
            adapter,
            (
                mismatched_profile["primary_ckn"],
                mismatched_profile["fallback_ckn"],
            ),
        )
        adapter.commit_profile(mismatched_profile)
        yield adapter


def _select_routed_link(environment, upstream_links, ports=None):
    portchannels = get_portchannel(environment["duthost"])
    duthost = environment["duthost"]
    eligible = []
    for port in environment["links"]:
        portchannel = find_portchannel_from_member(port, portchannels)
        if port in upstream_links and (not portchannel or len(portchannel["members"]) == 1):
            eligible.append(port)
    for port in eligible if ports is None else ports:
        if port not in eligible:
            continue
        if any(
                other != port
                and environment["links"][other]["name"] != environment["links"][port]["name"]
                and upstream_links[other]["local_ipv4_addr"] != upstream_links[port]["local_ipv4_addr"]
                and (not duthost.is_multi_asic or get_namespace_option(duthost, other)
                     == get_namespace_option(duthost, port))
                for other in eligible):
            return port, environment["links"][port]
    pytest.skip(
        "Transit MACsec traffic requires two distinct controlled routed neighbors "
        "on the same ASIC, each direct or on a single-member PortChannel")


def _transit_peer(environment, upstream_links, selected_port):
    duthost = environment["duthost"]
    portchannels = get_portchannel(duthost)
    selected = environment["links"][selected_port]
    for port, neighbor in environment["links"].items():
        if port == selected_port or port not in upstream_links:
            continue
        pc = find_portchannel_from_member(port, portchannels)
        if pc and len(pc["members"]) != 1:
            continue
        if (neighbor["name"] != selected["name"]
                and upstream_links[port]["local_ipv4_addr"]
                != upstream_links[selected_port]["local_ipv4_addr"]
                and (not duthost.is_multi_asic or get_namespace_option(duthost, port)
                     == get_namespace_option(duthost, selected_port))):
            return port
    pytest.skip("No distinct controlled neighbor on the selected ASIC for transit traffic")


def _route_result(host, port, command, allow_unreachable=False):
    result = host.command(
        "{} {}".format(_ping_namespace_prefix(host, port), command),
        module_ignore_errors=True, verbose=False)
    if result.get("failed") or result.get("rc", 0) != 0:
        if (allow_unreachable and "Network is unreachable" in result.get("stderr", "")):
            return ""
        raise RuntimeError("Unable to verify transit route on {}: {}".format(
            host.hostname, command))
    return result["stdout"].strip()


def _route_value(output, field):
    words = shlex.split(output)
    return words[words.index(field) + 1] if field in words and words.index(field) + 1 < len(words) else None


def _route_source(output):
    return _route_value(output, "from") or _route_value(output, "src")


def _stable_data_loopback(host, port):
    output = _route_result(host, port, "ip -o -4 addr show")
    candidates = {
        address
        for device, address in re.findall(
            r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/32\b",
            output, re.MULTILINE)
        if (device in ("lo", "lo0") or device.startswith("Loopback"))
        and not ipaddress.ip_address(address).is_loopback
    }
    if len(candidates) != 1:
        pytest.skip("Stable transit requires one data-VRF /32 loopback on each neighbor")
    return candidates.pop()


@contextmanager
def _stable_transit_path(environment, upstream_links, selected_port, other_port):
    """Own reversible neighbor and DUT routes to stable data-VRF loopbacks."""
    duthost = environment["duthost"]
    ports = (selected_port, other_port)
    portchannels = get_portchannel(duthost)
    sources = {
        port: _stable_data_loopback(
            environment["links"][port]["host"],
            environment["links"][port]["port"])
        for port in ports
    }
    if sources[selected_port] == sources[other_port]:
        pytest.skip("Transit neighbor loopback addresses must be distinct")
    endpoints = []
    routes = []
    for port, destination_port in ((selected_port, other_port), (other_port, selected_port)):
        neighbor = environment["links"][port]
        host = neighbor["host"]
        gateway = upstream_links[port]["peer_ipv4_addr"]
        address = upstream_links[port]["local_ipv4_addr"]
        destination = sources[destination_port]
        local_route = _route_result(
            host, neighbor["port"],
            "ip -4 route get {} from {}".format(gateway, sources[port]))
        link_route = _route_result(
            host, neighbor["port"],
            "ip -4 route get {} from {}".format(gateway, address))
        device = _route_value(local_route, "dev")
        if (not device or device != _route_value(link_route, "dev")
                or _route_source(local_route) != sources[port]
                or _route_value(local_route, "via")):
            pytest.skip("Neighbor loopback cannot reach its protected DUT gateway")
        endpoints.append((
            host, neighbor["port"], sources[port], destination, gateway, device))
        routes.append((
            destination_port, "{}/32".format(destination),
            upstream_links[destination_port]["local_ipv4_addr"]))

    namespace = get_namespace_option(duthost, selected_port)
    ns_name = namespace.split()[-1] if namespace else ""

    def _checked(host, command):
        result = host.command(command, module_ignore_errors=True, verbose=False)
        if result.get("failed") or result.get("rc", 0) != 0:
            raise RuntimeError("Transit route command failed on {}: {}".format(
                host.hostname, command))
        return result

    def _db(db, operation, key):
        return _checked(
            duthost, "sonic-db-cli {} {} {} {}".format(
                namespace, db, operation, shlex.quote(key)))

    def _route_keys(prefix):
        pattern = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*{}*".format(prefix)
        return [
            key for key in _db("ASIC_DB", "KEYS", pattern).get("stdout_lines", [])
            if key.strip()
        ]

    def _asic_route(prefix):
        matches = []
        marker = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:"
        switches = [
            key.strip() for key in _db(
                "ASIC_DB", "KEYS", "ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*"
            ).get("stdout_lines", []) if key.strip()
        ]
        if len(switches) != 1:
            return []
        switch = parse_db_hash(_db(
            "ASIC_DB", "HGETALL", switches[0]).get("stdout", ""))
        default_vr = switch.get("SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID")
        if not default_vr:
            default_routes = []
            for key in _route_keys("0.0.0.0/0"):
                if not key.startswith(marker):
                    raise ValueError("Unexpected ASIC default route key")
                default_route = json.loads(key[len(marker):])
                if default_route.get("dest") == "0.0.0.0/0":
                    default_routes.append(default_route.get("vr"))
            if len(default_routes) != 1 or not default_routes[0]:
                return []
            default_vr = default_routes[0]
        for key in _route_keys(prefix):
            if not key.startswith(marker):
                raise ValueError("Unexpected ASIC route key")
            try:
                route = json.loads(key[len(marker):])
            except (TypeError, ValueError) as error:
                raise ValueError("Malformed ASIC route key") from error
            if route.get("dest") == prefix:
                if route.get("vr") != default_vr:
                    raise AssertionError("ASIC route is not in the default data VRF")
                matches.append(key)
        return matches

    def _vtysh(line):
        command = "vtysh -c {} -c {}".format(
            shlex.quote("configure terminal"), shlex.quote(line))
        if ns_name:
            command = duthost.get_vtysh_cmd_for_namespace(command, ns_name)
        return _checked(duthost, command)

    def _running_static(prefix):
        command = "vtysh -c {}".format(shlex.quote("show running-config"))
        if ns_name:
            command = duthost.get_vtysh_cmd_for_namespace(command, ns_name)
        lines = _checked(duthost, command).get("stdout", "").splitlines()
        return [
            line.strip() for line in lines
            if re.match(r"^\s*ip route {}(?:\s|$)".format(re.escape(prefix)), line)
        ]

    def _owned_dut_route(port, prefix, nexthop):
        expected_dev = find_portchannel_from_member(port, portchannels)
        expected_dev = expected_dev["name"] if expected_dev else port
        if _running_static(prefix) != ["ip route {} {}".format(prefix, nexthop)]:
            return False
        row = parse_db_hash(_db(
            "APPL_DB", "HGETALL", "ROUTE_TABLE:{}".format(prefix)).get("stdout", ""))
        if row and (row.get("nexthop") != nexthop
                    or row.get("ifname") != expected_dev):
            return False
        keys = _asic_route(prefix)
        if len(keys) != 1:
            return False
        route = parse_db_hash(_db("ASIC_DB", "HGETALL", keys[0]).get("stdout", ""))
        oid = route.get("SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID", "")
        if not oid.startswith("oid:"):
            return False
        nexthop_row = parse_db_hash(_db(
            "ASIC_DB", "HGETALL",
            "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP:{}".format(oid)).get("stdout", ""))
        rif = nexthop_row.get("SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID", "")
        if not rif.startswith("oid:"):
            return False
        rif_row = parse_db_hash(_db(
            "ASIC_DB", "HGETALL",
            "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:{}".format(rif)
        ).get("stdout", ""))
        port_oid = _checked(
            duthost, "sonic-db-cli {} COUNTERS_DB HGET {} {}".format(
                namespace, shlex.quote("COUNTERS_PORT_NAME_MAP"),
                shlex.quote(expected_dev))).get("stdout", "").strip()
        return (
            nexthop_row.get("SAI_NEXT_HOP_ATTR_IP") == nexthop
            and nexthop_row.get("SAI_NEXT_HOP_ATTR_TYPE") == "SAI_NEXT_HOP_TYPE_IP"
            and bool(port_oid)
            and rif_row.get("SAI_ROUTER_INTERFACE_ATTR_PORT_ID") == port_oid)

    def _dut_route_correct(port, destination_port):
        source = sources[port]
        destination = sources[destination_port]
        incoming = find_portchannel_from_member(port, portchannels)
        incoming_dev = incoming["name"] if incoming else port
        outgoing = find_portchannel_from_member(destination_port, portchannels)
        expected_dev = outgoing["name"] if outgoing else destination_port
        route = _route_result(
            duthost, destination_port,
            "ip -4 route get {} from {} iif {}".format(
                destination, source, incoming_dev))
        return (
            _route_value(route, "dev") == expected_dev
            and _route_value(route, "via")
            == upstream_links[destination_port]["local_ipv4_addr"]
            and "nexthop" not in route.split())

    def _peer_config(endpoint):
        host, port, source, destination, gateway, device = endpoint
        line = "ip route {}{}/32 {}".format(
            "vrf {} ".format(host.bgp_vrf) if isinstance(host, EosHost) and host.bgp_vrf else "",
            destination, gateway)
        result = host.eos_command(commands=["show running-config | include ^ip route"])
        if result.get("failed") or result.get("rc", 0) != 0:
            raise RuntimeError("Unable to read neighbor static route configuration")
        output = result.get("stdout", [])
        if not output or not isinstance(output[0], str):
            raise ValueError("Malformed neighbor static route configuration")
        present = [
            entry.strip() for entry in output[0].splitlines()
            if re.search(r"(?<!\S){}/32(?:\s|$)".format(re.escape(destination)), entry)
        ]
        return line, present

    def _remove_peer_route(endpoint):
        host, port, source, destination, gateway, device = endpoint
        if not isinstance(host, EosHost):
            exact = _route_result(host, port, "ip -4 route show exact {}/32".format(destination))
            if exact:
                if (_route_value(exact, "via") != gateway
                        or _route_value(exact, "dev") != device):
                    raise AssertionError("Test-owned neighbor route changed during cleanup")
                _route_result(host, port, "sudo ip -4 route del {}/32 via {} dev {}".format(
                    destination, gateway, device))
            return
        line, present = _peer_config(endpoint)
        if not present:
            return
        if present != [line]:
            raise AssertionError("Test-owned EOS static route changed during cleanup")
        result = host.eos_config(lines=["no {}".format(line)])
        if result.get("failed") or result.get("rc", 0) != 0:
            raise RuntimeError("Unable to remove test-owned EOS static route")
        assert not _peer_config(endpoint)[1], "Test-owned EOS static route remains configured"

    def _remove_dut_route(route):
        port, prefix, nexthop = route
        line = "ip route {} {}".format(prefix, nexthop)
        configured = _running_static(prefix)
        if configured:
            assert configured == [line], "Test-owned DUT static route changed during cleanup"
            _vtysh("no {}".format(line))

        def _absent():
            return (
                not _running_static(prefix)
                and not _db("CONFIG_DB", "KEYS",
                            "STATIC_ROUTE*{}*".format(prefix)).get("stdout", "").strip()
                and not parse_db_hash(_db(
                    "APPL_DB", "HGETALL", "ROUTE_TABLE:{}".format(prefix)
                ).get("stdout", ""))
                and not _asic_route(prefix)
                and not _route_result(
                    duthost, port, "ip -4 route show exact {}".format(prefix)))

        _await_route(_absent, 60, "Test-owned DUT route did not withdraw")

    def _await_route(condition, timeout, message):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(2)
        raise AssertionError(message)

    for port, prefix, nexthop in routes:
        if (_running_static(prefix)
                or _db("CONFIG_DB", "KEYS", "STATIC_ROUTE*{}*".format(prefix)).get("stdout", "").strip()
                or parse_db_hash(_db(
                    "APPL_DB", "HGETALL", "ROUTE_TABLE:{}".format(prefix)
                ).get("stdout", ""))
                or _asic_route(prefix)
                or _route_result(duthost, port, "ip -4 route show exact {}".format(prefix))):
            pytest.skip("Cannot own existing DUT /32 route {}".format(prefix))
    for endpoint in endpoints:
        if isinstance(endpoint[0], EosHost) and _peer_config(endpoint)[1]:
            pytest.skip("Cannot own existing EOS /32 route to stable neighbor loopback")
        if not isinstance(endpoint[0], EosHost) and _route_result(
                endpoint[0], endpoint[1],
                "ip -4 route show exact {}/32".format(endpoint[3])):
            pytest.skip("Cannot own existing neighbor /32 route")

    with FailureSafeCleanup("stable transit route restoration") as cleanup:
        for route in routes:
            port, prefix, nexthop = route
            cleanup.callback(_remove_dut_route, route)
            _vtysh("ip route {} {}".format(prefix, nexthop))
        _await_route(
            lambda: all(_owned_dut_route(*route) for route in routes)
            and all(_dut_route_correct(port, other) for port, other in (
                (selected_port, other_port), (other_port, selected_port))),
            90, "DUT static routes did not reach the selected FRR/ASIC forwarding paths")
        assert all(not _db(
            "CONFIG_DB", "KEYS", "STATIC_ROUTE*{}*".format(prefix)
        ).get("stdout", "").strip() for _, prefix, _ in routes), (
            "Runtime DUT route unexpectedly appeared in persisted CONFIG_DB")
        for endpoint in endpoints:
            host, port, source, destination, gateway, device = endpoint
            cleanup.callback(_remove_peer_route, endpoint)
            if isinstance(host, EosHost):
                line, _ = _peer_config(endpoint)
                result = host.eos_config(lines=[line])
                if result.get("failed") or result.get("rc", 0) != 0:
                    raise RuntimeError("Unable to install test-owned EOS static route")
                assert _peer_config(endpoint)[1] == [line], (
                    "EOS data-VRF static route was not installed")
            else:
                _route_result(
                    host, port,
                    "sudo ip -4 route add {}/32 via {} dev {} src {}".format(
                        destination, gateway, device, source))

        def _neighbor_route(endpoint):
            host, port, source, destination, gateway, device = endpoint
            route = _route_result(
                host, port, "ip -4 route get {} from {}".format(destination, source))
            return (_route_value(route, "via") == gateway
                    and _route_value(route, "dev") == device
                    and _route_source(route) == source
                    and "nexthop" not in route.split())
        _await_route(
            lambda: all(_neighbor_route(endpoint) for endpoint in endpoints),
            60, "Neighbor stable loopback routes did not pin through the DUT")
        yield endpoints
        assert all(_neighbor_route(endpoint) for endpoint in endpoints), (
            "Neighbor stable routes did not recover after MACsec restoration")
        assert all(_owned_dut_route(*route) for route in routes), (
            "DUT hardware routes did not recover after MACsec restoration")
        assert (_dut_route_correct(selected_port, other_port)
                and _dut_route_correct(other_port, selected_port)), (
            "DUT stable transit route changed after MACsec restoration")


@contextmanager
def _transit_path(environment, upstream_links, selected_port, stable_endpoints=False):
    """Own only newly added endpoint routes; verify both ASIC transit directions."""
    other_port = _transit_peer(environment, upstream_links, selected_port)
    if stable_endpoints:
        with _stable_transit_path(
                environment, upstream_links, selected_port, other_port) as endpoints:
            yield endpoints
        return
    duthost = environment["duthost"]
    portchannels = get_portchannel(duthost)
    endpoints = []

    def _dut_route_correct(port, destination_port):
        source = upstream_links[port]["local_ipv4_addr"]
        destination = upstream_links[destination_port]["local_ipv4_addr"]
        incoming_pc = find_portchannel_from_member(port, portchannels)
        incoming_dev = incoming_pc["name"] if incoming_pc else port
        route = _route_result(
            duthost, destination_port,
            "ip -4 route get {} from {} iif {}".format(
                destination, source, incoming_dev))
        outgoing_pc = find_portchannel_from_member(destination_port, portchannels)
        expected_dev = outgoing_pc["name"] if outgoing_pc else destination_port
        return (_route_value(route, "dev") == expected_dev
                and not _route_value(route, "via")
                and "nexthop" not in route.split())

    for port, destination_port in ((selected_port, other_port), (other_port, selected_port)):
        link = upstream_links[port]
        neighbor = environment["links"][port]
        destination = upstream_links[destination_port]["local_ipv4_addr"]
        host = neighbor["host"]
        source = link["local_ipv4_addr"]
        gateway = link["peer_ipv4_addr"]
        local_route = _route_result(
            host, neighbor["port"], "ip -4 route get {} from {}".format(gateway, source))
        device = _route_value(local_route, "dev")
        if not device or _route_source(local_route) != source:
            pytest.skip("Neighbor has no source-bound data route to its DUT-facing gateway")
        if not _dut_route_correct(port, destination_port):
            pytest.skip("DUT route to {} does not use protected port {}".format(
                destination, destination_port))
        endpoints.append((host, neighbor["port"], source, destination, gateway, device))

    def _check_route(endpoint):
        host, port, source, destination, gateway, device = endpoint
        route = _route_result(
            host, port, "ip -4 route get {} from {}".format(destination, source),
            allow_unreachable=True)
        return (_route_value(route, "via") == gateway
                and _route_value(route, "dev") == device
                and _route_source(route) == source
                and "nexthop" not in route.split())

    def _remove_route(endpoint):
        host, port, source, destination, gateway, device = endpoint
        exact = _route_result(
            host, port, "ip -4 route show exact {}/32".format(destination))
        if not exact:
            return
        if (len(exact.splitlines()) != 1
                or _route_value(exact, "via") != gateway
                or _route_value(exact, "dev") != device):
            raise AssertionError("Test-owned transit route changed before cleanup")
        _route_result(host, port, "sudo ip -4 route del {}/32 via {} dev {}".format(
            destination, gateway, device))

    with FailureSafeCleanup("transit route restoration") as cleanup:
        for endpoint in endpoints:
            if _check_route(endpoint):
                continue
            host, port, source, destination, gateway, device = endpoint
            exact = _route_result(
                host, port, "ip -4 route show exact {}/32".format(destination))
            if exact:
                pytest.skip("Existing host route prevents pinned transit path to {}".format(destination))
            cleanup.callback(_remove_route, endpoint)
            _route_result(host, port, "sudo ip -4 route add {}/32 via {} dev {} src {}".format(
                destination, gateway, device, source))
        assert all(_check_route(endpoint) for endpoint in endpoints), (
            "Transit route did not pin both neighbor endpoints through the DUT")
        yield endpoints
        assert all(_check_route(endpoint) for endpoint in endpoints), (
            "Transit neighbor route changed during the observation")
        assert (_dut_route_correct(selected_port, other_port)
                and _dut_route_correct(other_port, selected_port)), (
            "DUT transit forwarding route changed during the observation")


def _set_rekey_period(host, port, profile_name, rekey_period):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=[
                "mka session rekey-period {}".format(rekey_period)
                if rekey_period else "no mka session rekey-period"
            ],
            parents=['mac security', 'profile {}'.format(profile_name)])
        return
    host.command(
        "sonic-db-cli {} CONFIG_DB HSET 'MACSEC_PROFILE|{}' "
        "rekey_period {}".format(
            get_namespace_option(host, port),
            profile_name,
            rekey_period,
        ))


def _reapply_macsec_ports(environment, ports):
    with FailureSafeCleanup("MACsec port reapply") as cleanup:
        for port in ports:
            cleanup.callback(
                enable_macsec_port, environment["duthost"], port, environment["profile"]["name"])
        cleanup_all(ports, lambda port: disable_macsec_port(environment["duthost"], port))


def _configure_environment_rekey_period(environment, rekey_period):
    restarted_hosts = {}
    duthost = environment["duthost"]
    for port in environment["links"]:
        _set_rekey_period(
            duthost, port, environment["profile"]["name"], rekey_period)
    restarted_hosts[duthost.hostname] = duthost

    for port, neighbor in environment["links"].items():
        _set_rekey_period(
            neighbor["host"], neighbor["port"],
            environment["neighbor_profiles"][port], rekey_period)
        if not isinstance(neighbor["host"], EosHost):
            restarted_hosts[neighbor["host"].hostname] = neighbor["host"]

    for host in restarted_hosts.values():
        restart_service_with_startlimit_guard(
            host, "macsec", is_namespaced=host.is_multi_asic,
            backoff_seconds=35, verify_timeout=180)


def _restore_rekey_period(environment, original_period):
    try:
        _configure_environment_rekey_period(environment, original_period)
    finally:
        environment["profile"]["rekey_period"] = original_period
    assert wait_until(
        MKA_CONVERGE_TIMEOUT, 3, 0,
        _environment_is_healthy, environment,
    ), "MKA did not recover after boundary stress cleanup"


def _environment_is_healthy(
        environment, principal_ckn=None, require_all_live=True,
        validate_peers=True):
    profile = environment["profile"]
    principal_ckn = principal_ckn or profile["primary_ckn"]
    for port in environment["links"]:
        errors = _snapshot(environment, port).protected_errors(
            profile, principal_ckn,
            require_all_live=require_all_live)
        if errors:
            logger.info("DUT MKA state on %s is not ready: %s", port, errors)
            return False
        if validate_peers:
            peer_errors = peer_adapter(
                environment, port).protected_errors(
                    environment["peer_profiles"][port],
                    principal_ckn,
                    require_all_live=require_all_live)
            if peer_errors:
                logger.info(
                    "Peer MKA state on %s is not ready: %s",
                    environment["links"][port]["port"],
                    peer_errors)
                return False
    return True


def _start_ping(host, port, source, destination, suffix):
    path = "/tmp/macsec_fallback_{}_{}.log".format(port, suffix)
    host.shell("rm -f {}".format(path), module_ignore_errors=True)
    prefix = _ping_namespace_prefix(host, port)
    command = "{} ping -D -i 0.1 -I {} {}".format(
        prefix, source, destination)
    result = host.shell(
        "nohup {} > {} 2>&1 < /dev/null & echo $!".format(command, path))
    pid = int(result["stdout_lines"][-1])
    assert pid > 0, "Continuous ping did not return a valid process ID"
    return {
        "host": host,
        "path": path,
        "pid": pid,
    }


def _ping_namespace_prefix(host, port):
    if isinstance(host, EosHost):
        return (
            "sudo ip netns exec ns-{}".format(host.bgp_vrf)
            if host.bgp_vrf else "")
    return get_ipnetns_prefix(host, port)


def _parse_ping_output(output):
    """Return successful reply sequences and the final ping summary."""
    reply_pattern = re.compile(
        r"^\s*(?:\[[^\]]+\]\s*)?\d+\s+bytes\s+from\b.*?"
        r"\bicmp_seq[= ](\d+)\b",
        re.MULTILINE,
    )
    summary_pattern = re.compile(
        r"^\s*(\d+) packets transmitted, "
        r"(\d+) (?:packets )?received,.*?"
        r"([\d.]+)% packet loss",
        re.MULTILINE,
    )
    summary = summary_pattern.search(output)
    return {
        "received_sequences": {
            int(sequence)
            for sequence in reply_pattern.findall(output)
        },
        "summary": (
            {
                "transmitted": int(summary.group(1)),
                "received": int(summary.group(2)),
                "loss_percent": float(summary.group(3)),
            }
            if summary else None
        ),
    }


def _ping_observation_result(pre_stop_output, final_output, start_boundary=0):
    """Measure replies after startup through the last pre-stop reply."""
    pre_stop = _parse_ping_output(pre_stop_output)
    final = _parse_ping_output(final_output)
    received_before_stop = pre_stop["received_sequences"]
    if not received_before_stop:
        return {
            "errors": ["no ping replies were observed before shutdown"],
            "boundary": None,
            "missing_sequences": [],
            "summary": final["summary"],
        }

    boundary = max(received_before_stop)
    received_by_exit = final["received_sequences"]
    missing_sequences = sorted(
        set(range(start_boundary + 1, boundary + 1)) - received_by_exit)
    errors = []
    if boundary - start_boundary < 10:
        errors.append(
            "traffic sample ended at sequence {} after starting at {}, "
            "expected at least 10".format(boundary, start_boundary))
    if missing_sequences:
        errors.append(
            "missing ping sequences within observation window")
    return {
        "errors": errors,
        "boundary": boundary,
        "missing_sequences": missing_sequences,
        "summary": final["summary"],
    }


def _read_ping_output(ping, ignore_errors=False):
    result = ping["host"].shell(
        "cat {}".format(ping["path"]),
        module_ignore_errors=ignore_errors,
    )
    return result.get("stdout", "")


def _ping_process_running(ping):
    result = ping["host"].shell(
        "sudo kill -0 {}".format(ping["pid"]),
        module_ignore_errors=True,
    )
    return not result.get("failed")


def _drain_ping_observation(ping):
    """Wait for post-transition replies before closing the observation."""
    initial_output = _read_ping_output(ping, ignore_errors=True)
    initial_sequences = _parse_ping_output(
        initial_output)["received_sequences"]
    initial_boundary = max(initial_sequences) if initial_sequences else 0
    target_boundary = max(10, initial_boundary + 3)
    drained_output = [initial_output]

    def _drained():
        if not _ping_process_running(ping):
            return False
        drained_output[0] = _read_ping_output(
            ping, ignore_errors=True)
        sequences = _parse_ping_output(
            drained_output[0])["received_sequences"]
        return bool(sequences) and max(sequences) >= target_boundary

    drained = wait_until(15, 1, 0, _drained)
    return {
        "drained": drained,
        "output": drained_output[0],
        "initial_boundary": initial_boundary,
        "target_boundary": target_boundary,
    }


def _stop_ping(ping, assert_loss=True):
    was_running = _ping_process_running(ping)
    drain = _drain_ping_observation(ping)
    pre_stop_output = drain["output"]
    signal_result = ping["host"].shell(
        "sudo kill -INT {}".format(ping["pid"]),
        module_ignore_errors=True,
    )
    exited = wait_until(
        15, 1, 0, lambda: not _ping_process_running(ping))
    if not exited:
        ping["host"].shell(
            "sudo kill -TERM {}".format(ping["pid"]),
            module_ignore_errors=True,
        )
    else:
        time.sleep(0.3)

    output = _read_ping_output(ping)
    summary = _parse_ping_output(output)["summary"]
    for _ in range(10):
        if summary:
            break
        time.sleep(0.2)
        output = _read_ping_output(ping)
        summary = _parse_ping_output(output)["summary"]
    assert summary, "Unable to parse ping summary:\n{}".format(output)
    ping["host"].shell(
        "rm -f {}".format(ping["path"]), module_ignore_errors=True)
    assert was_running, (
        "Continuous ping exited before the observation window closed: {}"
    ).format(ping)
    assert drain["drained"], (
        "Continuous ping did not drain after the transition; "
        "initial boundary={}, target boundary={}, ping={}"
    ).format(
        drain["initial_boundary"],
        drain["target_boundary"],
        ping,
    )
    assert not signal_result.get("failed"), (
        "Unable to stop continuous ping cleanly: {}"
    ).format(ping)
    assert exited, "Continuous ping did not exit after SIGINT: {}".format(
        ping)
    start_boundary = ping.get("start_boundary", 0)
    observation = _ping_observation_result(
        pre_stop_output, output, start_boundary=start_boundary)
    if assert_loss:
        assert not observation["errors"], (
            "Traffic loss detected during MACsec transition:\n{}\n"
            "Observation start/end: {}/{}\nMissing ICMP sequences: {}\n"
            "Final ping summary: {}"
        ).format(
            output,
            start_boundary,
            observation["boundary"],
            observation["missing_sequences"][:200],
            summary,
        )
    boundary = observation["boundary"]
    return {
        "transmitted": boundary - start_boundary if boundary is not None else 0,
        "received": (
            boundary - start_boundary - len(observation["missing_sequences"])
            if boundary is not None else 0),
        "loss_percent": (
            0.0 if boundary and not observation["missing_sequences"]
            else summary["loss_percent"]),
        "summary_transmitted": summary["transmitted"],
        "summary_received": summary["received"],
        "summary_loss_percent": summary["loss_percent"],
        "observation_start": start_boundary,
        "observation_boundary": boundary,
    }


def _abort_partial_ping(ping):
    """Stop an unobserved startup stream without requiring a ping summary."""
    host = ping["host"]
    pid = ping["pid"]
    try:
        signal = host.shell(
            "sudo kill -INT {}".format(pid), module_ignore_errors=True)
        exited = wait_until(
            15, 1, 0, lambda: not _ping_process_running(ping))
        if not exited:
            term = host.shell(
                "sudo kill -TERM {}".format(pid), module_ignore_errors=True)
            terminated = wait_until(
                5, 1, 0, lambda: not _ping_process_running(ping))
            assert not term.get("failed") and terminated, (
                "Unable to terminate partially started continuous ping")
        assert not signal.get("failed") and exited, (
            "Unable to stop partially started continuous ping")
    finally:
        host.shell("rm -f {}".format(ping["path"]),
                   module_ignore_errors=True)


def _probe_transit(endpoint):
    host, port, source, destination, _, _ = endpoint
    result = host.command(
        "{} ping -c 3 -I {} {}".format(
            _ping_namespace_prefix(host, port), source, destination),
        module_ignore_errors=True, verbose=False)
    output = "{}\n{}".format(
        result.get("stdout", ""), result.get("stderr", ""))
    rc = result.get("rc")
    if rc == 2 and re.search(r"\bping:.*Network is unreachable", output):
        return False
    summary = _parse_ping_output(output)["summary"]
    if (rc not in (0, 1) or not summary
            or result.get("stderr", "").strip()
            or (rc == 0 and result.get("failed"))
            or summary["transmitted"] != 3
            or not 0 <= summary["received"] <= 3
            or (rc == 0 and summary["received"] == 0)
            or (rc == 1 and summary["received"] == 3)):
        raise RuntimeError("Transit ping did not return a valid ICMP verdict on {}".format(
            host.hostname))
    return summary["received"] > 0


def _start_bidirectional_traffic(endpoints):
    assert _probe_transit(endpoints[0]), "Unable to warm first neighbor-to-neighbor transit path"
    assert _probe_transit(endpoints[1]), "Unable to warm reverse neighbor-to-neighbor transit path"
    traffic = []
    try:
        for index, (host, port, source, destination, _, _) in enumerate(endpoints):
            traffic.append(_start_ping(
                host, port, source, destination, "transit_{}".format(index)))

        for ping in traffic:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                assert _ping_process_running(ping), (
                    "Continuous transit ping exited before observation began")
                received = _parse_ping_output(
                    _read_ping_output(ping))["received_sequences"]
                if len(received) >= 10:
                    ping["start_boundary"] = max(received)
                    break
                time.sleep(0.2)
            else:
                raise AssertionError(
                    "Continuous transit ping did not establish a startup baseline")
    except BaseException:
        try:
            cleanup_all(traffic, _abort_partial_ping)
        except BaseException:
            logger.exception("Partial traffic startup cleanup failed")
        raise
    return traffic


def _selected_link_ping_results(environment, upstream_links, port):
    with _transit_path(environment, upstream_links, port) as endpoints:
        return tuple(_probe_transit(endpoint) for endpoint in endpoints)


def _selected_link_ping_succeeds(environment, upstream_links, port):
    return all(_selected_link_ping_results(
        environment, upstream_links, port))


def _wait_for_validated_state(timeout, interval, validator):
    """Wait for no validation errors, including one final boundary check."""
    attempts = []

    def _ready():
        errors = validator()
        attempts.append(errors)
        return not errors

    ready = wait_until(timeout, interval, 0, _ready)
    if not ready:
        ready = _ready()
    return ready, attempts[-1], attempts


def _macsecmgrd_process_ready(host, container):
    result = host.command(
        "docker exec {} supervisorctl status macsecmgrd".format(
            container),
        module_ignore_errors=True,
        verbose=False,
    )
    return (
        not result.get("failed")
        and "RUNNING" in result.get("stdout", "")
    )


def _ensure_macsecmgrd_running(host, container):
    if not _macsecmgrd_process_ready(host, container):
        host.command("docker exec {} supervisorctl start macsecmgrd".format(container))
    assert wait_until(60, 2, 0, _macsecmgrd_process_ready, host, container), \
        "macsecmgrd did not recover"


def _wait_bgp_recovered(host, neighbors):
    assert wait_until(
        MKA_CONVERGE_TIMEOUT, 10, 0, host.check_bgp_session_state_all_asics, neighbors), \
        "External BGP sessions did not recover"


def _wait_selected_traffic(environment, upstream_links, port):
    assert wait_until(
        MKA_CONVERGE_TIMEOUT, 3, 0, _selected_link_ping_succeeds, environment, upstream_links, port), \
        "Selected-link bidirectional traffic did not recover"


class _TrafficWindow(AbstractContextManager):
    """Guaranteed bidirectional traffic collection with exact-loss verdict."""

    def __init__(self, environment, upstream_links, port=None):
        self.environment = environment
        self.upstream_links = upstream_links
        self.port = port
        self.traffic = []
        self.results = None
        self.routes = None

    def __enter__(self):
        selected_port = self.port
        if selected_port is None:
            selected_port, _ = _select_routed_link(
                self.environment, self.upstream_links)
        self.routes = _transit_path(
            self.environment, self.upstream_links, selected_port)
        endpoints = self.routes.__enter__()
        try:
            self.traffic = _start_bidirectional_traffic(endpoints)
        except BaseException:
            self.routes.__exit__(*sys.exc_info())
            self.routes = None
            raise
        return self

    def close(self, assert_loss=True):
        if self.results is None:
            results = []
            try:
                cleanup_all(
                    self.traffic,
                    lambda ping: results.append(_stop_ping(ping, assert_loss=assert_loss)))
            finally:
                self.results = results
                self.traffic = []
                if self.routes is not None:
                    routes, self.routes = self.routes, None
                    routes.__exit__(*sys.exc_info())
        return self.results

    def assert_zero_loss(self):
        return self.close(assert_loss=True)

    def __exit__(self, exc_type, exc_value, traceback):
        if self.results is not None:
            return False
        try:
            self.close(assert_loss=exc_type is None)
        except BaseException:
            if exc_type is None:
                raise
            logger.exception("Traffic cleanup failed after scenario error")
        return False


@pytest.fixture(scope="module")
def fallback_macsec_environment(
        macsec_duthost, ctrl_links, macsec_profile, port_profiles,
        get_port_profile_name):
    """Verify the selected dual-CA profile without changing port bindings."""
    if port_profiles:
        pytest.skip(
            "Targeted rollover cases use one shared profile; the normal "
            "fallback profile still runs in the per-interface suite sweep")
    links = dict(ctrl_links)
    if not links:
        pytest.skip("Fallback CAK tests require a controlled MACsec link")
    if not mka_state_cli_supported(macsec_duthost):
        pytest.skip("SONiC image does not expose fallback CAK/MKA state CLI")

    neighbor_profiles = {
        port: get_port_profile_name(port)
        for port in links
    }
    profile = dict(macsec_profile)
    neighbor_priorities = {
        port: profile["priority"] + (1 if index % 2 else -1)
        for index, port in enumerate(links)
    }
    for port, neighbor in links.items():
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            lambda p=port, n=neighbor: (
                macsec_duthost.iface_macsec_ok(p)
                and n["host"].iface_macsec_ok(n["port"])
            ),
        ), "Dual-CA MKA did not converge on {}".format(port)

    environment = {
        "duthost": macsec_duthost,
        "links": links,
        "profile": profile,
        "neighbor_profiles": neighbor_profiles,
        "neighbor_priorities": neighbor_priorities,
        "peer_profiles": {
            port: dict(profile)
            for port in links
        },
    }
    assert wait_until(
        MKA_CONVERGE_TIMEOUT, 5, 0,
        _environment_is_healthy, environment,
    ), "Dual-CA MKA operational state did not become healthy"
    return environment


def test_fallback_operational_state_and_config(
        fallback_macsec_environment):
    """Verify dual-CA CONFIG_DB, STATE_DB, and protected SC/SA state."""
    environment = fallback_macsec_environment
    profile = environment["profile"]

    for port in environment["links"]:
        snapshot = _snapshot(environment, port)
        for field in (
                "primary_cak", "primary_ckn", "fallback_cak", "fallback_ckn"):
            if snapshot.profile_config[field].lower() != profile[field].lower():
                pytest.fail(
                    "Configured {} does not match the test profile".format(
                        field))

        assert not snapshot.protected_errors(profile, profile["primary_ckn"])
        state = {"session": snapshot.session, "participants": snapshot.participants}
        assert not find_secret_fields(state)
        serialized_state = json.dumps(state).lower()
        _assert_key_material_absent(serialized_state, profile)
        assert not peer_adapter(environment, port).protected_errors(
            environment["peer_profiles"][port], profile["primary_ckn"])


def test_ceos_primary_key_delete_fails_over_hitlessly(
        fallback_macsec_environment, upstream_links):
    """Fail over and recover after supported cEOS primary-key deletion."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    primary_pair = (profile["primary_cak"], profile["primary_ckn"])
    port, _ = _select_routed_link(environment, upstream_links)
    adapter = peer_adapter(environment, port)
    if not adapter.supports_primary_delete:
        pytest.skip(adapter.primary_delete_unsupported_reason)

    with _TrafficWindow(environment, upstream_links) as traffic:
        with FailureSafeCleanup("cEOS primary deletion") as cleanup:
            cleanup.callback(
                _restore_deleted_primary,
                environment, port, adapter, primary_pair)
            before = _snapshot(environment, port)
            adapter.delete_primary_if_supported(primary_pair)
            _wait_link_protected(
                environment, port, profile["fallback_ckn"],
                require_all_live=False)
            _wait_peer_primary_removed(adapter, profile)
            _wait_rotation_settled(
                environment, port, before, profile["fallback_ckn"], require_all_live=False)
        traffic.assert_zero_loss()


def test_principal_migration_preserves_counters(
        fallback_macsec_environment, upstream_links):
    """Check nondecreasing counters while migration still uses the inherited SAK."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    if profile["rekey_period"]:
        pytest.skip("Inherited-SAK counter sampling requires a non-periodic SONiC key server")
    candidates = [
        port for port in environment["links"]
        if peer_adapter(environment, port).supports_primary_delete
        and _snapshot(environment, port).session["is_key_server"] == "true"
    ]
    if not candidates:
        pytest.skip("Counter migration requires a cEOS link with SONiC as the elected key server")
    port, _ = _select_routed_link(environment, upstream_links, candidates)
    adapter = peer_adapter(environment, port)

    def _counters():
        egress, ingress = get_macsec_counters(environment["duthost"], port)
        fields = {
            "egress": ["SAI_MACSEC_SA_ATTR_CURRENT_XPN"],
            "ingress": ["SAI_MACSEC_SA_ATTR_CURRENT_XPN"],
        }
        if environment["duthost"].facts["asic_type"] != "vs":
            fields["egress"].append(
                "SAI_MACSEC_SA_STAT_OUT_PKTS_{}".format(
                    "ENCRYPTED" if profile["policy"] == "security" else "PROTECTED"))
            fields["ingress"].append("SAI_MACSEC_SA_STAT_IN_PKTS_OK")
        return {
            (direction, field): counters[field]
            for direction, counters in (("egress", egress), ("ingress", ingress))
            for field in fields[direction]
        }

    with _TrafficWindow(environment, upstream_links, port=port) as traffic:
        assert wait_until(60, 1, 0, lambda: all(value >= 10 for value in _counters().values())), \
            "Migration counter baseline did not receive traffic"
        _wait_rotation_settled(
            environment, port, _snapshot(environment, port), profile["primary_ckn"], require_rekey=False)
        before = _snapshot(environment, port)
        counters_before = _counters()
        with FailureSafeCleanup("migration counter sampling") as cleanup:
            cleanup.callback(
                _restore_deleted_primary, environment, port, adapter,
                (profile["primary_cak"], profile["primary_ckn"]))
            adapter.delete_primary_if_supported((profile["primary_cak"], profile["primary_ckn"]))
            observed = [None]

            def _migration_observed():
                observed[0] = _snapshot(environment, port)
                return (
                    observed[0].principal_ckns() == [profile["fallback_ckn"].lower()]
                    or observed[0].active_key_identity() != before.active_key_identity())

            assert wait_until(
                _protocol_timeout(environment, port, 4) + MKA_STATE_PUBLISH_TIMEOUT,
                1, 0, _migration_observed), "Fallback principal migration was not observed"
            if observed[0].active_key_identity() != before.active_key_identity():
                pytest.skip(
                    "Publication did not expose migration before deferred SAK rollover; counters not comparable")
            counters_after = _counters()
            if _snapshot(environment, port).active_key_identity() != before.active_key_identity():
                pytest.skip("SAK rolled during counter sampling; no no-reset verdict is possible")
            assert all(counters_after[field] >= value for field, value in counters_before.items()), \
                "Counters reset while principal migration retained the same SC/SA"
            _wait_rotation_settled(
                environment, port, before, profile["fallback_ckn"], require_all_live=False)
        traffic.assert_zero_loss()


def test_primary_rotation_is_hitless(
        fallback_macsec_environment, upstream_links):
    """Measure primary replacement without loss, then verify recovery."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    new_pair = generate_macsec_key_pair(profile["cipher_suite"])
    selected_port, _ = _select_routed_link(environment, upstream_links)

    with _rotated_cak(
            environment, "primary", new_pair, selected_port, upstream_links):
        pass


def test_fallback_rotation_keeps_primary_and_traffic(
        fallback_macsec_environment, upstream_links):
    """Rotate the fallback participant while primary carries traffic."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    new_pair = generate_macsec_key_pair(profile["cipher_suite"])
    selected_port, _ = _select_routed_link(environment, upstream_links)

    with _rotated_cak(
            environment, "fallback", new_pair, selected_port, upstream_links):
        pass


def test_crossed_roles_follow_key_server_primary(
        fallback_macsec_environment, upstream_links):
    """Verify crossed local roles follow the elected key server's primary."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    port, _ = _select_routed_link(environment, upstream_links)
    max_sa_per_sc = get_macsec_max_sa_per_sc(
        environment["duthost"], port)
    if not crossed_role_peer_key_server_supported(max_sa_per_sc):
        pytest.skip(
            "Crossed-role peer-key-server coverage requires "
            "max_sa_per_sc=4; {} reports {} and WPA forces DUT "
            "key-server priority for any other capability".format(
                port, max_sa_per_sc))
    peer_profile_name = environment["neighbor_profiles"][port]
    peer_priority = max(0, profile["priority"] - 1)
    crossed_profile = dict(profile)
    crossed_profile.update({
        "primary_cak": profile["fallback_cak"],
        "primary_ckn": profile["fallback_ckn"],
        "fallback_cak": profile["primary_cak"],
        "fallback_ckn": profile["primary_ckn"],
    })
    adapter = peer_adapter(environment, port)

    try:
        adapter.replace_profile(
            peer_profile_name, crossed_profile, peer_priority)
        before = _snapshot(environment, port)
        _wait_link_protected(
            environment, port, profile["fallback_ckn"])
        _wait_peer_protected(
            adapter, crossed_profile, profile["fallback_ckn"])
        with _TrafficWindow(environment, upstream_links) as traffic:
            _wait_rotation_settled(
                environment, port, before, profile["fallback_ckn"], require_rekey=None)
            traffic.assert_zero_loss()
    finally:
        adapter.replace_profile(
            peer_profile_name, profile,
            environment["neighbor_priorities"][port])
        _wait_environment(environment, profile["primary_ckn"])


def test_primary_mismatch_fallback_takeover_and_recovery_is_hitless(
        fallback_macsec_environment, upstream_links):
    """Fail over to fallback after primary mismatch without traffic loss."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    port, _ = _select_routed_link(environment, upstream_links)
    invalid_pair = generate_macsec_key_pair(
        profile["cipher_suite"])

    with _TrafficWindow(environment, upstream_links) as traffic:
        with _primary_mismatch(environment, port, invalid_pair):
            pass
        traffic.assert_zero_loss()


@pytest.mark.stress_test
def test_cak_rotation_at_periodic_rekey_boundary(
        fallback_macsec_environment, upstream_links):
    """Rotate CAK immediately after observing a periodic SAK boundary."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    if profile["name"] != FALLBACK_PROFILE:
        pytest.skip("Boundary stress runs only on the static fallback profile")

    original_period = profile["rekey_period"]
    new_pair = generate_macsec_key_pair(profile["cipher_suite"])

    with FailureSafeCleanup("periodic CAK rotation") as cleanup:
        cleanup.callback(
            _restore_rekey_period, environment, original_period)
        _configure_environment_rekey_period(environment, 30)
        profile["rekey_period"] = 30
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "MKA did not converge with the short rekey period"

        port, _ = _select_routed_link(environment, upstream_links)
        assert _selected_link_ping_succeeds(
            environment, upstream_links, port), (
                "Transit path was not healthy before periodic rekey")
        before = _snapshot(environment, port).active_key_identity()
        assert wait_until(
            90, 2, 0,
            lambda: _snapshot(
                environment, port).active_key_identity() != before,
        ), "No periodic SAK rekey was observed"

        with _rotated_cak(environment, "primary", new_pair, port, upstream_links):
            pass


@pytest.mark.stress_test
def test_back_to_back_cak_rotation_stress(
        fallback_macsec_environment, upstream_links):
    """Measure each forward replacement, restoring between rotations."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    if profile["name"] != FALLBACK_PROFILE:
        pytest.skip("Rotation stress runs only on the static fallback profile")

    port, _ = _select_routed_link(environment, upstream_links)
    for iteration in range(STRESS_ROTATIONS):
        role = "fallback" if iteration % 2 else "primary"
        new_pair = generate_macsec_key_pair(profile["cipher_suite"])
        with _rotated_cak(environment, role, new_pair, port, upstream_links):
            pass


def test_profile_update_validation_and_unattached_update(
        fallback_macsec_environment):
    """Verify paired fallback validation and unattached-profile rotation."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    port = next(iter(environment["links"]))
    namespace = get_namespace_option(duthost, port)
    temp_name = "{}_UNATTACHED".format(FALLBACK_PROFILE)
    primary_cak, primary_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    fallback_cak, fallback_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    base_options = (
        "--priority {priority} --cipher_suite {cipher_suite} "
        "--primary_cak {primary_cak} --primary_ckn {primary_ckn} "
        "--policy {policy} --send_sci "
    ).format(
        priority=profile["priority"],
        cipher_suite=profile["cipher_suite"],
        primary_cak=primary_cak,
        primary_ckn=primary_ckn,
        policy=profile["policy"],
    )

    delete_macsec_profile(duthost, temp_name, namespace_option=namespace)
    with FailureSafeCleanup("unattached profile validation") as cleanup:
        cleanup.callback(delete_macsec_profile, duthost, temp_name, namespace_option=namespace)
        invalid_ckn_options = base_options.replace(
            "--primary_ckn {}".format(primary_ckn),
            "--primary_ckn not-hex",
        )
        invalid_ckn = duthost.command(
            "config macsec {} profile add {} {}".format(
                namespace, temp_name, invalid_ckn_options),
            module_ignore_errors=True,
        )
        assert invalid_ckn["failed"]
        assert not get_macsec_profile_config(
            duthost, port, temp_name)

        for field, value in (("fallback_cak", fallback_cak), ("fallback_ckn", fallback_ckn)):
            half_fallback = duthost.command(
                "config macsec {} profile add {} {} --{} {}".format(
                    namespace, temp_name, base_options, field, value),
                module_ignore_errors=True)
            assert half_fallback["failed"]
            assert not get_macsec_profile_config(duthost, port, temp_name)

        duplicate_ckn = duthost.command(
            "config macsec {} profile add {} {} "
            "--fallback_cak {} --fallback_ckn {}".format(
                namespace, temp_name, base_options,
                fallback_cak, primary_ckn),
            module_ignore_errors=True,
        )
        assert duplicate_ckn["failed"]
        assert not get_macsec_profile_config(
            duthost, port, temp_name)

        invalid_fallback_cak = duthost.command(
            "config macsec {} profile add {} {} "
            "--fallback_cak 00 --fallback_ckn {}".format(
                namespace, temp_name, base_options, fallback_ckn),
            module_ignore_errors=True,
        )
        assert invalid_fallback_cak["failed"]
        assert not get_macsec_profile_config(
            duthost, port, temp_name)

        valid_profile = dict(profile)
        valid_profile.update({
            "name": temp_name,
            "primary_cak": primary_cak,
            "primary_ckn": primary_ckn,
            "fallback_cak": fallback_cak,
            "fallback_ckn": fallback_ckn,
        })
        _set_profile(duthost, temp_name, valid_profile, namespace_option=namespace)
        original = get_macsec_profile_config(duthost, port, temp_name)
        new_cak, new_ckn = generate_macsec_key_pair(
            profile["cipher_suite"])
        _profile_update(
            duthost, temp_name, primary_cak, primary_ckn, new_cak, new_ckn,
            namespace_option=namespace)
        config = get_macsec_profile_config(duthost, port, temp_name)
        expected = dict(original, primary_cak=new_cak, primary_ckn=new_ckn)
        _assert_profile_unchanged(expected, config, "Unattached profile replacement")

        before = dict(config)
        _profile_update(
            duthost, temp_name, new_cak, new_ckn, new_cak, new_ckn,
            namespace_option=namespace, expect_success=False)
        _profile_update(
            duthost, temp_name, "", "00" * (len(new_ckn) // 2),
            new_cak, primary_ckn,
            namespace_option=namespace, expect_success=False)
        _profile_update(
            duthost, temp_name, new_cak, new_ckn,
            fallback_cak, fallback_ckn,
            namespace_option=namespace, expect_success=False)
        for invalid_cak, invalid_ckn in (("00", primary_ckn), (new_cak, "not-hex")):
            _profile_update(
                duthost, temp_name, new_cak, new_ckn, invalid_cak, invalid_ckn,
                namespace_option=namespace, expect_success=False)
        _assert_profile_unchanged(
            before,
            get_macsec_profile_config(duthost, port, temp_name),
            "Rejected unattached-profile update",
        )

        delete_macsec_profile(duthost, temp_name, namespace_option=namespace)
        primary_only = dict(valid_profile)
        primary_only.pop("fallback_cak")
        primary_only.pop("fallback_ckn")
        _set_profile(duthost, temp_name, primary_only, namespace_option=namespace)
        before = get_macsec_profile_config(duthost, port, temp_name)
        _profile_update(
            duthost, temp_name, primary_cak, primary_ckn, new_cak, new_ckn,
            namespace_option=namespace, expect_success=False)
        _assert_profile_unchanged(
            before,
            get_macsec_profile_config(duthost, port, temp_name),
            "Rejected primary-only profile update",
        )


def test_multi_port_desired_update_defers_only_unsafe_port(
        fallback_macsec_environment):
    """Accept desired state, isolate unsafe applied state, then reconcile."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    ports_by_namespace = {}
    for port in environment["links"]:
        ports_by_namespace.setdefault(
            get_namespace_option(duthost, port), []).append(port)
    ports = next(
        (items for items in ports_by_namespace.values() if len(items) >= 2),
        None,
    )
    if ports is None:
        pytest.skip(
            "Independent reconciliation requires two ports in one namespace")

    peer_scopes = {
        port: peer_adapter(environment, port).scope
        for port in ports
    }
    pair = select_independent_port_pair(ports, peer_scopes)
    if pair is None:
        pytest.skip(
            "Independent reconciliation requires independently scoped "
            "peer profiles")
    unsafe_port, safe_port = pair

    old_pair = (profile["fallback_cak"], profile["fallback_ckn"])
    mismatched_pair = generate_macsec_key_pair(
        profile["cipher_suite"])
    replacement_pair = generate_macsec_key_pair(profile["cipher_suite"])
    replacement_cak, replacement_ckn = replacement_pair
    namespace = get_namespace_option(duthost, unsafe_port)
    adapter = peer_adapter(environment, unsafe_port)
    safe_adapter = peer_adapter(environment, safe_port)
    original_unsafe_peer = dict(environment["peer_profiles"][unsafe_port])
    original_safe_peer = dict(environment["peer_profiles"][safe_port])
    desired = dict(profile, primary_cak=replacement_cak, primary_ckn=replacement_ckn)
    original_primary = (profile["primary_cak"], profile["primary_ckn"])

    with FailureSafeCleanup("multi-port desired reconciliation") as cleanup:
        cleanup.callback(_wait_environment, environment, profile["primary_ckn"])
        cleanup.callback(
            _restore_peer_step, environment, unsafe_port, "fallback",
            original_unsafe_peer, mismatched_pair)
        adapter.rotate("fallback", old_pair, mismatched_pair)

        def _precondition_errors():
            peer_states = {
                port: peer_adapter(
                    environment, port).normalized_state()
                for port in (unsafe_port, safe_port)
            }
            participants_by_port = {
                port: get_mka_state(duthost, port)[1]
                for port in ports
            }
            peer_participants_by_port = {
                port: state["participants"]
                for port, state in peer_states.items()
            }
            peer_configured_ckns_by_port = {
                port: state["configured_ckns"]
                for port, state in peer_states.items()
            }
            return validate_multi_port_alternate_state(
                participants_by_port,
                old_pair[1],
                unsafe_port,
                [safe_port],
                peer_participants_by_port,
                peer_configured_ckns_by_port,
            )

        ready, errors, attempts = _wait_for_validated_state(
            _protocol_timeout(environment, unsafe_port, 4) + MKA_STATE_PUBLISH_TIMEOUT,
            1,
            _precondition_errors,
        )
        assert ready, (
            "Multi-port preconditions failed after {} evaluations: "
            "attempt_errors={}, final_errors={}, unsafe={}, safe={}"
        ).format(
            len(attempts),
            attempts,
            errors,
            _diagnostics(environment, unsafe_port),
            _diagnostics(environment, safe_port),
        )

        before = _snapshot(environment, unsafe_port)
        assert not before.protected_errors(
            profile, profile["primary_ckn"], require_all_live=False)
        assert int(before.participants[profile["primary_ckn"].lower()]["live_peers"]) > 0, \
            "Unsafe port must retain a live primary peer, not qualify as peerless"
        assert not _snapshot(environment, safe_port).protected_errors(
            profile, profile["primary_ckn"])
        cleanup.callback(
            restore_macsec_profile_key, duthost, profile["name"],
            original_primary[0], original_primary[1],
            replacement_cak, replacement_ckn,
            namespace_options=[namespace])
        _profile_update(
            duthost, profile["name"], original_primary[0], original_primary[1],
            replacement_cak, replacement_ckn, namespace_option=namespace)
        _assert_profile_unchanged(
            dict(before.profile_config, primary_cak=replacement_cak,
                 primary_ckn=replacement_ckn),
            get_macsec_profile_config(duthost, unsafe_port, profile["name"]),
            "Accepted desired profile update",
        )

        def _deferred():
            current = _snapshot(environment, unsafe_port)
            session = current.session
            primary = current.participants.get(original_primary[1].lower(), {})
            fallback = current.participants.get(profile["fallback_ckn"].lower(), {})
            return (
                session.get("query_status") == "ok"
                and session.get("config_status") == "degraded"
                and bool(session.get("config_error"))
                and session.get("secured") == "true"
                and session.get("failed") == "false"
                and parse_mka_timestamp(session["last_updated"])
                > parse_mka_timestamp(before.session["last_updated"])
                and set(current.participants) == {
                    profile["primary_ckn"].lower(), profile["fallback_ckn"].lower()}
                and primary.get("is_primary") == "true"
                and primary.get("is_principal") == "true"
                and primary.get("active") == "true"
                and primary.get("mi") == before.participants[
                    original_primary[1].lower()].get("mi")
                and int(primary.get("live_peers", "0")) > 0
                and fallback.get("is_primary") == "false"
                and fallback.get("active") == "true"
                and current.appl_port.get("enable") == "true"
                and (profile["rekey_period"] or
                     current.active_key_identity() == before.active_key_identity())
            )

        assert wait_until(
            MKA_STATE_PUBLISH_TIMEOUT, 2, 0, _deferred), \
            "Unsafe peer-present port lost applied primary or degraded state"
        assert wait_until(
            _protocol_timeout(environment, safe_port, 4) + MKA_STATE_PUBLISH_TIMEOUT,
            2, 0,
            lambda: not _snapshot(environment, safe_port).protected_errors(
                desired, profile["fallback_ckn"], require_all_live=False)), \
            "Safe sibling did not independently apply the desired primary"
        assert _deferred(), "Safe sibling progress changed the unsafe applied participant"

        cleanup.callback(
            _restore_peer_step, environment, safe_port, "primary",
            original_safe_peer, replacement_pair)
        safe_adapter.rotate("primary", original_primary, replacement_pair)
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 2, 0,
            lambda: (
                not _snapshot(environment, safe_port).protected_errors(
                    desired, replacement_ckn)
                and not safe_adapter.protected_errors(
                    environment["peer_profiles"][safe_port], replacement_ckn)
            )), "Safe sibling did not establish the accepted primary"

        _restore_peer_step(
            environment, unsafe_port, "fallback",
            original_unsafe_peer, mismatched_pair)
        cleanup.callback(
            _restore_peer_step, environment, unsafe_port, "primary",
            original_unsafe_peer, replacement_pair)
        adapter.rotate("primary", original_primary, replacement_pair)
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 2, 0,
            lambda: (
                not _snapshot(environment, unsafe_port).protected_errors(
                    desired, replacement_ckn)
                and not adapter.protected_errors(
                    environment["peer_profiles"][unsafe_port], replacement_ckn)
            )), "Pending unsafe port did not apply accepted desired state"
        _assert_profile_unchanged(
            dict(before.profile_config, primary_cak=replacement_cak,
                 primary_ckn=replacement_ckn),
            get_macsec_profile_config(duthost, unsafe_port, profile["name"]),
            "Desired profile during pending recovery",
        )


def _macsecmgrd_restart_known_failure(duthost, tbinfo):
    """Return whether this physical testbed has the known rebuild defect."""
    return (
        tbinfo.get("conf-name") == "vms26-t2-7800-1"
        and duthost.facts.get("asic_type") != "vs"
    )


def test_disable_deletes_mka_state(fallback_macsec_environment):
    """Delete both MKA tables on explicit disable and republish on enable."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    selected_port = next(iter(environment["links"]))

    with FailureSafeCleanup("MACsec explicit disable") as cleanup:
        cleanup.callback(_wait_environment, environment, profile["primary_ckn"])
        cleanup.callback(enable_macsec_port, duthost, selected_port, profile["name"])
        disable_macsec_port(duthost, selected_port)
        assert wait_until(
            MKA_TIMEOUT, 2, 0,
            lambda: get_mka_state(duthost, selected_port) == ({}, {}),
        ), "MKA operational rows remained after explicit port disable"


def test_macsecmgrd_restart_revalidates_without_loss(
        fallback_macsec_environment, upstream_links, tbinfo):
    """Revalidate all affected rows without replacing WPA sessions or dropping traffic."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    if _macsecmgrd_restart_known_failure(duthost, tbinfo):
        pytest.skip(
            "Known macsecmgrd reconstruction failure on physical "
            "vms26-t2-7800-1; explicit-disable coverage remains enabled")
    profile = environment["profile"]
    selected_port, _ = _select_routed_link(environment, upstream_links)
    asic = duthost.get_port_asic_instance(selected_port)
    container = asic.get_docker_name("macsec")
    affected_ports = [
        candidate for candidate in environment["links"]
        if duthost.get_port_asic_instance(
            candidate).get_docker_name("macsec") == container
    ]
    old_pids = duthost.command(
        "docker exec {} pgrep -x macsecmgrd".format(container)
    ).get("stdout_lines", [])
    old_wpa_pids = duthost.command(
        "docker exec {} pgrep -x wpa_supplicant".format(container))["stdout_lines"]
    before = {port: _snapshot(environment, port) for port in affected_ports}
    markers = {"dut": {port: snapshot.session["last_updated"] for port, snapshot in before.items()}, "peers": {}}
    bgp_neighbors = duthost.get_bgp_neighbors_per_asic(state="all")
    with FailureSafeCleanup("macsecmgrd restart recovery") as cleanup:
        cleanup.callback(_wait_bgp_recovered, duthost, bgp_neighbors)
        cleanup.callback(_wait_selected_traffic, environment, upstream_links, selected_port)
        cleanup.callback(
            _wait_restored_environment_published, environment, markers,
            profile["primary_ckn"], "restart cleanup")
        cleanup.callback(_reapply_macsec_ports, environment, affected_ports)
        cleanup.callback(_ensure_macsecmgrd_running, duthost, container)
        with _TrafficWindow(environment, upstream_links) as traffic:
            duthost.command("docker exec {} supervisorctl restart macsecmgrd".format(container))

            def _restart_ready():
                status = duthost.command(
                    "docker exec {} supervisorctl status macsecmgrd".format(container),
                    module_ignore_errors=True).get("stdout", "")
                new_pids = duthost.command(
                    "docker exec {} pgrep -x macsecmgrd".format(container),
                    module_ignore_errors=True).get("stdout_lines", [])
                return macsecmgrd_restart_ready(old_pids, new_pids, status)

            assert wait_until(60, 2, 0, _restart_ready), \
                "macsecmgrd did not restart with a new RUNNING process"
            _wait_restored_environment_published(
                environment, markers, profile["primary_ckn"], "macsecmgrd restart")
            assert set(duthost.command(
                "docker exec {} pgrep -x wpa_supplicant".format(container))["stdout_lines"]) == set(old_wpa_pids), \
                "Manager restart replaced existing WPA sessions"
            if profile["rekey_period"] == 0:
                for port, snapshot in before.items():
                    assert _snapshot(environment, port).active_key_identity() == snapshot.active_key_identity(), \
                        "Manager restart changed the installed SAK on {}".format(port)
            traffic.assert_zero_loss()
        cleanup.dismiss()


def test_both_invalid_tears_down_and_matching_profile_recovers(
        fallback_macsec_environment, upstream_links):
    """Lose both shared CAKs through supported peer configuration."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    port, _ = _select_routed_link(
        environment, upstream_links)
    adapter = peer_adapter(environment, port)
    invalid_primary_cak, invalid_primary_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    invalid_fallback_cak, invalid_fallback_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    original_profile_name = environment["neighbor_profiles"][port]
    original_peer_profile = dict(environment["peer_profiles"][port])
    invalid_primary = (invalid_primary_cak, invalid_primary_ckn)
    invalid_fallback = (invalid_fallback_cak, invalid_fallback_ckn)

    with _transit_path(
            environment, upstream_links, port, stable_endpoints=True) as endpoints:
        healthy_results = tuple(_probe_transit(endpoint) for endpoint in endpoints)
        assert all(healthy_results), (
            "Neighbor-to-neighbor transit path was not healthy before invalidating both CAKs: "
            "selected_to_other={}, other_to_selected={}".format(*healthy_results))

        if adapter.provider == "ceos":
            with _primary_mismatch(environment, port, invalid_primary):
                with _ceos_fallback_mismatch(
                        environment, port, adapter, invalid_fallback):
                    traffic_results = tuple(
                        _probe_transit(endpoint) for endpoint in endpoints)
                    assert not any(traffic_results), (
                        "Traffic still forwarded with both CAKs mismatched: "
                        "selected_to_other={}, other_to_selected={}"
                    ).format(*traffic_results)
        else:
            dut_last_updated = _snapshot(
                environment, port).session.get("last_updated")
            peer_last_updated = adapter.publication_marker()
            temp_profile_name = "MKA_BOTH_INVALID_{}".format(
                adapter.peer_port)
            both_invalid_profile = dict(original_peer_profile)
            both_invalid_profile.update({
                "name": temp_profile_name,
                "primary_cak": invalid_primary_cak,
                "primary_ckn": invalid_primary_ckn,
                "fallback_cak": invalid_fallback_cak,
                "fallback_ckn": invalid_fallback_ckn,
            })

            def _delete_temporary_profile():
                attachment = adapter.host.command(
                    "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' macsec".format(
                        adapter.namespace_option, adapter.peer_port),
                    module_ignore_errors=True, verbose=False)
                if attachment.get("failed") or attachment.get("rc", 0) != 0:
                    raise RuntimeError("Unable to verify original peer profile binding")
                assert attachment.get("stdout", "").strip() == original_profile_name, (
                    "Peer binding was not restored; retaining temporary MACsec profile")
                delete_macsec_profile(
                    adapter.host, temp_profile_name,
                    namespace_option=adapter.namespace_option)
                assert not get_macsec_profile_config(
                    adapter.host, adapter.peer_port, temp_profile_name), (
                        "Temporary MACsec profile was not removed")

            with FailureSafeCleanup("both-invalid peer profile") as cleanup:
                cleanup.callback(_delete_temporary_profile)
                adapter.create_profile(temp_profile_name, both_invalid_profile)
                cleanup.callback(
                    adapter.rebind, original_profile_name, original_peer_profile)
                adapter.rebind(temp_profile_name, both_invalid_profile)

                _wait_link_blocked(
                    environment, port,
                    (profile["primary_ckn"], profile["fallback_ckn"]),
                    previous_last_updated=dut_last_updated)
                _wait_peer_blocked(
                    adapter, (invalid_primary_ckn, invalid_fallback_ckn),
                    previous_last_updated=peer_last_updated)
                traffic_results = tuple(
                    _probe_transit(endpoint) for endpoint in endpoints)
                assert not any(traffic_results), (
                    "Traffic still forwarded with both CAKs mismatched: "
                    "selected_to_other={}, other_to_selected={}"
                ).format(*traffic_results)

        _wait_link_protected(
            environment, port, profile["primary_ckn"])
        _wait_peer_protected(
            adapter, original_peer_profile,
            original_peer_profile["primary_ckn"])
        recovery_results = tuple(_probe_transit(endpoint) for endpoint in endpoints)
        assert all(recovery_results), (
            "Neighbor-to-neighbor transit traffic did not recover "
            "after restoring a matching profile: "
            "selected_to_other={}, other_to_selected={}".format(*recovery_results))
