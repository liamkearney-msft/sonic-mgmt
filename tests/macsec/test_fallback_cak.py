import json
import logging
import re
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
    select_independent_port_pair,
    validate_multi_port_alternate_state,
    parse_mka_timestamp,
)
from tests.common.utilities import ping_ip, wait_until


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
        require_all_live=True, check_peers=False, published=None):
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
def _rotated_cak(environment, role, new_pair, selected_port):
    """Replace one role per configuration scope and observe both directions of restoration."""
    profile = environment["profile"]
    original_profile = dict(profile)
    old_pair = (profile["{}_cak".format(role)], profile["{}_ckn".format(role)])
    peer_originals = {port: dict(value) for port, value in environment["peer_profiles"].items()}
    before = _snapshots(environment, environment["links"])
    attempted = []
    completed = [False]
    with FailureSafeCleanup("{} rotation".format(role)) as cleanup:
        cleanup.callback(
            _restore_rotation, environment, role, original_profile,
            peer_originals, new_pair, attempted, completed)
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
        _wait_rotations_settled(
            environment, before, profile["primary_ckn"],
            require_rekey=True if role == "primary" else (
                False if profile["rekey_period"] == 0 else None),
            check_peers=True)
        completed[0] = True
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
    for port in environment["links"] if ports is None else ports:
        neighbor = environment["links"][port]
        portchannel = find_portchannel_from_member(port, portchannels)
        if port in upstream_links and (not portchannel or len(portchannel["members"]) == 1):
            return port, neighbor
    pytest.skip("Exact per-link traffic observation requires a direct or single-member controlled routed link")


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


def _start_ping(host, port, destination, suffix):
    path = "/tmp/macsec_fallback_{}_{}.log".format(port, suffix)
    host.shell("rm -f {}".format(path), module_ignore_errors=True)
    prefix = _ping_namespace_prefix(host, port)
    command = "{} ping -D -i 0.1 {}".format(prefix, destination)
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


def _ping_observation_result(pre_stop_output, final_output):
    """Measure loss only through the last reply seen before shutdown."""
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
        set(range(1, boundary + 1)) - received_by_exit)
    errors = []
    if boundary < 10:
        errors.append(
            "traffic sample ended at sequence {}, expected at least 10"
            .format(boundary))
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
    observation = _ping_observation_result(pre_stop_output, output)
    if assert_loss:
        assert not observation["errors"], (
            "Traffic loss detected during MACsec transition:\n{}\n"
            "Observation boundary: {}\nMissing ICMP sequences: {}\n"
            "Final ping summary: {}"
        ).format(
            output,
            observation["boundary"],
            observation["missing_sequences"][:200],
            summary,
        )
    boundary = observation["boundary"]
    return {
        "transmitted": boundary,
        "received": (
            boundary - len(observation["missing_sequences"])
            if boundary is not None else 0),
        "loss_percent": (
            0.0 if boundary and not observation["missing_sequences"]
            else summary["loss_percent"]),
        "summary_transmitted": summary["transmitted"],
        "summary_received": summary["received"],
        "summary_loss_percent": summary["loss_percent"],
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


def _start_bidirectional_traffic(environment, upstream_links, port=None):
    duthost = environment["duthost"]
    port, neighbor = _select_routed_link(
        environment, upstream_links, [port] if port is not None else None)
    link = upstream_links[port]
    assert ping_ip(
        duthost, link["local_ipv4_addr"], count=3,
        cmd_prefix=_ping_namespace_prefix(duthost, port),
    ), "Unable to warm the DUT-to-neighbor traffic path"
    assert ping_ip(
        neighbor["host"], link["peer_ipv4_addr"], count=3,
        cmd_prefix=_ping_namespace_prefix(
            neighbor["host"], neighbor["port"]),
    ), "Unable to warm the neighbor-to-DUT traffic path"
    traffic = []
    try:
        traffic.append(_start_ping(
            duthost, port, link["local_ipv4_addr"], "dut_to_neighbor"))
        traffic.append(_start_ping(
            neighbor["host"], neighbor["port"],
            link["peer_ipv4_addr"], "neighbor_to_dut"))
    except BaseException:
        try:
            cleanup_all(traffic, _abort_partial_ping)
        except BaseException:
            logger.exception("Partial traffic startup cleanup failed")
        raise
    return traffic


def _selected_link_ping_results(environment, upstream_links, port):
    duthost = environment["duthost"]
    neighbor = environment["links"][port]
    link = upstream_links[port]
    return (
        ping_ip(
            duthost, link["local_ipv4_addr"], count=3,
            cmd_prefix=_ping_namespace_prefix(duthost, port)),
        ping_ip(
            neighbor["host"], link["peer_ipv4_addr"], count=3,
            cmd_prefix=_ping_namespace_prefix(
                neighbor["host"], neighbor["port"])),
    )


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

    def __enter__(self):
        self.traffic = _start_bidirectional_traffic(
            self.environment, self.upstream_links, self.port)
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


def test_primary_rotation_and_recovery_are_hitless(
        fallback_macsec_environment, upstream_links):
    """Rotate the primary CAK through supported config without traffic loss."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    new_pair = generate_macsec_key_pair(profile["cipher_suite"])
    selected_port, _ = _select_routed_link(environment, upstream_links)

    with _TrafficWindow(environment, upstream_links) as traffic:
        with _rotated_cak(environment, "primary", new_pair, selected_port):
            pass
        traffic.assert_zero_loss()


def test_fallback_rotation_keeps_primary_and_traffic(
        fallback_macsec_environment, upstream_links):
    """Rotate the fallback participant while primary carries traffic."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    new_pair = generate_macsec_key_pair(profile["cipher_suite"])
    selected_port, _ = _select_routed_link(environment, upstream_links)

    with _TrafficWindow(environment, upstream_links) as traffic:
        with _rotated_cak(environment, "fallback", new_pair, selected_port):
            pass
        traffic.assert_zero_loss()


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

        with _TrafficWindow(environment, upstream_links) as traffic:
            port, _ = _select_routed_link(environment, upstream_links)
            before = _snapshot(environment, port).active_key_identity()
            assert wait_until(
                90, 2, 0,
                lambda: _snapshot(
                    environment, port).active_key_identity() != before,
            ), "No periodic SAK rekey was observed"

            with _rotated_cak(environment, "primary", new_pair, port):
                pass
            traffic.assert_zero_loss()


@pytest.mark.stress_test
def test_back_to_back_cak_rotation_stress(
        fallback_macsec_environment, upstream_links):
    """Alternate bounded replacements and restorations without traffic loss."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    if profile["name"] != FALLBACK_PROFILE:
        pytest.skip("Rotation stress runs only on the static fallback profile")

    with _TrafficWindow(environment, upstream_links) as traffic:
        port, _ = _select_routed_link(environment, upstream_links)
        for iteration in range(STRESS_ROTATIONS):
            role = "fallback" if iteration % 2 else "primary"
            new_pair = generate_macsec_key_pair(profile["cipher_suite"])
            with _rotated_cak(environment, role, new_pair, port):
                pass
        traffic.assert_zero_loss()


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
    temp_profile_name = None
    invalid_primary = (invalid_primary_cak, invalid_primary_ckn)
    invalid_fallback = (invalid_fallback_cak, invalid_fallback_ckn)
    if adapter.provider == "ceos":
        with _primary_mismatch(environment, port, invalid_primary):
            with _ceos_fallback_mismatch(
                    environment, port, adapter, invalid_fallback):
                traffic_results = _selected_link_ping_results(
                    environment, upstream_links, port)
                assert not any(traffic_results), (
                    "Traffic still forwarded with both CAKs mismatched: "
                    "dut_to_peer={}, peer_to_dut={}"
                ).format(*traffic_results)
    else:
        dut_last_updated = _snapshot(
            environment, port).session.get("last_updated")
        peer_last_updated = adapter.publication_marker()
        try:
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
            adapter.create_profile(temp_profile_name, both_invalid_profile)
            adapter.rebind(temp_profile_name, both_invalid_profile)

            _wait_link_blocked(
                environment, port,
                (profile["primary_ckn"], profile["fallback_ckn"]),
                previous_last_updated=dut_last_updated)
            _wait_peer_blocked(
                adapter, (invalid_primary_ckn, invalid_fallback_ckn),
                previous_last_updated=peer_last_updated)
            traffic_results = _selected_link_ping_results(
                environment, upstream_links, port)
            assert not any(traffic_results), (
                "Traffic still forwarded with both CAKs mismatched: "
                "dut_to_peer={}, peer_to_dut={}"
            ).format(*traffic_results)

            adapter.rebind(original_profile_name, original_peer_profile)
            delete_macsec_profile(adapter.host, temp_profile_name)
            temp_profile_name = None
        finally:
            if temp_profile_name:
                adapter.rebind(
                    original_profile_name, original_peer_profile)
                delete_macsec_profile(adapter.host, temp_profile_name)

    _wait_link_protected(
        environment, port, profile["primary_ckn"])
    _wait_peer_protected(
        adapter, original_peer_profile,
        original_peer_profile["primary_ckn"])
    assert _selected_link_ping_succeeds(
        environment, upstream_links, port), \
        "Traffic did not recover after restoring a matching profile"
