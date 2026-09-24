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
    read_link_snapshot,
)
from tests.common.macsec.macsec_config_helper import (
    delete_macsec_profile,
    disable_macsec_port,
    enable_macsec_port,
    ensure_macsec_profile_fallback,
    generate_macsec_key_pair,
    macsec_profile_has_fallback,
    set_macsec_profile,
    update_macsec_profile_key,
)
from tests.common.macsec.macsec_helper import (
    get_appl_db,
    get_ipnetns_prefix,
)
from tests.common.macsec.mka_state_helper import (
    cleanup_all,
    crossed_role_peer_key_server_supported,
    find_secret_fields,
    get_macsec_ingress_sc_state,
    get_macsec_max_sa_per_sc,
    get_macsec_profile_config,
    get_mka_state,
    get_namespace_option,
    macsecmgrd_restart_command,
    macsecmgrd_restart_ready,
    mka_hello_timeout_seconds,
    mka_state_cli_supported,
    parse_eos_mka_participants,
    remaining_link_items,
    select_independent_port_pair,
    validate_lifecycle_cleanup_state,
    validate_multi_port_alternate_state,
    validate_eos_mka_participants,
    validate_point_to_point_ingress_sc,
    validate_mka_snapshot,
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


def _profile_kwargs(profile, priority=None):
    return {
        "priority": profile["priority"] if priority is None else priority,
        "cipher_suite": profile["cipher_suite"],
        "primary_cak": profile["primary_cak"],
        "primary_ckn": profile["primary_ckn"],
        "policy": profile["policy"],
        "send_sci": profile["send_sci"],
        "rekey_period": profile["rekey_period"],
        "fallback_cak": profile["fallback_cak"],
        "fallback_ckn": profile["fallback_ckn"],
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


def _set_profile(host, name, profile, priority=None):
    set_macsec_profile(
        host, name, **_profile_kwargs(profile, priority=priority))


def _profile_update(
        host, profile_name, old_cak, old_ckn, new_cak, new_ckn,
        is_fallback=False, namespace_option=None, expect_success=True):
    return update_macsec_profile_key(
        host, profile_name, old_cak, old_ckn, new_cak, new_ckn,
        is_fallback=is_fallback, namespace_option=namespace_option,
        expect_success=expect_success)


def _get_eos_participant_output(host, port):
    result = host.eos_command(
        commands=[
            "show mac security participants {} detail | json".format(port)
        ])
    output = result.get("stdout", [{}])[0]
    if not isinstance(output, dict):
        return {}
    return output


def _protocol_timeout(environment, port, intervals):
    session, _ = get_mka_state(environment["duthost"], port)
    return mka_hello_timeout_seconds(session, intervals)


def _snapshot(environment, port):
    return read_link_snapshot(
        environment["duthost"],
        port,
        environment["links"][port],
        environment["profile"]["name"],
    )


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
    for port in environment["links"]:
        _wait_link_protected(
            environment, port, principal_ckn, timeout=timeout)


def _capture_environment_last_updated(
        environment, dut_ports=(), peer_ports=()):
    snapshots = {"dut": {}, "peers": {}}
    for port in dut_ports:
        snapshots["dut"][port] = _snapshot(
            environment, port).session.get("last_updated")
    for port in peer_ports:
        adapter = peer_adapter(environment, port)
        marker = adapter.publication_marker()
        if marker is not None:
            snapshots["peers"][port] = marker
    return snapshots


def _restored_environment_published(
        environment, snapshots, principal_ckn):
    for port in environment["links"]:
        dut_snapshot = _snapshot(environment, port)
        if (
                port in snapshots["dut"]
                and dut_snapshot.session.get("last_updated")
                == snapshots["dut"][port]):
            return False
        if dut_snapshot.protected_errors(
                environment["profile"], principal_ckn):
            return False
        adapter = peer_adapter(environment, port)
        if (
                port in snapshots["peers"]
                and adapter.publication_marker()
                == snapshots["peers"][port]):
            return False
        if adapter.protected_errors(
                environment["peer_profiles"][port], principal_ckn):
            return False
    return True


def _wait_restored_environment_published(
        environment, snapshots, principal_ckn, description):
    assert wait_until(
        MKA_STATE_PUBLISH_TIMEOUT, 2, 0,
        _restored_environment_published,
        environment, snapshots, principal_ckn,
    ), "{} did not republish within three status sweeps".format(
        description)


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


def _wait_active_key_stable(environment, port):
    previous = [None]
    stable = [0]

    def _stable():
        current = _snapshot(environment, port).active_key_identity()
        if current == previous[0]:
            stable[0] += 1
        else:
            previous[0] = current
            stable[0] = 0
        return stable[0] >= 2

    assert wait_until(
        MKA_STATE_PUBLISH_TIMEOUT, 2, 0, _stable
    ), "Active key identity did not stabilize on {}".format(port)
    return previous[0]


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
    body_error = None
    body_traceback = None

    try:
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
        yield adapter
    except BaseException as error:
        body_error = error
        body_traceback = error.__traceback__

    cleanup_error = None
    try:
        adapter.restore_primary(original_profile, invalid_pair)
        _wait_link_protected(
            environment, port, profile["primary_ckn"])
        _wait_peer_protected(
            adapter,
            original_profile,
            profile["primary_ckn"],
        )
    except BaseException as error:
        cleanup_error = error
    finally:
        adapter.commit_profile(original_profile)

    if body_error is not None:
        if cleanup_error is not None:
            logger.error(
                "Primary mismatch cleanup failed after scenario error: %r; "
                "diagnostics=%s",
                cleanup_error,
                _safe_diagnostics(environment, port),
            )
        raise body_error.with_traceback(body_traceback)
    if cleanup_error is not None:
        raise cleanup_error


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
    body_error = None
    body_traceback = None

    try:
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
    except BaseException as error:
        body_error = error
        body_traceback = error.__traceback__

    cleanup_error = None
    try:
        adapter.restore_fallback(original_profile, invalid_pair)
        _wait_link_protected(
            environment, port, profile["fallback_ckn"],
            require_all_live=False)
        _wait_peer_protected(
            adapter,
            original_profile,
            profile["fallback_ckn"],
            require_all_live=False,
        )
    except BaseException as error:
        cleanup_error = error
    finally:
        adapter.commit_profile(original_profile)

    if body_error is not None:
        if cleanup_error is not None:
            logger.error(
                "Fallback mismatch cleanup failed after scenario error: %r; "
                "diagnostics=%s",
                cleanup_error,
                _safe_diagnostics(environment, port),
            )
        raise body_error.with_traceback(body_traceback)
    if cleanup_error is not None:
        raise cleanup_error


def _select_routed_link(environment, upstream_links):
    for port, neighbor in environment["links"].items():
        if port in upstream_links:
            return port, neighbor
    pytest.skip("Test requires a controlled routed link")


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


def _restart_sonic_macsec(host):
    restart_service_with_startlimit_guard(
        host, "macsec", is_namespaced=host.is_multi_asic,
        backoff_seconds=35, verify_timeout=180)


def _port_profile_attachment(host, port):
    result = host.command(
        "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' macsec".format(
            get_namespace_option(host, port), port),
        module_ignore_errors=True,
        verbose=False,
    )
    return result.get("stdout", "").strip()


def _reapply_macsec_ports(environment, ports):
    for port in ports:
        disable_macsec_port(environment["duthost"], port)
    for port in ports:
        enable_macsec_port(
            environment["duthost"], port,
            environment["profile"]["name"])


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
        _restart_sonic_macsec(host)


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
    prefix = "" if isinstance(host, EosHost) else get_ipnetns_prefix(
        host, port)
    command = "{} ping -D -i 0.1 {}".format(prefix, destination)
    result = host.shell(
        "nohup {} > {} 2>&1 < /dev/null & echo $!".format(command, path))
    return {
        "host": host,
        "path": path,
        "pid": int(result["stdout_lines"][-1]),
    }


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


def _stop_ping(ping, assert_loss=True, phase_diagnostics=None):
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

    try:
        output = _read_ping_output(ping)
    finally:
        ping["host"].shell(
            "rm -f {}".format(ping["path"]),
            module_ignore_errors=True,
        )

    parsed = _parse_ping_output(output)
    summary = parsed["summary"]
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
    assert summary, "Unable to parse ping summary:\n{}".format(output)

    observation = _ping_observation_result(pre_stop_output, output)
    if assert_loss:
        assert not observation["errors"], (
            "Traffic loss detected during MACsec transition:\n{}\n"
            "Observation boundary: {}\nMissing ICMP sequences: {}\n"
            "Final ping summary: {}\nPhase diagnostics: {}"
        ).format(
            output,
            observation["boundary"],
            observation["missing_sequences"][:200],
            summary,
            phase_diagnostics or [],
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


def _cleanup_traffic(traffic, assert_loss, phase_diagnostics=None):
    cleanup_all(
        traffic,
        lambda ping: _stop_ping(
            ping, assert_loss=assert_loss,
            phase_diagnostics=phase_diagnostics))


def _start_bidirectional_traffic(environment, upstream_links):
    duthost = environment["duthost"]
    port, neighbor = _select_routed_link(environment, upstream_links)
    link = upstream_links[port]
    assert not duthost.command(
        "{} ping -c 3 {}".format(
            get_ipnetns_prefix(duthost, port),
            link["local_ipv4_addr"]),
        module_ignore_errors=True,
    )["failed"], "Unable to warm the DUT-to-neighbor traffic path"
    assert not neighbor["host"].shell(
        "{} ping -c 3 {}".format(
            "" if isinstance(neighbor["host"], EosHost)
            else get_ipnetns_prefix(
                neighbor["host"], neighbor["port"]),
            link["peer_ipv4_addr"]),
        module_ignore_errors=True,
    )["failed"], "Unable to warm the neighbor-to-DUT traffic path"
    return [
        _start_ping(
            duthost, port, link["local_ipv4_addr"], "dut_to_neighbor"),
        _start_ping(
            neighbor["host"], neighbor["port"],
            link["peer_ipv4_addr"], "neighbor_to_dut"),
    ]


def _selected_link_ping_results(environment, upstream_links, port):
    duthost = environment["duthost"]
    neighbor = environment["links"][port]
    link = upstream_links[port]
    dut_result = duthost.command(
        "{} ping -c 3 {}".format(
            get_ipnetns_prefix(duthost, port),
            link["local_ipv4_addr"]),
        module_ignore_errors=True,
    )
    peer_result = neighbor["host"].shell(
        "{} ping -c 3 {}".format(
            "" if isinstance(neighbor["host"], EosHost)
            else get_ipnetns_prefix(
                neighbor["host"], neighbor["port"]),
            link["peer_ipv4_addr"]),
        module_ignore_errors=True,
    )
    return (
        not dut_result.get("failed"),
        not peer_result.get("failed"),
    )


def _selected_link_ping_succeeds(environment, upstream_links, port):
    return all(_selected_link_ping_results(
        environment, upstream_links, port))


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


def _lifecycle_cleanup_errors(
        environment, container, affected_ports, previous_last_updated):
    errors = []
    duthost = environment["duthost"]
    for port in affected_ports:
        neighbor = environment["links"][port]
        session, _ = get_mka_state(duthost, port)
        _, egress_sc, _, egress_sas, _ = get_appl_db(
            duthost, port, neighbor["host"], neighbor["port"])
        ingress_scs = get_macsec_ingress_sc_state(duthost, port)
        port_errors = validate_lifecycle_cleanup_state(
            session,
            previous_last_updated.get(port),
            _macsecmgrd_process_ready(duthost, container),
            duthost.iface_macsec_ok(port),
            egress_sc,
            egress_sas,
            ingress_scs,
        )
        if not neighbor["host"].iface_macsec_ok(neighbor["port"]):
            port_errors.append("peer controlled port is not open")
        if port_errors:
            errors.append("{}: {}".format(port, port_errors))
    return errors


class _TrafficWindow(AbstractContextManager):
    """Guaranteed bidirectional traffic collection with exact-loss verdict."""

    def __init__(self, environment, upstream_links):
        self.environment = environment
        self.upstream_links = upstream_links
        self.traffic = []
        self.results = None

    def __enter__(self):
        self.traffic = _start_bidirectional_traffic(
            self.environment, self.upstream_links)
        return self

    def close(self, assert_loss=True):
        if self.results is None:
            results = []
            cleanup_all(
                self.traffic,
                lambda ping: results.append(
                    _stop_ping(ping, assert_loss=assert_loss)),
            )
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
        except Exception:
            if exc_type is None:
                raise
            logger.exception("Traffic cleanup failed after scenario error")
        return False


@pytest.fixture(scope="module")
def fallback_macsec_environment(
        macsec_duthost, ctrl_links, macsec_profile, port_profiles,
        get_port_profile_name):
    """Reuse an existing fallback profile or add only a missing fallback."""
    if port_profiles:
        pytest.skip(
            "Targeted rollover cases use one shared profile; the normal "
            "fallback profile still runs in the per-interface suite sweep")
    links = dict(ctrl_links)
    if not links:
        pytest.skip("Fallback CAK tests require a controlled MACsec link")
    if not mka_state_cli_supported(macsec_duthost):
        pytest.skip("SONiC image does not expose fallback CAK/MKA state CLI")

    original_profiles = {
        port: get_port_profile_name(port)
        for port in links
    }
    profile = dict(macsec_profile)
    runtime_profile = get_macsec_profile_config(
        macsec_duthost, next(iter(links)), profile["name"])
    if (not macsec_profile_has_fallback(profile)
            and runtime_profile.get("fallback_cak")
            and runtime_profile.get("fallback_ckn")):
        profile.update({
            "fallback_cak": runtime_profile["fallback_cak"],
            "fallback_ckn": runtime_profile["fallback_ckn"],
        })

    profile, added_fallback = ensure_macsec_profile_fallback(profile)
    reuse_profile = not added_fallback
    if reuse_profile:
        neighbor_profiles = {
            port: original_profiles[port]
            for port in links
        }
    else:
        profile["name"] = FALLBACK_PROFILE
        neighbor_profiles = {
            port: "{}_{}".format(FALLBACK_PROFILE, port)
            for port in links
        }
    neighbor_priorities = {}

    try:
        for index, (port, neighbor) in enumerate(links.items()):
            neighbor_priorities[port] = (
                profile["priority"] + (1 if index % 2 else -1)
            )

        if not reuse_profile:
            for port, neighbor in links.items():
                disable_macsec_port(macsec_duthost, port)
                disable_macsec_port(neighbor["host"], neighbor["port"])

            delete_macsec_profile(macsec_duthost, FALLBACK_PROFILE)
            for port, neighbor in links.items():
                delete_macsec_profile(
                    neighbor["host"], neighbor_profiles[port])

            _set_profile(macsec_duthost, FALLBACK_PROFILE, profile)
            for port, neighbor in links.items():
                _set_profile(
                    neighbor["host"], neighbor_profiles[port], profile,
                    neighbor_priorities[port])

            for port, neighbor in links.items():
                enable_macsec_port(
                    macsec_duthost, port, FALLBACK_PROFILE)
                enable_macsec_port(
                    neighbor["host"], neighbor["port"],
                    neighbor_profiles[port])

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
            "reused_profile": reuse_profile,
        }
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 5, 0,
            _environment_is_healthy, environment,
        ), "Dual-CA MKA operational state did not become healthy"
        yield environment
    finally:
        if not reuse_profile:
            for port, neighbor in links.items():
                disable_macsec_port(macsec_duthost, port)
                disable_macsec_port(neighbor["host"], neighbor["port"])
            delete_macsec_profile(macsec_duthost, FALLBACK_PROFILE)
            for port, neighbor in links.items():
                delete_macsec_profile(
                    neighbor["host"], neighbor_profiles[port])
                enable_macsec_port(
                    macsec_duthost, port, original_profiles[port])
                enable_macsec_port(
                    neighbor["host"], neighbor["port"],
                    original_profiles[port])

            for port, neighbor in links.items():
                assert wait_until(
                    MKA_CONVERGE_TIMEOUT, 3, 0,
                    lambda p=port, n=neighbor: (
                        macsec_duthost.iface_macsec_ok(p)
                        and n["host"].iface_macsec_ok(n["port"])
                    ),
                ), "Original MACsec profile did not recover on {}".format(port)


def test_fallback_operational_state_and_show(
        fallback_macsec_environment):
    """Verify dual-CA CONFIG_DB, STATE_DB, show output, and one-SC state."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]

    for port, neighbor in environment["links"].items():
        config = get_macsec_profile_config(duthost, port, profile["name"])
        for field in (
                "primary_cak", "primary_ckn", "fallback_cak", "fallback_ckn"):
            if config[field].lower() != profile[field].lower():
                pytest.fail(
                    "Configured {} does not match the test profile".format(
                        field))

        session, participants = get_mka_state(duthost, port)
        assert not validate_mka_snapshot(
            session, participants, profile, profile["primary_ckn"])
        assert not find_secret_fields({
            "session": session,
            "participants": participants,
        })
        serialized_state = json.dumps(
            {"session": session, "participants": participants}).lower()
        _assert_key_material_absent(serialized_state, profile)

        _, egress_sc, _, egress_sas, _ = get_appl_db(
            duthost, port, neighbor["host"], neighbor["port"])
        assert egress_sc, "No egress SC on {}".format(port)
        encoding_an = int(egress_sc["encoding_an"])
        assert encoding_an in egress_sas, (
            "No active egress SA on {} for AN {}; available={}"
        ).format(port, encoding_an, sorted(egress_sas))
        assert egress_sas[encoding_an].get("sak"), \
            "Active egress SA on {} has no SAK".format(port)
        ingress_scs = get_macsec_ingress_sc_state(duthost, port)
        ingress_errors = validate_point_to_point_ingress_sc(
            ingress_scs)
        assert not ingress_errors, (
            "Invalid ingress SC state on {}: {}"
        ).format(port, ingress_errors)
        if isinstance(neighbor["host"], EosHost):
            eos_output = _get_eos_participant_output(
                neighbor["host"], neighbor["port"])
            eos_participants = parse_eos_mka_participants(
                eos_output, neighbor["port"])
            assert not validate_eos_mka_participants(
                eos_participants,
                profile,
                neighbor["host"].iface_macsec_ok(neighbor["port"]),
            )
            _assert_key_material_absent(json.dumps(eos_output), profile)

        detail = duthost.command(
            "show macsec --mka {}".format(port))["stdout"].lower()
        assert profile["primary_ckn"].lower() in detail
        assert profile["fallback_ckn"].lower() in detail
        _assert_key_material_absent(detail, profile)
        assert "primary_cak" not in detail
        assert "fallback_cak" not in detail

    compact = duthost.command("show macsec --mka")["stdout"]
    for port in environment["links"]:
        assert port in compact


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
        adapter.delete_primary_if_supported(primary_pair)
        _wait_link_protected(
            environment, port, profile["fallback_ckn"],
            require_all_live=False)
        adapter.add_primary(primary_pair)
        _wait_link_protected(
            environment, port, profile["primary_ckn"])
        _wait_peer_protected(adapter, profile, profile["primary_ckn"])
        traffic.assert_zero_loss()


def test_primary_rotation_and_recovery_are_hitless(
        fallback_macsec_environment, upstream_links):
    """Rotate the primary CAK through supported config without traffic loss."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    old_pair = (profile["primary_cak"], profile["primary_ckn"])
    new_pair = generate_macsec_key_pair(profile["cipher_suite"])
    selected_port, _ = _select_routed_link(environment, upstream_links)
    adapter = peer_adapter(environment, selected_port)
    updated_ports = []

    try:
        with _TrafficWindow(environment, upstream_links) as traffic:
            _profile_update(
                duthost, profile["name"], old_pair[0], old_pair[1],
                new_pair[0], new_pair[1])
            profile["primary_cak"], profile["primary_ckn"] = new_pair
            for port in environment["links"]:
                _wait_link_protected(
                    environment, port, profile["fallback_ckn"],
                    require_all_live=False)

            adapter.rotate("primary", old_pair, new_pair)
            updated_ports.append(selected_port)
            _wait_link_protected(
                environment, selected_port, new_pair[1])
            _wait_peer_protected(adapter, profile, new_pair[1])
            traffic.assert_zero_loss()

        for port, _ in remaining_link_items(
                environment["links"], selected_port):
            peer_adapter(environment, port).rotate(
                "primary", old_pair, new_pair)
            updated_ports.append(port)
        _wait_environment(environment, new_pair[1])
    finally:
        snapshots = _capture_environment_last_updated(
            environment,
            dut_ports=tuple(environment["links"]),
            peer_ports=tuple(updated_ports),
        )
        _profile_update(
            duthost, profile["name"], new_pair[0], new_pair[1],
            old_pair[0], old_pair[1])
        for port in updated_ports:
            peer_adapter(environment, port).rotate(
                "primary", new_pair, old_pair)
        profile["primary_cak"], profile["primary_ckn"] = old_pair
        _wait_restored_environment_published(
            environment, snapshots, old_pair[1],
            "original primary cleanup")


def test_fallback_rotation_keeps_primary_and_traffic(
        fallback_macsec_environment, upstream_links):
    """Rotate the fallback participant while primary carries traffic."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    old_pair = (profile["fallback_cak"], profile["fallback_ckn"])
    new_pair = generate_macsec_key_pair(profile["cipher_suite"])
    selected_port, _ = _select_routed_link(environment, upstream_links)
    adapter = peer_adapter(environment, selected_port)
    updated_neighbors = []
    initial_key = _wait_active_key_stable(environment, selected_port)

    try:
        with _TrafficWindow(environment, upstream_links) as traffic:
            _profile_update(
                duthost, profile["name"], old_pair[0], old_pair[1],
                new_pair[0], new_pair[1], is_fallback=True)
            profile["fallback_cak"], profile["fallback_ckn"] = new_pair
            adapter.rotate("fallback", old_pair, new_pair)
            updated_neighbors.append(selected_port)
            _wait_link_protected(
                environment, selected_port, profile["primary_ckn"])
            _wait_peer_protected(
                adapter, profile, profile["primary_ckn"])
            if profile["rekey_period"] == 0:
                assert _snapshot(
                    environment, selected_port
                ).active_key_identity() == initial_key
            traffic.assert_zero_loss()

        for port, _ in remaining_link_items(
                environment["links"], selected_port):
            peer_adapter(environment, port).rotate(
                "fallback", old_pair, new_pair)
            updated_neighbors.append(port)
        _wait_environment(environment, profile["primary_ckn"])
    finally:
        snapshots = _capture_environment_last_updated(
            environment,
            dut_ports=tuple(environment["links"]),
            peer_ports=tuple(updated_neighbors),
        )
        _profile_update(
            duthost, profile["name"], new_pair[0], new_pair[1],
            old_pair[0], old_pair[1], is_fallback=True)
        for port in updated_neighbors:
            peer_adapter(environment, port).rotate(
                "fallback", new_pair, old_pair)
        profile["fallback_cak"], profile["fallback_ckn"] = old_pair
        _wait_restored_environment_published(
            environment, snapshots, profile["primary_ckn"],
            "original fallback cleanup")


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
        _wait_link_protected(
            environment, port, profile["fallback_ckn"])
        _wait_peer_protected(
            adapter, crossed_profile, profile["fallback_ckn"])
        with _TrafficWindow(environment, upstream_links) as traffic:
            time.sleep(3)
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
            traffic.assert_zero_loss()


def test_fallback_rotation_rejected_while_fallback_is_principal(
        fallback_macsec_environment, upstream_links):
    """Reject fallback rotation as a lossless no-op while fallback carries."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    port, _ = _select_routed_link(environment, upstream_links)
    invalid_pair = generate_macsec_key_pair(profile["cipher_suite"])
    replacement_pair = generate_macsec_key_pair(profile["cipher_suite"])

    with _primary_mismatch(environment, port, invalid_pair):
        before = _snapshot(environment, port)
        before_roles = {
            ckn: (
                participant.get("is_primary"),
                participant.get("is_principal"),
                participant.get("active"),
            )
            for ckn, participant in before.participants.items()
        }
        with _TrafficWindow(environment, upstream_links) as traffic:
            _profile_update(
                duthost, profile["name"],
                profile["fallback_cak"], profile["fallback_ckn"],
                replacement_pair[0], replacement_pair[1],
                is_fallback=True,
                namespace_option=get_namespace_option(duthost, port),
                expect_success=False)
            after = _snapshot(environment, port)
            _assert_profile_unchanged(
                before.profile_config,
                after.profile_config,
                "Rejected fallback rotation",
            )
            assert {
                ckn: (
                    participant.get("is_primary"),
                    participant.get("is_principal"),
                    participant.get("active"),
                )
                for ckn, participant in after.participants.items()
            } == before_roles
            assert not after.protected_errors(
                profile, profile["fallback_ckn"],
                require_all_live=False)
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
    old_cak = profile["primary_cak"]
    old_ckn = profile["primary_ckn"]
    new_cak, new_ckn = generate_macsec_key_pair(profile["cipher_suite"])
    dut_updated = False
    updated_neighbors = []

    try:
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

            _profile_update(
                environment["duthost"], profile["name"],
                old_cak, old_ckn, new_cak, new_ckn)
            dut_updated = True
            profile["primary_cak"] = new_cak
            profile["primary_ckn"] = new_ckn
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 2, 0,
                _environment_is_healthy, environment,
                profile["fallback_ckn"], False, False,
            ), "Fallback did not carry the post-SAK-boundary CAK rotation"

            for port, neighbor in environment["links"].items():
                _profile_update(
                    neighbor["host"],
                    environment["neighbor_profiles"][port],
                    old_cak, old_ckn, new_cak, new_ckn)
                updated_neighbors.append(port)
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 2, 0,
                _environment_is_healthy, environment, new_ckn,
            ), "Primary did not recover after boundary CAK rotation"
            traffic.assert_zero_loss()
    finally:
        if dut_updated:
            _profile_update(
                environment["duthost"], profile["name"],
                new_cak, new_ckn, old_cak, old_ckn)
        for port in updated_neighbors:
            neighbor = environment["links"][port]
            _profile_update(
                neighbor["host"],
                environment["neighbor_profiles"][port],
                new_cak, new_ckn, old_cak, old_ckn)
        profile["primary_cak"] = old_cak
        profile["primary_ckn"] = old_ckn
        _configure_environment_rekey_period(
            environment, original_period)
        profile["rekey_period"] = original_period
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "MKA did not recover after boundary stress cleanup"


@pytest.mark.stress_test
def test_back_to_back_cak_rotation_stress(
        fallback_macsec_environment, upstream_links):
    """Alternate bounded primary/fallback rotations without wedging MKA."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    if profile["name"] != FALLBACK_PROFILE:
        pytest.skip("Rotation stress runs only on the static fallback profile")

    original = dict(profile)
    dut_pairs = {
        role: (profile["{}_cak".format(role)],
               profile["{}_ckn".format(role)])
        for role in ("primary", "fallback")
    }
    peer_pairs = {
        port: dict(dut_pairs)
        for port in environment["links"]
    }
    with _TrafficWindow(environment, upstream_links) as traffic:
        try:
            for iteration in range(STRESS_ROTATIONS):
                is_fallback = iteration % 2 == 1
                role = "fallback" if is_fallback else "primary"
                old_cak = profile["{}_cak".format(role)]
                old_ckn = profile["{}_ckn".format(role)]
                new_cak, new_ckn = generate_macsec_key_pair(
                    profile["cipher_suite"])

                _profile_update(
                    environment["duthost"], profile["name"],
                    old_cak, old_ckn, new_cak, new_ckn,
                    is_fallback=is_fallback)
                dut_pairs[role] = (new_cak, new_ckn)
                profile["{}_cak".format(role)] = new_cak
                profile["{}_ckn".format(role)] = new_ckn

                for port, neighbor in environment["links"].items():
                    _profile_update(
                        neighbor["host"],
                        environment["neighbor_profiles"][port],
                        old_cak, old_ckn, new_cak, new_ckn,
                        is_fallback=is_fallback)
                    peer_pairs[port][role] = (new_cak, new_ckn)

                assert wait_until(
                    MKA_CONVERGE_TIMEOUT, 2, 0,
                    _environment_is_healthy, environment,
                ), "MKA wedged after {} rotation {}".format(
                    role, iteration + 1)
                for port, neighbor in environment["links"].items():
                    _, egress_sc, ingress_sc, _, _ = get_appl_db(
                        environment["duthost"], port,
                        neighbor["host"], neighbor["port"])
                    assert egress_sc and ingress_sc
        finally:
            for role, is_fallback in (
                    ("primary", False), ("fallback", True)):
                original_cak = original["{}_cak".format(role)]
                original_ckn = original["{}_ckn".format(role)]
                current_cak, current_ckn = dut_pairs[role]
                if (current_cak, current_ckn) != (
                        original_cak, original_ckn):
                    _profile_update(
                        environment["duthost"], profile["name"],
                        current_cak, current_ckn,
                        original_cak, original_ckn,
                        is_fallback=is_fallback)
                for port, neighbor in environment["links"].items():
                    peer_cak, peer_ckn = peer_pairs[port][role]
                    if (peer_cak, peer_ckn) != (
                            original_cak, original_ckn):
                        _profile_update(
                            neighbor["host"],
                            environment["neighbor_profiles"][port],
                            peer_cak, peer_ckn,
                            original_cak, original_ckn,
                            is_fallback=is_fallback)
                profile["{}_cak".format(role)] = original_cak
                profile["{}_ckn".format(role)] = original_ckn
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 3, 0,
                _environment_is_healthy, environment,
            ), "MKA did not recover after CAK rotation stress"
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

    delete_macsec_profile(duthost, temp_name)
    try:
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

        half_fallback = duthost.command(
            "config macsec {} profile add {} {} --fallback_cak {}".format(
                namespace, temp_name, base_options, fallback_cak),
            module_ignore_errors=True,
        )
        assert half_fallback["failed"]
        assert not get_macsec_profile_config(
            duthost, port, temp_name)

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
        _set_profile(duthost, temp_name, valid_profile)
        new_cak, new_ckn = generate_macsec_key_pair(
            profile["cipher_suite"])
        _profile_update(
            duthost, temp_name, primary_cak, primary_ckn, new_cak, new_ckn,
            namespace_option=namespace)
        config = get_macsec_profile_config(duthost, port, temp_name)
        assert config["primary_ckn"].lower() == new_ckn.lower()

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
        _assert_profile_unchanged(
            before,
            get_macsec_profile_config(duthost, port, temp_name),
            "Rejected unattached-profile update",
        )
    finally:
        delete_macsec_profile(duthost, temp_name)


def test_multi_port_preflight_is_all_or_nothing(
        fallback_macsec_environment):
    """Reject rotation when one attached port has no live alternate."""
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
            "All-or-nothing preflight requires two ports in one namespace")

    peer_scopes = {
        port: (
            environment["links"][port]["host"].hostname,
            environment["neighbor_profiles"][port],
        )
        for port in ports
    }
    pair = select_independent_port_pair(ports, peer_scopes)
    if pair is None:
        pytest.skip(
            "All-or-nothing preflight requires independently scoped "
            "peer profiles")
    unsafe_port, safe_port = pair

    old_pair = (profile["fallback_cak"], profile["fallback_ckn"])
    mismatched_pair = generate_macsec_key_pair(
        profile["cipher_suite"])
    replacement_cak, replacement_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    namespace = get_namespace_option(duthost, unsafe_port)
    adapter = peer_adapter(environment, unsafe_port)

    try:
        adapter.rotate("fallback", old_pair, mismatched_pair)

        def _preconditions_ready():
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
            return not validate_multi_port_alternate_state(
                participants_by_port,
                old_pair[1],
                unsafe_port,
                [safe_port],
                peer_participants_by_port,
                peer_configured_ckns_by_port,
            )

        assert wait_until(
            _protocol_timeout(environment, unsafe_port, 4), 1, 0,
            _preconditions_ready,
        ), "Multi-port preconditions failed: unsafe={}, safe={}".format(
            _diagnostics(environment, unsafe_port),
            _diagnostics(environment, safe_port),
        )

        before = get_macsec_profile_config(
            duthost, unsafe_port, profile["name"])
        _profile_update(
            duthost, profile["name"], profile["primary_cak"],
            profile["primary_ckn"], replacement_cak, replacement_ckn,
            namespace_option=namespace, expect_success=False)
        after = get_macsec_profile_config(
            duthost, unsafe_port, profile["name"])
        _assert_profile_unchanged(
            before, after, "Rejected multi-port preflight")
        for port in ports:
            assert _snapshot(environment, port).principal_ckns() == [
                profile["primary_ckn"].lower()]
    finally:
        adapter.rotate("fallback", mismatched_pair, old_pair)
        _wait_environment(environment, profile["primary_ckn"])


def test_query_failure_retains_state_and_recovers(
        fallback_macsec_environment):
    """Document that query-failure injection belongs in component testing."""
    pytest.skip(
        "MKA query-failure injection requires direct wpa_supplicant "
        "control; sonic-mgmt E2E coverage uses supported service restart "
        "and published-state recovery instead")


def _macsecmgrd_restart_known_failure(duthost, tbinfo):
    """Return whether this physical testbed has the known rebuild defect."""
    return (
        tbinfo.get("conf-name") == "vms26-t2-7800-1"
        and duthost.facts.get("asic_type") != "vs"
    )


def test_disable_and_macsecmgrd_restart_lifecycle(
        fallback_macsec_environment, upstream_links, tbinfo):
    """Delete state on port disable and rebuild it after macsecmgrd restart."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    if _macsecmgrd_restart_known_failure(duthost, tbinfo):
        pytest.skip(
            "Known macsecmgrd reconstruction failure on physical "
            "vms26-t2-7800-1; retain coverage on VS and other testbeds")
    profile = environment["profile"]
    selected_port, _ = _select_routed_link(
        environment, upstream_links)

    disable_macsec_port(duthost, selected_port)
    try:
        assert wait_until(
            MKA_TIMEOUT, 2, 0,
            lambda: get_mka_state(
                duthost, selected_port) == ({}, {}),
        ), "MKA operational rows remained after explicit port disable"
    finally:
        enable_macsec_port(
            duthost, selected_port, profile["name"])

    assert wait_until(
        MKA_CONVERGE_TIMEOUT, 3, 0,
        _environment_is_healthy, environment,
    ), "MKA did not recover after port re-enable"

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
    previous_last_updated = {
        candidate: get_mka_state(duthost, candidate)[0].get(
            "last_updated")
        for candidate in affected_ports
    }
    bgp_neighbors = duthost.get_bgp_neighbors_per_asic(
        state="all")
    traffic = []
    restart_error = None
    restart_traceback = None
    try:
        traffic = _start_bidirectional_traffic(
            environment, upstream_links)
        result = duthost.command(
            macsecmgrd_restart_command(container),
            module_ignore_errors=True,
        )
        assert not result.get("failed"), (
            "supervisor restart macsecmgrd failed: {}"
        ).format(result)

        def _restart_ready():
            status = duthost.command(
                "docker exec {} supervisorctl status macsecmgrd".format(
                    container),
                module_ignore_errors=True,
            ).get("stdout", "")
            new_pids = duthost.command(
                "docker exec {} pgrep -x macsecmgrd".format(container),
                module_ignore_errors=True,
            ).get("stdout_lines", [])
            return macsecmgrd_restart_ready(
                old_pids, new_pids, status)

        assert wait_until(60, 2, 0, _restart_ready), \
            "macsecmgrd did not restart with a new RUNNING process"
        reconstructed = wait_until(
            25, 2, 0,
            _environment_is_healthy, environment,
        )
        if not reconstructed:
            attachments = {
                candidate: _port_profile_attachment(
                    duthost, candidate)
                for candidate in affected_ports
            }
            rows = {
                candidate: get_mka_state(duthost, candidate)
                for candidate in affected_ports
            }
            raise AssertionError(
                "macsecmgrd restart reconstruction defect signature: "
                "supervisor RUNNING with a new PID and CONFIG_DB "
                "attachments {}, but MKA rows did not rebuild after >20s: "
                "{}".format(attachments, rows))
    except BaseException as error:
        restart_error = error
        restart_traceback = error.__traceback__

    cleanup_errors = []
    try:
        _cleanup_traffic(traffic, assert_loss=False)
    except Exception as error:
        cleanup_errors.append(
            "traffic collection failed: {!r}".format(error))

    try:
        status = duthost.command(
            "docker exec {} supervisorctl status macsecmgrd".format(
                container),
            module_ignore_errors=True,
        ).get("stdout", "")
        if "RUNNING" not in status:
            duthost.command(
                "docker exec {} supervisorctl start macsecmgrd".format(
                    container),
                module_ignore_errors=True,
            )
            assert wait_until(60, 2, 0, lambda: "RUNNING" in
                              duthost.command(
                                  "docker exec {} supervisorctl status "
                                  "macsecmgrd".format(container),
                                  module_ignore_errors=True,
                              ).get("stdout", ""))
        _reapply_macsec_ports(environment, affected_ports)
    except Exception as error:
        cleanup_errors.append(
            "service/port reapply failed: {!r}".format(error))

    cleanup_state_errors = [None]
    try:
        def _cleanup_state_ready():
            cleanup_state_errors[0] = _lifecycle_cleanup_errors(
                environment, container, affected_ports,
                previous_last_updated)
            return not cleanup_state_errors[0]

        cleanup_state_recovered = wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0, _cleanup_state_ready)
    except Exception as error:
        cleanup_state_recovered = False
        cleanup_state_errors[0] = [repr(error)]
    if not cleanup_state_recovered:
        cleanup_errors.append(
            "fresh MKA/process/SC-SA recovery failed: {}".format(
                cleanup_state_errors[0]))
    try:
        selected_link_recovered = _selected_link_ping_succeeds(
            environment, upstream_links, selected_port)
    except Exception as error:
        selected_link_recovered = False
        cleanup_errors.append(
            "selected-link ping check failed: {!r}".format(error))
    if not selected_link_recovered:
        cleanup_errors.append(
            "selected-link bidirectional ping did not recover")
    try:
        bgp_recovered = wait_until(
            MKA_CONVERGE_TIMEOUT, 10, 0,
            duthost.check_bgp_session_state_all_asics,
            bgp_neighbors)
    except Exception as error:
        bgp_recovered = False
        cleanup_errors.append(
            "external BGP recovery check failed: {!r}".format(error))
    if not bgp_recovered:
        cleanup_errors.append(
            "external BGP sessions did not recover")

    if restart_error is not None:
        if cleanup_errors:
            logger.error(
                "Lifecycle cleanup failed after restart verdict: %s",
                cleanup_errors)
        raise restart_error.with_traceback(restart_traceback)
    assert not cleanup_errors, \
        "Lifecycle cleanup failed: {}".format(cleanup_errors)


def test_both_invalid_tears_down_and_fallback_recovers(
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
