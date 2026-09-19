import hashlib
import json
import logging
import re
import time

import pytest
from passlib.hash import cisco_type7

from tests.common.devices.eos import EosHost
from tests.common.helpers.dut_utils import (
    restart_service_with_startlimit_guard,
)
from tests.common.macsec.macsec_config_helper import (
    add_runtime_macsec_key,
    delete_macsec_profile,
    delete_runtime_macsec_key,
    disable_macsec_port,
    enable_macsec_port,
    ensure_macsec_profile_fallback,
    generate_macsec_key_pair,
    macsec_profile_has_fallback,
    list_runtime_macsec_participants,
    set_macsec_profile,
    update_macsec_profile_key,
)
from tests.common.macsec.macsec_helper import (
    get_appl_db,
    get_ipnetns_prefix,
)
from tests.common.macsec.mka_state_helper import (
    find_secret_fields,
    get_macsec_profile_config,
    get_mka_state,
    get_namespace_option,
    mka_state_cli_supported,
    parse_eos_mka_participants,
    parse_wpa_mka_participants,
    validate_eos_mka_participants,
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
        assert encoded.lower() not in text
        assert decoded.lower() not in text


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


def _get_eos_participants(host, port):
    return parse_eos_mka_participants(
        _get_eos_participant_output(host, port), port)


def _replace_peer_profile(neighbor, profile_name, profile, priority):
    disable_macsec_port(neighbor["host"], neighbor["port"])
    delete_macsec_profile(neighbor["host"], profile_name)
    _set_profile(neighbor["host"], profile_name, profile, priority)
    enable_macsec_port(neighbor["host"], neighbor["port"], profile_name)


def _pause_macsecmgrd(host, port):
    asic = host.get_port_asic_instance(port)
    container = asic.get_docker_name("macsec")
    result = host.command(
        "docker exec {} pgrep -x macsecmgrd".format(container))
    pids = [int(pid) for pid in result.get("stdout_lines", [])]
    assert pids, "Unable to locate macsecmgrd"
    host.command(
        "docker exec {} kill -STOP {}".format(
            container, " ".join(str(pid) for pid in pids)))
    return container, pids


def _resume_macsecmgrd(host, paused):
    container, pids = paused
    host.command(
        "docker exec {} kill -CONT {}".format(
            container, " ".join(str(pid) for pid in pids)),
        module_ignore_errors=True,
    )


def _runtime_participants(host, port):
    return parse_wpa_mka_participants(
        list_runtime_macsec_participants(host, port))


def _direct_participants(host, port):
    if isinstance(host, EosHost):
        return _get_eos_participants(host, port)
    return _runtime_participants(host, port)


def _stable_sa_fingerprint(table):
    stable_rows = []
    for an, row in sorted(table.items()):
        stable_rows.append({
            "an": str(an),
            "sak": row.get("sak"),
            "salt": row.get("salt"),
            "ssci": row.get("ssci"),
        })
    return hashlib.sha256(
        json.dumps(stable_rows, sort_keys=True).encode()
    ).hexdigest()


def _snapshot_active_key_state(environment):
    snapshot = {}
    for port, neighbor in environment["links"].items():
        session, _ = get_mka_state(environment["duthost"], port)
        _, _, _, egress_sa, ingress_sa = get_appl_db(
            environment["duthost"], port,
            neighbor["host"], neighbor["port"])
        snapshot[port] = {
            "keys_distributed": session.get("keys_distributed"),
            "keys_received": session.get("keys_received"),
            "egress_sa": _stable_sa_fingerprint(egress_sa),
            "ingress_sa": _stable_sa_fingerprint(ingress_sa),
        }
    return snapshot


def _sa_identity_changed(before, after):
    return any(
        before[port]["egress_sa"] != after[port]["egress_sa"]
        or before[port]["ingress_sa"] != after[port]["ingress_sa"]
        for port in before
    )


def _wait_for_stable_active_key_state(environment):
    previous = [None]

    def _stable():
        current = _snapshot_active_key_state(environment)
        if current == previous[0]:
            return True
        previous[0] = current
        return False

    assert wait_until(30, 3, 3, _stable), \
        "Active SAK state did not stabilize before fallback rotation"
    return previous[0]


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


def _peer_state_is_healthy(
        neighbor, profile, profile_name, principal_ckn,
        require_all_live=True):
    host = neighbor["host"]
    port = neighbor["port"]
    if not host.iface_macsec_ok(port):
        return False

    if isinstance(host, EosHost):
        participants = _get_eos_participants(host, port)
        return not validate_eos_mka_participants(
            participants, profile, principal_ckn,
            require_all_live=require_all_live)

    peer_profile = dict(profile, name=profile_name)
    session, participants = get_mka_state(host, port)
    return not validate_mka_snapshot(
        session, participants, peer_profile, principal_ckn,
        require_all_live=require_all_live)


def _participant_is_principal(host, port, ckn):
    session, participants = get_mka_state(host, port)
    participant = participants.get(ckn.lower(), {})
    return (
        session.get("query_status") == "ok"
        and session.get("secured") == "true"
        and participant.get("is_principal") == "true"
        and participant.get("live_peers", "0").isdigit()
        and int(participant["live_peers"]) >= 1
    )


def _environment_is_healthy(
        environment, principal_ckn=None, require_all_live=True,
        validate_peers=True):
    profile = environment["profile"]
    principal_ckn = principal_ckn or profile["primary_ckn"]
    for port in environment["links"]:
        neighbor = environment["links"][port]
        session, participants = get_mka_state(
            environment["duthost"], port)
        errors = validate_mka_snapshot(
            session, participants, profile, principal_ckn,
            require_all_live=require_all_live)
        if errors:
            logger.info("MKA state on %s is not ready: %s", port, errors)
            return False
        if (validate_peers and
                not _peer_state_is_healthy(
                    neighbor, profile,
                    environment["neighbor_profiles"][port],
                    principal_ckn, require_all_live)):
            logger.info(
                "Peer MKA state on %s is not ready", neighbor["port"])
            return False
    return True


def _start_ping(host, port, destination, suffix):
    path = "/tmp/macsec_fallback_{}_{}.log".format(port, suffix)
    host.shell("rm -f {}".format(path), module_ignore_errors=True)
    prefix = "" if isinstance(host, EosHost) else get_ipnetns_prefix(
        host, port)
    command = "{} ping -q -i 0.1 {}".format(prefix, destination)
    result = host.shell(
        "nohup {} > {} 2>&1 < /dev/null & echo $!".format(command, path))
    return {
        "host": host,
        "path": path,
        "pid": int(result["stdout_lines"][-1]),
    }


def _stop_ping(ping):
    ping["host"].shell(
        "sudo kill -INT {}".format(ping["pid"]), module_ignore_errors=True)

    def _has_summary():
        result = ping["host"].shell(
            "cat {}".format(ping["path"]), module_ignore_errors=True)
        return "packet loss" in result.get("stdout", "")

    assert wait_until(15, 1, 0, _has_summary), (
        "Continuous ping did not produce a summary: {}"
    ).format(ping)
    output = ping["host"].shell("cat {}".format(ping["path"]))["stdout"]
    ping["host"].shell(
        "rm -f {}".format(ping["path"]), module_ignore_errors=True)
    match = re.search(
        r"(\d+) packets transmitted, (\d+) (?:packets )?received,.*?"
        r"([\d.]+)% packet loss",
        output,
        re.DOTALL,
    )
    assert match, "Unable to parse ping output:\n{}".format(output)
    transmitted, received = int(match.group(1)), int(match.group(2))
    assert transmitted >= 10, (
        "Traffic sample was too short:\n{}"
    ).format(output)
    assert transmitted == received and float(match.group(3)) == 0.0, (
        "Traffic loss detected during MACsec transition:\n{}"
    ).format(output)


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
            assert config[field].lower() == profile[field].lower()

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

        _, egress_sc, ingress_sc, _, _ = get_appl_db(
            duthost, port, neighbor["host"], neighbor["port"])
        assert egress_sc, "No egress SC on {}".format(port)
        assert ingress_sc, "No ingress SC on {}".format(port)
        if isinstance(neighbor["host"], EosHost):
            eos_output = _get_eos_participant_output(
                neighbor["host"], neighbor["port"])
            eos_participants = parse_eos_mka_participants(
                eos_output, neighbor["port"])
            assert set(eos_participants) == {
                profile["primary_ckn"].lower(),
                profile["fallback_ckn"].lower(),
            }
            assert sum(
                participant["is_principal"]
                for participant in eos_participants.values()
            ) == 1
            assert all(
                participant["active"]
                for participant in eos_participants.values()
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


def test_primary_failure_rotation_and_recovery_are_hitless(
        fallback_macsec_environment, upstream_links):
    """Rotate one side first, fail over to fallback, then recover primary."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    old_cak = profile["primary_cak"]
    old_ckn = profile["primary_ckn"]
    new_cak, new_ckn = generate_macsec_key_pair(profile["cipher_suite"])
    traffic = _start_bidirectional_traffic(environment, upstream_links)
    dut_updated = False
    updated_neighbors = []

    try:
        port, neighbor = _select_routed_link(environment, upstream_links)
        paused = _pause_macsecmgrd(duthost, port)
        primary_removed = False
        try:
            delete_runtime_macsec_key(
                duthost, port, profile["name"], old_cak, old_ckn)
            primary_removed = True

            def _fallback_owns_remove_only_interval():
                participants = _runtime_participants(duthost, port)
                return (
                    old_ckn.lower() not in participants
                    and participants.get(
                        profile["fallback_ckn"].lower(), {}
                    ).get("is_principal")
                    and _peer_state_is_healthy(
                        neighbor, profile,
                        environment["neighbor_profiles"][port],
                        profile["fallback_ckn"],
                        require_all_live=False)
                    and duthost.iface_macsec_ok(port)
                )

            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 2, 0,
                _fallback_owns_remove_only_interval,
            ), "Fallback did not own the remove-only primary interval"

            add_runtime_macsec_key(
                duthost, port, profile["name"], old_cak, old_ckn)
            primary_removed = False

            def _primary_reclaims_after_add():
                participants = _runtime_participants(duthost, port)
                return (
                    participants.get(old_ckn.lower(), {}).get(
                        "is_principal")
                    and _peer_state_is_healthy(
                        neighbor, profile,
                        environment["neighbor_profiles"][port],
                        old_ckn)
                )

            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 2, 0,
                _primary_reclaims_after_add,
            ), "Primary did not reclaim the port after runtime add"
        finally:
            if primary_removed:
                add_runtime_macsec_key(
                    duthost, port, profile["name"], old_cak, old_ckn)
            _resume_macsecmgrd(duthost, paused)

        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "MKA state did not recover after runtime primary remove/add"

        peer_paused = (
            None if isinstance(neighbor["host"], EosHost)
            else _pause_macsecmgrd(neighbor["host"], neighbor["port"])
        )
        peer_primary_removed = False
        try:
            delete_runtime_macsec_key(
                neighbor["host"], neighbor["port"],
                environment["neighbor_profiles"][port],
                old_cak, old_ckn)
            peer_primary_removed = True

            def _peer_fallback_owns_remove_only_interval():
                participants = _direct_participants(
                    neighbor["host"], neighbor["port"])
                return (
                    old_ckn.lower() not in participants
                    and participants.get(
                        profile["fallback_ckn"].lower(), {}
                    ).get("is_principal")
                    and _participant_is_principal(
                        duthost, port, profile["fallback_ckn"])
                    and neighbor["host"].iface_macsec_ok(
                        neighbor["port"])
                )

            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 2, 0,
                _peer_fallback_owns_remove_only_interval,
            ), "Peer fallback did not own its remove-only primary interval"

            add_runtime_macsec_key(
                neighbor["host"], neighbor["port"],
                environment["neighbor_profiles"][port],
                old_cak, old_ckn)
            peer_primary_removed = False

            def _peer_primary_reclaims_after_add():
                participants = _direct_participants(
                    neighbor["host"], neighbor["port"])
                return (
                    participants.get(old_ckn.lower(), {}).get(
                        "is_principal")
                    and _participant_is_principal(
                        duthost, port, old_ckn)
                )

            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 2, 0,
                _peer_primary_reclaims_after_add,
            ), "Peer primary did not reclaim the port after runtime add"
        finally:
            if peer_primary_removed:
                add_runtime_macsec_key(
                    neighbor["host"], neighbor["port"],
                    environment["neighbor_profiles"][port],
                    old_cak, old_ckn)
            if peer_paused:
                _resume_macsecmgrd(neighbor["host"], peer_paused)

        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "MKA state did not recover after peer primary remove/add"

        _profile_update(
            duthost, profile["name"], old_cak, old_ckn, new_cak, new_ckn)
        dut_updated = True
        profile["primary_cak"] = new_cak
        profile["primary_ckn"] = new_ckn
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment, profile["fallback_ckn"],
            False, False,
        ), "Fallback did not become principal after one-sided primary rotation"
        for port in environment["links"]:
            _, participants = get_mka_state(duthost, port)
            assert old_ckn.lower() not in participants
            assert new_ckn.lower() in participants

        for port, neighbor in environment["links"].items():
            _profile_update(
                neighbor["host"], environment["neighbor_profiles"][port],
                old_cak, old_ckn, new_cak, new_ckn)
            updated_neighbors.append(port)

        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment, new_ckn,
        ), "Replacement primary did not regain ownership"
    finally:
        try:
            for ping in traffic:
                _stop_ping(ping)
        finally:
            if dut_updated:
                _profile_update(
                    duthost, profile["name"], new_cak, new_ckn,
                    old_cak, old_ckn)
            for port in updated_neighbors:
                neighbor = environment["links"][port]
                _profile_update(
                    neighbor["host"],
                    environment["neighbor_profiles"][port],
                    new_cak, new_ckn, old_cak, old_ckn)
            profile["primary_cak"] = old_cak
            profile["primary_ckn"] = old_ckn
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 3, 0,
                _environment_is_healthy, environment,
            ), "Original primary did not recover after rotation test"


def test_fallback_rotation_keeps_primary_and_traffic(
        fallback_macsec_environment, upstream_links):
    """Rotate the fallback participant while primary carries traffic."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    old_cak = profile["fallback_cak"]
    old_ckn = profile["fallback_ckn"]
    new_cak, new_ckn = generate_macsec_key_pair(profile["cipher_suite"])
    traffic = _start_bidirectional_traffic(environment, upstream_links)
    dut_updated = False
    updated_neighbors = []
    assert_no_forced_rekey = profile["rekey_period"] == 0
    initial_key_state = (
        _wait_for_stable_active_key_state(environment)
        if assert_no_forced_rekey else None
    )

    try:
        _profile_update(
            duthost, profile["name"], old_cak, old_ckn, new_cak, new_ckn,
            is_fallback=True)
        dut_updated = True
        profile["fallback_cak"] = new_cak
        profile["fallback_ckn"] = new_ckn
        for port in environment["links"]:
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 3, 0,
                _participant_is_principal,
                duthost, port, profile["primary_ckn"],
            ), "Primary lost ownership during fallback rotation"
        if assert_no_forced_rekey:
            assert (
                _snapshot_active_key_state(environment) == initial_key_state
            ), \
                "DUT fallback update unexpectedly changed the active SAK"

        for port, neighbor in environment["links"].items():
            _profile_update(
                neighbor["host"], environment["neighbor_profiles"][port],
                old_cak, old_ckn, new_cak, new_ckn,
                is_fallback=True)
            updated_neighbors.append(port)
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "Replacement fallback did not converge"
        if assert_no_forced_rekey:
            assert (
                _snapshot_active_key_state(environment) == initial_key_state
            ), \
                "Peer fallback update unexpectedly changed the active SAK"
    finally:
        try:
            for ping in traffic:
                _stop_ping(ping)
        finally:
            if dut_updated:
                _profile_update(
                    duthost, profile["name"], new_cak, new_ckn,
                    old_cak, old_ckn, is_fallback=True)
            for port in updated_neighbors:
                neighbor = environment["links"][port]
                _profile_update(
                    neighbor["host"],
                    environment["neighbor_profiles"][port],
                    new_cak, new_ckn, old_cak, old_ckn,
                    is_fallback=True)
            profile["fallback_cak"] = old_cak
            profile["fallback_ckn"] = old_ckn
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 3, 0,
                _environment_is_healthy, environment,
            ), "Original fallback did not recover after rotation test"


def test_crossed_roles_follow_key_server_primary(
        fallback_macsec_environment, upstream_links):
    """Verify crossed local roles follow the elected key server's primary."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    port, neighbor = _select_routed_link(environment, upstream_links)
    peer_profile_name = environment["neighbor_profiles"][port]
    peer_priority = max(0, profile["priority"] - 1)
    crossed_profile = dict(profile)
    crossed_profile.update({
        "primary_cak": profile["fallback_cak"],
        "primary_ckn": profile["fallback_ckn"],
        "fallback_cak": profile["primary_cak"],
        "fallback_ckn": profile["primary_ckn"],
    })
    traffic = []

    try:
        _replace_peer_profile(
            neighbor, peer_profile_name, crossed_profile, peer_priority)

        def _crossed_roles_converged():
            session, participants = get_mka_state(
                environment["duthost"], port)
            dut_errors = validate_mka_snapshot(
                session, participants, profile,
                profile["fallback_ckn"])
            return (
                not dut_errors
                and _peer_state_is_healthy(
                    neighbor, crossed_profile, peer_profile_name,
                    profile["fallback_ckn"])
            )

        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _crossed_roles_converged,
        ), "Crossed primary/fallback roles did not converge"

        traffic = _start_bidirectional_traffic(
            environment, upstream_links)
        time.sleep(3)
    finally:
        try:
            for ping in traffic:
                _stop_ping(ping)
        finally:
            _replace_peer_profile(
                neighbor, peer_profile_name, profile,
                environment["neighbor_priorities"][port])
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 3, 0,
                _environment_is_healthy, environment,
            ), "Normal primary/fallback roles did not recover"


def test_fallback_rotation_rejected_without_live_primary(
        fallback_macsec_environment, upstream_links):
    """Reject fallback rotation while fallback carries a failed primary."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    port, neighbor = _select_routed_link(environment, upstream_links)
    peer_profile_name = environment["neighbor_profiles"][port]
    invalid_cak, invalid_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    replacement_cak, replacement_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    traffic = _start_bidirectional_traffic(environment, upstream_links)
    peer_updated = False

    try:
        _profile_update(
            neighbor["host"], peer_profile_name,
            profile["primary_cak"], profile["primary_ckn"],
            invalid_cak, invalid_ckn)
        peer_updated = True
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _participant_is_principal,
            duthost, port, profile["fallback_ckn"],
        ), "Fallback did not take over after the primary stopped being live"

        before_config = get_macsec_profile_config(
            duthost, port, profile["name"])
        _, before_participants = get_mka_state(duthost, port)
        _profile_update(
            duthost, profile["name"],
            profile["fallback_cak"], profile["fallback_ckn"],
            replacement_cak, replacement_ckn,
            is_fallback=True,
            namespace_option=get_namespace_option(duthost, port),
            expect_success=False)
        after_config = get_macsec_profile_config(
            duthost, port, profile["name"])
        _, after_participants = get_mka_state(duthost, port)
        assert after_config == before_config
        before_roles = {
            ckn: (
                participant.get("is_primary"),
                participant.get("is_principal"),
                participant.get("active"),
            )
            for ckn, participant in before_participants.items()
        }
        after_roles = {
            ckn: (
                participant.get("is_primary"),
                participant.get("is_principal"),
                participant.get("active"),
            )
            for ckn, participant in after_participants.items()
        }
        assert after_roles == before_roles
        assert _participant_is_principal(
            duthost, port, profile["fallback_ckn"])
    finally:
        try:
            if peer_updated:
                _profile_update(
                    neighbor["host"], peer_profile_name,
                    invalid_cak, invalid_ckn,
                    profile["primary_cak"], profile["primary_ckn"])
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 3, 0,
                _environment_is_healthy, environment,
            ), "Primary did not recover after rejected fallback rotation"
        finally:
            for ping in traffic:
                _stop_ping(ping)


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
    traffic = []
    dut_updated = False
    updated_neighbors = []

    try:
        _configure_environment_rekey_period(environment, 30)
        profile["rekey_period"] = 30
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "MKA did not converge with the short rekey period"

        traffic = _start_bidirectional_traffic(environment, upstream_links)
        before = _snapshot_active_key_state(environment)
        assert wait_until(
            90, 2, 0,
            lambda: _sa_identity_changed(
                before, _snapshot_active_key_state(environment)),
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
    finally:
        try:
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
        finally:
            for ping in traffic:
                _stop_ping(ping)


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
    traffic = _start_bidirectional_traffic(environment, upstream_links)
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
        try:
            for role, is_fallback in (
                    ("primary", False), ("fallback", True)):
                original_cak = original["{}_cak".format(role)]
                original_ckn = original["{}_ckn".format(role)]
                current_cak, current_ckn = dut_pairs[role]
                if (current_cak, current_ckn) == (
                        original_cak, original_ckn):
                    pass
                else:
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
        finally:
            for ping in traffic:
                _stop_ping(ping)


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
        assert get_macsec_profile_config(
            duthost, port, temp_name) == before
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

    unsafe_port = ports[0]
    safe_port = ports[1]
    neighbor = environment["links"][unsafe_port]
    old_fallback_cak = profile["fallback_cak"]
    old_fallback_ckn = profile["fallback_ckn"]
    mismatched_cak, mismatched_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    replacement_cak, replacement_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    namespace = get_namespace_option(duthost, unsafe_port)
    neighbor_updated = False

    try:
        _profile_update(
            neighbor["host"],
            environment["neighbor_profiles"][unsafe_port],
            old_fallback_cak, old_fallback_ckn,
            mismatched_cak, mismatched_ckn, is_fallback=True)
        neighbor_updated = True
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            lambda: (
                get_mka_state(duthost, unsafe_port)[1]
                [old_fallback_ckn.lower()].get("live_peers") == "0"
                and int(get_mka_state(duthost, safe_port)[1]
                        [old_fallback_ckn.lower()].get("live_peers", "0")) >= 1
            ),
        ), "Did not create one unsafe and one safe attached port"

        before = get_macsec_profile_config(
            duthost, unsafe_port, profile["name"])
        _profile_update(
            duthost, profile["name"], profile["primary_cak"],
            profile["primary_ckn"], replacement_cak, replacement_ckn,
            namespace_option=namespace, expect_success=False)
        after = get_macsec_profile_config(
            duthost, unsafe_port, profile["name"])
        assert after == before
        for port in ports:
            assert _participant_is_principal(
                duthost, port, profile["primary_ckn"])
    finally:
        if neighbor_updated:
            _profile_update(
                neighbor["host"],
                environment["neighbor_profiles"][unsafe_port],
                mismatched_cak, mismatched_ckn,
                old_fallback_cak, old_fallback_ckn, is_fallback=True)
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "Fallback did not recover after unsafe preflight test"


def test_query_failure_retains_state_and_recovers(
        fallback_macsec_environment):
    """Retain the last MKA snapshot on query failure, then refresh it."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    port = next(iter(environment["links"]))
    asic = duthost.get_port_asic_instance(port)
    container = asic.get_docker_name("macsec")
    before_session, before_participants = get_mka_state(duthost, port)
    assert before_session and before_participants
    result = duthost.command(
        "docker exec {} pgrep -f '/var/run/{}'".format(container, port))
    pids = [int(pid) for pid in result["stdout_lines"]]
    assert pids, "Unable to locate wpa_supplicant for {}".format(port)

    try:
        duthost.command(
            "docker exec {} kill -STOP {}".format(
                container, " ".join(str(pid) for pid in pids)))
        assert wait_until(
            45, 3, 0,
            lambda: get_mka_state(
                duthost, port)[0].get("query_status") == "error",
        ), "MKA query failure was not published"
        failed_session, retained_participants = get_mka_state(duthost, port)
        assert retained_participants
        assert wait_until(
            10, 2, 6,
            lambda: get_mka_state(duthost, port) == (
                failed_session, retained_participants),
        ), "Retained MKA state changed while queries were failing"
        output = duthost.command(
            "show macsec --mka {}".format(port))["stdout"].lower()
        assert "error" in output
        assert "retained" in output or "stale" in output
        _assert_key_material_absent(output, environment["profile"])

        profile = environment["profile"]
        before_config = get_macsec_profile_config(
            duthost, port, profile["name"])
        blocked_cak, blocked_ckn = generate_macsec_key_pair(
            profile["cipher_suite"])
        _profile_update(
            duthost, profile["name"], profile["primary_cak"],
            profile["primary_ckn"], blocked_cak, blocked_ckn,
            namespace_option=get_namespace_option(duthost, port),
            expect_success=False)
        assert get_macsec_profile_config(
            duthost, port, profile["name"]) == before_config
    finally:
        duthost.command(
            "docker exec {} kill -CONT {}".format(
                container, " ".join(str(pid) for pid in pids)),
            module_ignore_errors=True,
        )

    assert wait_until(
        MKA_CONVERGE_TIMEOUT, 3, 0,
        _environment_is_healthy, environment,
    ), "MKA state did not recover after query resumed"
    recovered_session, _ = get_mka_state(duthost, port)
    assert recovered_session["last_updated"] != failed_session["last_updated"]


def test_disable_and_macsecmgrd_restart_lifecycle(
        fallback_macsec_environment):
    """Delete state on port disable and rebuild it after macsecmgrd restart."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    port = next(iter(environment["links"]))

    disable_macsec_port(duthost, port)
    try:
        assert wait_until(
            MKA_TIMEOUT, 2, 0,
            lambda: get_mka_state(duthost, port) == ({}, {}),
        ), "MKA operational rows remained after explicit port disable"
    finally:
        enable_macsec_port(duthost, port, profile["name"])

    assert wait_until(
        MKA_CONVERGE_TIMEOUT, 3, 0,
        _environment_is_healthy, environment,
    ), "MKA did not recover after port re-enable"

    asic = duthost.get_port_asic_instance(port)
    container = asic.get_docker_name("macsec")
    duthost.command(
        "docker exec {} pkill -9 -x macsecmgrd".format(container))
    assert wait_until(
        60, 2, 0,
        lambda: "RUNNING" in duthost.command(
            "docker exec {} supervisorctl status macsecmgrd".format(
                container),
            module_ignore_errors=True,
        ).get("stdout", ""),
    ), "macsecmgrd did not restart"
    assert wait_until(
        MKA_CONVERGE_TIMEOUT, 3, 0,
        _environment_is_healthy, environment,
    ), "MKA operational rows did not rebuild after macsecmgrd restart"


def test_both_invalid_tears_down_and_fallback_recovers(
        fallback_macsec_environment):
    """Lose both shared CAKs, then recover service with the fallback CA."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    port, neighbor = next(iter(environment["links"].items()))
    neighbor_profile = environment["neighbor_profiles"][port]
    invalid_primary_cak, invalid_primary_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    invalid_fallback_cak, invalid_fallback_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    primary_updated = False
    fallback_updated = False

    try:
        _profile_update(
            neighbor["host"], neighbor_profile,
            profile["primary_cak"], profile["primary_ckn"],
            invalid_primary_cak, invalid_primary_ckn)
        primary_updated = True
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _participant_is_principal,
            duthost, port, profile["fallback_ckn"],
        ), "Fallback did not carry the port after primary mismatch"

        _profile_update(
            neighbor["host"], neighbor_profile,
            profile["fallback_cak"], profile["fallback_ckn"],
            invalid_fallback_cak, invalid_fallback_ckn,
            is_fallback=True)
        fallback_updated = True
        assert wait_until(
            MKA_TIMEOUT, 2, 0,
            lambda: (
                not duthost.iface_macsec_ok(port)
                and not neighbor["host"].iface_macsec_ok(neighbor["port"])
            ),
        ), "Controlled port remained up with both CAKs mismatched"

        _profile_update(
            neighbor["host"], neighbor_profile,
            invalid_fallback_cak, invalid_fallback_ckn,
            profile["fallback_cak"], profile["fallback_ckn"],
            is_fallback=True)
        fallback_updated = False
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            lambda: (
                duthost.iface_macsec_ok(port)
                and neighbor["host"].iface_macsec_ok(neighbor["port"])
                and _participant_is_principal(
                    duthost, port, profile["fallback_ckn"])
            ),
        ), "Controlled port did not recover on the matching fallback CA"
    finally:
        if fallback_updated:
            _profile_update(
                neighbor["host"], neighbor_profile,
                invalid_fallback_cak, invalid_fallback_ckn,
                profile["fallback_cak"], profile["fallback_ckn"],
                is_fallback=True)
        if primary_updated:
            _profile_update(
                neighbor["host"], neighbor_profile,
                invalid_primary_cak, invalid_primary_ckn,
                profile["primary_cak"], profile["primary_ckn"])
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "Primary/fallback state did not recover after mismatch test"
