import json
import logging
import re

import pytest
from passlib.hash import cisco_type7

from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_config_helper import (
    delete_macsec_profile,
    disable_macsec_port,
    enable_macsec_port,
    generate_macsec_key_pair,
    generate_macsec_profile,
    set_macsec_profile,
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
    validate_mka_snapshot,
)
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]

FALLBACK_PROFILE = "MACSEC_PROFILE_FALLBACK"
MKA_TIMEOUT = 30
MKA_CONVERGE_TIMEOUT = 180


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


def _profile_update(host, profile_name, old_ckn, new_cak, new_ckn,
                    namespace_option=None, expect_success=True):
    if namespace_option is None:
        namespace_options = [""]
        if host.is_multi_asic:
            namespace_options = [
                "-n {}".format(namespace)
                for namespace in host.get_asic_namespace_list()
            ]
    else:
        namespace_options = [namespace_option]

    results = []
    for option in namespace_options:
        command = (
            "config macsec {} profile update {} "
            "--old_ckn {} --new_ckn {} --new_cak {}"
        ).format(option, profile_name, old_ckn, new_ckn, new_cak)
        result = host.command(command, module_ignore_errors=True)
        results.append(result)
        if expect_success:
            assert not result["failed"], (
                "MACsec profile update failed on {}: {}"
            ).format(host.hostname, result)
        else:
            assert result["failed"], (
                "MACsec profile update unexpectedly succeeded on {}"
            ).format(host.hostname)
    return results


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
        environment, principal_ckn=None, require_all_live=True):
    profile = environment["profile"]
    principal_ckn = principal_ckn or profile["primary_ckn"]
    for port in environment["links"]:
        session, participants = get_mka_state(
            environment["duthost"], port)
        errors = validate_mka_snapshot(
            session, participants, profile, principal_ckn,
            require_all_live=require_all_live)
        if errors:
            logger.info("MKA state on %s is not ready: %s", port, errors)
            return False
    return True


def _replace_bound_profile(host, port, profile_name, profile, priority):
    disable_macsec_port(host, port)
    delete_macsec_profile(host, profile_name)
    _set_profile(host, profile_name, profile, priority)
    enable_macsec_port(host, port, profile_name)


def _start_ping(host, port, destination, suffix):
    path = "/tmp/macsec_fallback_{}_{}.log".format(port, suffix)
    host.command("rm -f {}".format(path), module_ignore_errors=True)
    command = "{} ping -q -i 0.1 {}".format(
        get_ipnetns_prefix(host, port), destination)
    result = host.shell(
        "nohup {} > {} 2>&1 < /dev/null & echo $!".format(command, path))
    return {
        "host": host,
        "path": path,
        "pid": int(result["stdout_lines"][-1]),
    }


def _stop_ping(ping):
    ping["host"].command(
        "sudo kill -INT {}".format(ping["pid"]), module_ignore_errors=True)

    def _has_summary():
        result = ping["host"].command(
            "cat {}".format(ping["path"]), module_ignore_errors=True)
        return "packet loss" in result.get("stdout", "")

    assert wait_until(15, 1, 0, _has_summary), (
        "Continuous ping did not produce a summary: {}"
    ).format(ping)
    output = ping["host"].command("cat {}".format(ping["path"]))["stdout"]
    ping["host"].command(
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
    for port, neighbor in environment["links"].items():
        if port not in upstream_links:
            continue
        link = upstream_links[port]
        assert not duthost.command(
            "{} ping -c 3 {}".format(
                get_ipnetns_prefix(duthost, port),
                link["local_ipv4_addr"]),
            module_ignore_errors=True,
        )["failed"], "Unable to warm the DUT-to-neighbor traffic path"
        assert not neighbor["host"].command(
            "{} ping -c 3 {}".format(
                get_ipnetns_prefix(neighbor["host"], neighbor["port"]),
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
    pytest.skip("Fallback CAK continuity requires a controlled routed link")


@pytest.fixture(scope="module")
def fallback_macsec_environment(
        macsec_duthost, ctrl_links, macsec_profile, get_port_profile_name):
    """Install one dual-CA profile on every SONiC controlled link."""
    links = {
        port: neighbor
        for port, neighbor in ctrl_links.items()
        if not isinstance(neighbor["host"], EosHost)
    }
    if not links:
        pytest.skip("Fallback CAK tests require a SONiC neighbor")

    hosts = [macsec_duthost]
    hosts.extend(neighbor["host"] for neighbor in links.values())
    if not all(mka_state_cli_supported(host) for host in hosts):
        pytest.skip("SONiC image does not expose fallback CAK/MKA state CLI")

    profile = generate_macsec_profile(
        next(iter(links)),
        cipher_suite=macsec_profile["cipher_suite"],
        priority=macsec_profile["priority"],
        policy=macsec_profile["policy"],
        send_sci=macsec_profile["send_sci"],
        rekey_period=macsec_profile["rekey_period"],
        include_fallback=True,
    )
    profile["name"] = FALLBACK_PROFILE
    original_profiles = {
        port: get_port_profile_name(port)
        for port in links
    }
    neighbor_profiles = {
        port: "{}_{}".format(FALLBACK_PROFILE, port)
        for port in links
    }
    neighbor_priorities = {}

    try:
        for port, neighbor in links.items():
            disable_macsec_port(macsec_duthost, port)
            disable_macsec_port(neighbor["host"], neighbor["port"])

        delete_macsec_profile(macsec_duthost, FALLBACK_PROFILE)
        for port, neighbor in links.items():
            delete_macsec_profile(
                neighbor["host"], neighbor_profiles[port])

        _set_profile(macsec_duthost, FALLBACK_PROFILE, profile)
        for index, (port, neighbor) in enumerate(links.items()):
            priority = profile["priority"] + (1 if index % 2 else -1)
            neighbor_priorities[port] = priority
            _set_profile(
                neighbor["host"], neighbor_profiles[port], profile, priority)

        for port, neighbor in links.items():
            enable_macsec_port(macsec_duthost, port, FALLBACK_PROFILE)
            enable_macsec_port(
                neighbor["host"], neighbor["port"], neighbor_profiles[port])

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
        }
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 5, 0,
            _environment_is_healthy, environment,
        ), "Dual-CA MKA operational state did not become healthy"
        yield environment
    finally:
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
                neighbor["host"], neighbor["port"], original_profiles[port])

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
        _profile_update(
            duthost, profile["name"], old_ckn, new_cak, new_ckn)
        dut_updated = True
        profile["primary_cak"] = new_cak
        profile["primary_ckn"] = new_ckn
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment, profile["fallback_ckn"],
            False,
        ), "Fallback did not become principal after one-sided primary rotation"

        for port, neighbor in environment["links"].items():
            _profile_update(
                neighbor["host"], environment["neighbor_profiles"][port],
                old_ckn, new_cak, new_ckn)
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
                    duthost, profile["name"], new_ckn, old_cak, old_ckn)
            for port in updated_neighbors:
                neighbor = environment["links"][port]
                _profile_update(
                    neighbor["host"],
                    environment["neighbor_profiles"][port],
                    new_ckn, old_cak, old_ckn)
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

    try:
        _profile_update(
            duthost, profile["name"], old_ckn, new_cak, new_ckn)
        dut_updated = True
        profile["fallback_cak"] = new_cak
        profile["fallback_ckn"] = new_ckn
        for port in environment["links"]:
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 3, 0,
                _participant_is_principal,
                duthost, port, profile["primary_ckn"],
            ), "Primary lost ownership during fallback rotation"

        for port, neighbor in environment["links"].items():
            _profile_update(
                neighbor["host"], environment["neighbor_profiles"][port],
                old_ckn, new_cak, new_ckn)
            updated_neighbors.append(port)
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "Replacement fallback did not converge"
    finally:
        try:
            for ping in traffic:
                _stop_ping(ping)
        finally:
            if dut_updated:
                _profile_update(
                    duthost, profile["name"], new_ckn, old_cak, old_ckn)
            for port in updated_neighbors:
                neighbor = environment["links"][port]
                _profile_update(
                    neighbor["host"],
                    environment["neighbor_profiles"][port],
                    new_ckn, old_cak, old_ckn)
            profile["fallback_cak"] = old_cak
            profile["fallback_ckn"] = old_ckn
            assert wait_until(
                MKA_CONVERGE_TIMEOUT, 3, 0,
                _environment_is_healthy, environment,
            ), "Original fallback did not recover after rotation test"


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
            duthost, temp_name, primary_ckn, new_cak, new_ckn,
            namespace_option=namespace)
        config = get_macsec_profile_config(duthost, port, temp_name)
        assert config["primary_ckn"].lower() == new_ckn.lower()

        before = dict(config)
        _profile_update(
            duthost, temp_name, new_ckn, new_cak, new_ckn,
            namespace_option=namespace, expect_success=False)
        _profile_update(
            duthost, temp_name, "00" * (len(new_ckn) // 2),
            new_cak, primary_ckn,
            namespace_option=namespace, expect_success=False)
        _profile_update(
            duthost, temp_name, new_ckn, fallback_cak, fallback_ckn,
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
            old_fallback_ckn, mismatched_cak, mismatched_ckn)
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
            duthost, profile["name"], profile["primary_ckn"],
            replacement_cak, replacement_ckn,
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
                mismatched_ckn, old_fallback_cak, old_fallback_ckn)
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
    priority = environment["neighbor_priorities"][port]
    invalid_profile = generate_macsec_profile(
        port,
        cipher_suite=profile["cipher_suite"],
        priority=priority,
        policy=profile["policy"],
        send_sci=profile["send_sci"],
        rekey_period=profile["rekey_period"],
        include_fallback=True,
    )
    invalid_profile["name"] = neighbor_profile

    try:
        _replace_bound_profile(
            neighbor["host"], neighbor["port"], neighbor_profile,
            invalid_profile, priority)
        assert wait_until(
            MKA_TIMEOUT, 2, 0,
            lambda: (
                not duthost.iface_macsec_ok(port)
                and not neighbor["host"].iface_macsec_ok(neighbor["port"])
            ),
        ), "Controlled port remained up with both CAKs mismatched"

        fallback_only_match = dict(invalid_profile)
        fallback_only_match["fallback_cak"] = profile["fallback_cak"]
        fallback_only_match["fallback_ckn"] = profile["fallback_ckn"]
        _replace_bound_profile(
            neighbor["host"], neighbor["port"], neighbor_profile,
            fallback_only_match, priority)
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
        _replace_bound_profile(
            neighbor["host"], neighbor["port"], neighbor_profile,
            profile, priority)
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 3, 0,
            _environment_is_healthy, environment,
        ), "Primary/fallback state did not recover after mismatch test"
