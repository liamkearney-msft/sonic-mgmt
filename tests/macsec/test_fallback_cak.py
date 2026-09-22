import json
import logging
import re
import sys
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
    get_macsec_counters,
)
from tests.common.macsec.mka_state_helper import (
    active_key_state,
    bounded_transition_stage_timeout,
    cleanup_all,
    classify_macsec_teardown,
    crossed_role_peer_key_server_supported,
    eos_key_deletion_status,
    eos_key_replacement_status,
    find_secret_fields,
    fresh_mka_state_published,
    get_macsec_ingress_sc_state,
    get_macsec_max_sa_per_sc,
    get_macsec_profile_config,
    get_macsec_teardown_state,
    get_mka_state,
    get_namespace_option,
    final_new_key_stable,
    macsec_sa_lifecycle_sample,
    macsecmgrd_restart_command,
    macsecmgrd_restart_ready,
    mka_hello_timeout_seconds,
    mka_state_cli_supported,
    parse_eos_profile_ckns,
    parse_eos_mka_participants,
    parse_wpa_mka_participants,
    quiescence_budget_seconds,
    remaining_transition_seconds,
    remaining_link_items,
    select_independent_port_pair,
    validate_direct_actor_state,
    validate_macsec_sa_lifecycle_sample,
    validate_make_before_break_samples,
    validate_pre_distsak_lifecycle,
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
MKA_TRANSITION_CONVERGENCE_TIMEOUT = 30
MKA_LIVENESS_INTERVALS = 4
MKA_ACTOR_READY_INTERVALS = 4
MKA_ADVERTISEMENT_READY_INTERVALS = 5
MKA_PEER_FOLLOW_INTERVALS = 8
MKA_OBSERVATION_POLL_SECONDS = 1
MKA_STATE_PUBLISH_TIMEOUT = 30
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


def _get_eos_profile_ckns(host, profile_name):
    result = host.eos_command(
        commands=["show running-config section mac security"])
    output = result.get("stdout", [""])[0]
    if not isinstance(output, str):
        return set()
    return parse_eos_profile_ckns(output, profile_name)


def _get_peer_profile_ckns(neighbor, profile_name):
    if isinstance(neighbor["host"], EosHost):
        return _get_eos_profile_ckns(
            neighbor["host"], profile_name)
    config = get_macsec_profile_config(
        neighbor["host"], neighbor["port"], profile_name)
    return {
        value.lower()
        for field in ("primary_ckn", "fallback_ckn")
        for value in (config.get(field),)
        if value
    }


def _replace_peer_profile(neighbor, profile_name, profile, priority):
    disable_macsec_port(neighbor["host"], neighbor["port"])
    delete_macsec_profile(neighbor["host"], profile_name)
    _set_profile(neighbor["host"], profile_name, profile, priority)
    enable_macsec_port(neighbor["host"], neighbor["port"], profile_name)


def _profile_with_replacement(
        profile, new_cak, new_ckn, is_fallback=False):
    updated = dict(profile)
    role = "fallback" if is_fallback else "primary"
    updated["{}_cak".format(role)] = new_cak
    updated["{}_ckn".format(role)] = new_ckn
    return updated


def _eos_replacement_errors(
        neighbor, profile_name, old_ckn, new_ckn,
        expected_profile, required_live_ckns):
    participants = _get_eos_participants(
        neighbor["host"], neighbor["port"])
    configured_ckns = _get_eos_profile_ckns(
        neighbor["host"], profile_name)
    return eos_key_replacement_status(
        configured_ckns,
        participants,
        old_ckn,
        new_ckn,
        required_live_ckns=required_live_ckns,
        controlled_port=neighbor["host"].iface_macsec_ok(
            neighbor["port"]),
        expected_configured_ckns={
            expected_profile["primary_ckn"],
            expected_profile["fallback_ckn"],
        },
    )


def _eos_deletion_errors(
        neighbor, profile_name, deleted_ckn, remaining_ckns):
    return eos_key_deletion_status(
        _get_eos_profile_ckns(neighbor["host"], profile_name),
        _get_eos_participants(neighbor["host"], neighbor["port"]),
        deleted_ckn,
        remaining_ckns,
        controlled_port=neighbor["host"].iface_macsec_ok(
            neighbor["port"]),
    )


def _replace_peer_key_and_verify(
        environment, port, old_cak, old_ckn, new_cak, new_ckn,
        is_fallback=False, required_live_ckns=(),
        hot_update_failure="fail"):
    """Replace a peer key and prove the old runtime actor stopped."""
    neighbor = environment["links"][port]
    profile_name = environment["neighbor_profiles"][port]
    current_profile = environment["peer_profiles"][port]
    updated_profile = _profile_with_replacement(
        current_profile, new_cak, new_ckn,
        is_fallback=is_fallback)

    action_started = time.monotonic()
    _profile_update(
        neighbor["host"], profile_name,
        old_cak, old_ckn, new_cak, new_ckn,
        is_fallback=is_fallback)

    if isinstance(neighbor["host"], EosHost):
        def _replacement_ready():
            return not _eos_replacement_errors(
                neighbor, profile_name, old_ckn, new_ckn,
                updated_profile, required_live_ckns)

        if not wait_until(
                _transition_stage_timeout(
                    environment, port,
                    MKA_ADVERTISEMENT_READY_INTERVALS,
                    action_started),
                1, 0, _replacement_ready):
            transition_errors = _eos_replacement_errors(
                neighbor, profile_name, old_ckn, new_ckn,
                updated_profile, required_live_ckns)
            _profile_update(
                neighbor["host"], profile_name,
                new_cak, new_ckn, old_cak, old_ckn,
                is_fallback=is_fallback)
            rollback_live_ckns = tuple(
                old_ckn if ckn.lower() == new_ckn.lower() else ckn
                for ckn in required_live_ckns
            )

            def _rollback_ready():
                return not _eos_replacement_errors(
                    neighbor, profile_name, new_ckn, old_ckn,
                    current_profile, rollback_live_ckns)

            rollback_ready = wait_until(
                _transition_stage_timeout(
                    environment, port,
                    MKA_ADVERTISEMENT_READY_INTERVALS,
                    time.monotonic()),
                1, 0, _rollback_ready)
            assert rollback_ready, (
                "EOS hot key replacement and key-line-only rollback both "
                "failed; transition={}, rollback={}"
            ).format(
                transition_errors,
                _eos_replacement_errors(
                    neighbor, profile_name, new_ckn, old_ckn,
                    current_profile, rollback_live_ckns))
            message = (
                "cEOS hot key replacement did not converge without profile "
                "detach/rebind: {}"
            ).format(transition_errors)
            if hot_update_failure == "skip":
                pytest.skip(message)
            raise AssertionError(message)

    environment["peer_profiles"][port] = updated_profile
    return updated_profile


def _delete_peer_key_and_verify(
        environment, port, cak, ckn, remaining_ckns,
        is_fallback=False, hot_update_failure="fail"):
    """Delete one peer actor and prove it is absent before timing DUT expiry."""
    neighbor = environment["links"][port]
    profile_name = environment["neighbor_profiles"][port]
    action_started = time.monotonic()
    delete_runtime_macsec_key(
        neighbor["host"], neighbor["port"], profile_name, cak, ckn,
        is_fallback=is_fallback)

    if isinstance(neighbor["host"], EosHost):
        def _deleted():
            return not _eos_deletion_errors(
                neighbor, profile_name, ckn, remaining_ckns)

        if not wait_until(
                _transition_stage_timeout(
                    environment, port, MKA_LIVENESS_INTERVALS,
                    action_started),
                1, 0, _deleted):
            transition_errors = _eos_deletion_errors(
                neighbor, profile_name, ckn, remaining_ckns)
            add_runtime_macsec_key(
                neighbor["host"], neighbor["port"], profile_name,
                cak, ckn, is_fallback=is_fallback)
            expected_profile = environment["peer_profiles"][port]

            def _rollback_ready():
                return not _eos_replacement_errors(
                    neighbor, profile_name, "__deleted__", ckn,
                    expected_profile, tuple(remaining_ckns) + (ckn,))

            rollback_ready = wait_until(
                _transition_stage_timeout(
                    environment, port,
                    MKA_ADVERTISEMENT_READY_INTERVALS,
                    time.monotonic()),
                1, 0, _rollback_ready)
            assert rollback_ready, (
                "EOS direct key deletion and key-line-only rollback both "
                "failed; transition={}, rollback={}"
            ).format(
                transition_errors,
                _eos_replacement_errors(
                    neighbor, profile_name, "__deleted__", ckn,
                    expected_profile, tuple(remaining_ckns) + (ckn,)))
            message = (
                "cEOS direct key deletion left the old runtime actor; "
                "profile detach/rebind is prohibited: {}"
            ).format(transition_errors)
            if hot_update_failure == "skip":
                pytest.skip(message)
            raise AssertionError(message)
    else:
        assert wait_until(
            _transition_stage_timeout(
                environment, port, MKA_LIVENESS_INTERVALS,
                action_started),
            1, 0,
            lambda: ckn.lower() not in _runtime_participants(
                neighbor["host"], neighbor["port"]),
        ), "Deleted peer CKN remains in runtime participants"


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


def _snapshot_active_key_state(environment, ports):
    snapshot = {}
    diagnostics = {}
    for port in ports:
        neighbor = environment["links"][port]
        session, participants = get_mka_state(
            environment["duthost"], port)
        _, egress_sc, _, egress_sa, _ = get_appl_db(
            environment["duthost"], port,
            neighbor["host"], neighbor["port"])
        ingress_scs = get_macsec_ingress_sc_state(
            environment["duthost"], port)
        assert egress_sc, "No egress SC on {}".format(port)
        encoding_an = int(egress_sc["encoding_an"])
        assert encoding_an in egress_sa, (
            "No active egress SA on {} for AN {}"
        ).format(port, encoding_an)
        assert egress_sa[encoding_an].get("sak"), \
            "Active egress SA on {} has no SAK".format(port)
        ingress_errors = validate_point_to_point_ingress_sc(
            ingress_scs)
        assert not ingress_errors, (
            "Invalid ingress SC state on {}: {}"
        ).format(port, ingress_errors)
        snapshot[port] = active_key_state(
            session, participants, egress_sc, egress_sa, ingress_scs)
        diagnostics[port] = {
            "keys_distributed": session.get("keys_distributed"),
            "keys_received": session.get("keys_received"),
        }
    return snapshot, diagnostics


def _snapshot_sa_lifecycle(environment, port):
    neighbor = environment["links"][port]
    session, participants = get_mka_state(
        environment["duthost"], port)
    port_table, egress_sc, _, egress_sas, _ = get_appl_db(
        environment["duthost"], port,
        neighbor["host"], neighbor["port"])
    ingress_scs = get_macsec_ingress_sc_state(
        environment["duthost"], port)
    key_state = active_key_state(
        session, participants, egress_sc, egress_sas, ingress_scs)
    return macsec_sa_lifecycle_sample(
        port_table.get("enable"), key_state)


def _sa_identity_changed(before, after):
    return any(
        before[port] != after[port]
        for port in before
    )


def _wait_for_stable_active_key_state(environment, ports):
    session, _ = get_mka_state(environment["duthost"], ports[0])
    poll_seconds = max(1, mka_hello_timeout_seconds(session, 1))
    settle_seconds = mka_hello_timeout_seconds(session, 6)
    started = time.monotonic()
    previous, _ = _snapshot_active_key_state(environment, ports)
    snapshot_seconds = max(1, time.monotonic() - started)
    deadline = time.monotonic() + quiescence_budget_seconds(
        settle_seconds, snapshot_seconds, poll_seconds)
    last_change = time.monotonic()
    stable_polls = 0

    while time.monotonic() < deadline:
        sample_started = time.monotonic()
        current, _ = _snapshot_active_key_state(environment, ports)
        sample_finished = time.monotonic()
        if current == previous:
            stable_polls += 1
        else:
            previous = current
            stable_polls = 0
            last_change = sample_finished
        if (stable_polls >= 2
                and sample_finished - last_change >= settle_seconds):
            return previous
        remaining_poll = poll_seconds - (
            sample_finished - sample_started)
        if remaining_poll > 0:
            time.sleep(remaining_poll)

    raise AssertionError(
        "Active SAK state did not quiesce for {}s; measured snapshot "
        "cost={:.1f}s, final state={}".format(
            settle_seconds, snapshot_seconds, previous))


def _protocol_timeout(environment, port, intervals):
    session, _ = get_mka_state(environment["duthost"], port)
    return mka_hello_timeout_seconds(session, intervals)


def _transition_stage_timeout(
        environment, port, intervals, action_started):
    return bounded_transition_stage_timeout(
        _protocol_timeout(environment, port, intervals),
        action_started,
        time.monotonic(),
        MKA_TRANSITION_CONVERGENCE_TIMEOUT,
        MKA_OBSERVATION_POLL_SECONDS,
    )


def _wait_direct_actor_ready(
        environment, port, host, host_port, ckn,
        is_primary, is_principal, is_key_server, is_elected,
        action_started, intervals=MKA_ACTOR_READY_INTERVALS,
        absent_ckn=None, description="MKA actor"):
    errors = [None]

    def _ready():
        errors[0] = validate_direct_actor_state(
            _direct_participants(host, host_port),
            ckn,
            is_primary,
            is_principal,
            is_key_server,
            is_elected,
            absent_ckn=absent_ckn,
        )
        return not errors[0]

    timeout = _transition_stage_timeout(
        environment, port, intervals, action_started)
    if _ready():
        return
    assert timeout > 0 and wait_until(
        timeout, MKA_OBSERVATION_POLL_SECONDS, 0, _ready,
    ), "{} did not become ready within the transition budget: {}".format(
        description, errors[0])


def _wait_peer_follow(
        environment, port, neighbor, ckn, action_started,
        expected_primary, inherited_lifecycle,
        absent_ckn=None, description="peer follow"):
    marker = "Following key server onto CKN {}".format(ckn.lower())
    marker_before = (
        None if isinstance(neighbor["host"], EosHost)
        else _mka_log_marker_count(
            neighbor["host"], neighbor["port"], marker)
    )
    diagnostics = [None]
    samples = []
    following_index = [None]
    pending_change_index = [None]
    previous_post_follow = [None]

    def _followed():
        sample = _snapshot_sa_lifecycle(environment, port)
        samples.append(sample)
        sample_errors = validate_macsec_sa_lifecycle_sample(sample)
        assert not sample_errors, (
            "MACsec SA lifecycle became unusable during peer follow: {}"
        ).format(sample_errors)

        if isinstance(neighbor["host"], EosHost):
            peer_ready = _peer_ckn_transition_is_operational(
                neighbor, ckn, absent_ckn=absent_ckn)
            diagnostics[0] = _direct_participants(
                neighbor["host"], neighbor["port"])
            following_seen = False
        else:
            participants = _runtime_participants(
                neighbor["host"], neighbor["port"])
            following_seen = _mka_log_marker_count(
                neighbor["host"], neighbor["port"], marker) > marker_before
            peer_ready = not validate_direct_actor_state(
                participants,
                ckn,
                expected_primary,
                True,
                False,
                True,
                absent_ckn=absent_ckn,
            )
            diagnostics[0] = {
                "participants": participants,
                "following_log_seen": following_seen,
            }

        key_changed = (
            sample.get("tx_active")
            != inherited_lifecycle.get("tx_active")
            or sample.get("rx_active")
            != inherited_lifecycle.get("rx_active")
        )
        boundary_seen = following_seen or (peer_ready and key_changed)
        if following_index[0] is None:
            if boundary_seen:
                following_index[0] = (
                    pending_change_index[0]
                    if pending_change_index[0] is not None
                    else len(samples) - 1)
            elif key_changed:
                if pending_change_index[0] is None:
                    pending_change_index[0] = len(samples) - 1
                    return False
                raise AssertionError(
                    "Active KI/AN changed more than one poll before peer "
                    "Following/readiness")
            else:
                pre_errors = validate_pre_distsak_lifecycle(
                    inherited_lifecycle, sample)
                assert not pre_errors, (
                    "Inherited active KI/AN was not preserved before peer "
                    "Following: {}"
                ).format(pre_errors)
                return False

        if not peer_ready:
            return False
        if final_new_key_stable(
                inherited_lifecycle,
                previous_post_follow[0],
                sample):
            lifecycle_errors = validate_make_before_break_samples(
                inherited_lifecycle, samples, following_index[0])
            assert not lifecycle_errors, (
                "Invalid MACsec make-before-break lifecycle: {}"
            ).format(lifecycle_errors)
            return True
        previous_post_follow[0] = sample
        return False

    if _followed():
        return
    timeout = _transition_stage_timeout(
        environment, port, MKA_PEER_FOLLOW_INTERVALS, action_started)
    assert timeout > 0 and wait_until(
        timeout, MKA_OBSERVATION_POLL_SECONDS, 0, _followed,
    ), "{} did not converge within the transition budget: {}".format(
        description, diagnostics[0])


def _wait_dut_owner_then_peer_follow(
        environment, port, neighbor, ckn, action_started,
        expected_primary,
        absent_ckn=None, description="CKN ownership"):
    _wait_direct_actor_ready(
        environment,
        port,
        environment["duthost"],
        port,
        ckn,
        expected_primary,
        True,
        True,
        True,
        action_started,
        absent_ckn=absent_ckn,
        description="{} DUT authoritative actor".format(description),
    )
    inherited_lifecycle = _snapshot_sa_lifecycle(
        environment, port)
    _wait_peer_follow(
        environment,
        port,
        neighbor,
        ckn,
        action_started,
        expected_primary,
        inherited_lifecycle,
        absent_ckn=absent_ckn,
        description="{} remote follow".format(description),
    )


def _wait_peer_actor_then_dut_owner(
        environment, port, neighbor, ckn, action_started,
        expected_primary,
        absent_ckn=None, description="peer actor"):
    is_eos = isinstance(neighbor["host"], EosHost)
    _wait_direct_actor_ready(
        environment,
        port,
        neighbor["host"],
        neighbor["port"],
        ckn,
        None if is_eos else expected_primary,
        None if is_eos else True,
        None if is_eos else False,
        None if is_eos else True,
        action_started,
        intervals=(
            MKA_ADVERTISEMENT_READY_INTERVALS
            if is_eos else MKA_ACTOR_READY_INTERVALS),
        absent_ckn=absent_ckn,
        description="{} local readiness".format(description),
    )
    _wait_dut_owner_then_peer_follow(
        environment,
        port,
        neighbor,
        ckn,
        action_started,
        expected_primary,
        absent_ckn=absent_ckn,
        description=description,
    )


def _wait_authoritative_peer_then_dut_follow(
        environment, port, neighbor, ckn, action_started,
        dut_expected_primary, description="peer key-server ownership"):
    is_eos = isinstance(neighbor["host"], EosHost)
    _wait_direct_actor_ready(
        environment,
        port,
        neighbor["host"],
        neighbor["port"],
        ckn,
        None if is_eos else True,
        None if is_eos else True,
        None if is_eos else True,
        None if is_eos else True,
        action_started,
        intervals=(
            MKA_ADVERTISEMENT_READY_INTERVALS
            if is_eos else MKA_ACTOR_READY_INTERVALS),
        description="{} authoritative actor".format(description),
    )
    _wait_direct_actor_ready(
        environment,
        port,
        environment["duthost"],
        port,
        ckn,
        dut_expected_primary,
        True,
        False,
        True,
        action_started,
        intervals=MKA_PEER_FOLLOW_INTERVALS,
        description="{} DUT non-key-server follow".format(description),
    )


def _wait_fresh_mka_state(host, port, previous_last_updated):
    assert wait_until(
        MKA_STATE_PUBLISH_TIMEOUT, 2, 0,
        lambda: fresh_mka_state_published(
            get_mka_state(host, port)[0],
            previous_last_updated),
    ), "Fresh MKA STATE_DB was not published on {}".format(port)


def _wait_final_environment(
        environment, port, action_started, principal_ckn=None,
        description="MKA environment"):
    timeout = remaining_transition_seconds(
        action_started,
        time.monotonic(),
        MKA_TRANSITION_CONVERGENCE_TIMEOUT,
    )
    if _environment_is_healthy(environment, principal_ckn):
        return
    assert timeout > 0 and wait_until(
        timeout, MKA_OBSERVATION_POLL_SECONDS, 0,
        _environment_is_healthy, environment, principal_ckn,
    ), "{} did not become healthy within 30 seconds".format(description)


def _wait_final_link(
        environment, port, action_started, principal_ckn,
        description="MKA link"):
    timeout = remaining_transition_seconds(
        action_started,
        time.monotonic(),
        MKA_TRANSITION_CONVERGENCE_TIMEOUT,
    )
    if _selected_link_is_healthy(
            environment, port, principal_ckn):
        return
    assert timeout > 0 and wait_until(
        timeout, MKA_OBSERVATION_POLL_SECONDS, 0,
        _selected_link_is_healthy,
        environment, port, principal_ckn,
    ), "{} did not become healthy within 30 seconds".format(description)


def _redacted_diagnostics(environment, port):
    neighbor = environment["links"][port]
    session, participants = get_mka_state(
        environment["duthost"], port)
    peer = _direct_participants(
        neighbor["host"], neighbor["port"])
    return {
        "port": port,
        "session": session,
        "participants": participants,
        "peer_ckns": sorted(peer),
        "peer_participants": peer,
        "peer_controlled_port": neighbor["host"].iface_macsec_ok(
            neighbor["port"]),
    }


def _mka_log_marker_count(host, port, marker):
    container = host.get_port_asic_instance(port).get_docker_name("macsec")
    result = host.command(
        "(docker logs {} 2>&1 || true; cat /var/log/syslog) "
        "| grep -F -c -- '{}'".format(container, marker),
        module_ignore_errors=True,
        verbose=False,
    )
    try:
        return int(result.get("stdout", "0").strip() or 0)
    except ValueError:
        return 0


def _macsec_traffic_phase(environment, port, phase):
    neighbor = environment["links"][port]
    port_table, egress_sc, _, egress_sas, _ = get_appl_db(
        environment["duthost"], port,
        neighbor["host"], neighbor["port"])
    ingress_scs = get_macsec_ingress_sc_state(
        environment["duthost"], port)
    egress_counters, ingress_counters = get_macsec_counters(
        environment["duthost"], port)
    state, counters = _snapshot_active_key_state(environment, [port])

    def _redact_sa(sa):
        return {
            key: value for key, value in sa.items()
            if key.lower() not in ("sak", "auth_key", "salt")
        }

    return {
        "phase": phase,
        "timestamp": time.time(),
        "key_state": state[port],
        "counters": counters[port],
        "appl_port": port_table,
        "egress_sc": egress_sc,
        "egress_sas": {
            an: _redact_sa(sa) for an, sa in egress_sas.items()
        },
        "ingress_scs": [
            {
                "sci": entry["sci"],
                "sc": entry["sc"],
                "sas": {
                    an: _redact_sa(sa)
                    for an, sa in entry["sas"].items()
                },
            }
            for entry in ingress_scs
        ],
        "secy_counters": {
            "egress": egress_counters,
            "ingress": ingress_counters,
        },
        "wpa_log_marker_counts": {
            marker: _mka_log_marker_count(
                environment["duthost"], port, marker)
            for marker in (
                "principal participant (CP owner) set to CKN",
                "No CA has a live peer",
                "CP_CHANGE",
                "deferred rekey",
            )
        },
        "mka": _redacted_diagnostics(environment, port),
    }


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


def _peer_state_is_healthy(
        neighbor, profile, profile_name, principal_ckn,
        require_all_live=True):
    host = neighbor["host"]
    port = neighbor["port"]
    controlled_port = host.iface_macsec_ok(port)

    if isinstance(host, EosHost):
        participants = _get_eos_participants(host, port)
        return not validate_eos_mka_participants(
            participants, profile, controlled_port)

    if not controlled_port:
        return False
    peer_profile = dict(profile, name=profile_name)
    session, participants = get_mka_state(host, port)
    return not validate_mka_snapshot(
        session, participants, peer_profile, principal_ckn,
        require_all_live=require_all_live,
        require_principal=False)


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


def _peer_ckn_transition_is_operational(
        neighbor, expected_ckn, absent_ckn=None):
    host = neighbor["host"]
    port = neighbor["port"]
    participants = _direct_participants(host, port)
    if absent_ckn and absent_ckn.lower() in participants:
        return False
    expected = participants.get(expected_ckn.lower(), {})
    return (
        host.iface_macsec_ok(port)
        and expected.get("active")
        and expected.get("live_peers", 0) >= 1
        and expected.get("success", True)
        and not expected.get("failed", False)
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
        if (validate_peers
                and not _peer_state_is_healthy(
                    neighbor, profile,
                    environment["neighbor_profiles"][port],
                    principal_ckn, require_all_live)):
            logger.info(
                "Peer MKA state on %s is not ready", neighbor["port"])
            return False
    return True


def _selected_link_is_healthy(
        environment, port, principal_ckn,
        require_all_live=True):
    profile = environment["profile"]
    neighbor = environment["links"][port]
    session, participants = get_mka_state(
        environment["duthost"], port)
    return (
        not validate_mka_snapshot(
            session, participants, profile, principal_ckn,
            require_all_live=require_all_live)
        and _peer_state_is_healthy(
            neighbor,
            profile,
            environment["neighbor_profiles"][port],
            principal_ckn,
            require_all_live,
        )
    )


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


def _stop_ping(ping, assert_loss=True, phase_diagnostics=None):
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
    received_sequences = {
        int(sequence)
        for sequence in re.findall(r"icmp_seq[= ](\d+)", output)
    }
    missing_sequences = (
        sorted(set(range(1, transmitted + 1)) - received_sequences)
        if received_sequences else [])
    if assert_loss:
        assert transmitted >= 10, (
            "Traffic sample was too short:\n{}"
        ).format(output)
        assert transmitted == received and float(match.group(3)) == 0.0, (
            "Traffic loss detected during MACsec transition:\n{}\n"
            "Missing ICMP sequences: {}\nPhase diagnostics: {}"
        ).format(
            output, missing_sequences[:200], phase_diagnostics or [])
    return {
        "transmitted": transmitted,
        "received": received,
        "loss_percent": float(match.group(3)),
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


def _wpa_process_ready(host, container, port):
    result = host.command(
        "docker exec {} pgrep -f '/var/run/{}'".format(
            container, port),
        module_ignore_errors=True,
        verbose=False,
    )
    return (
        not result.get("failed")
        and bool(result.get("stdout_lines", []))
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
            _wpa_process_ready(duthost, container, port),
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


def test_primary_failure_rotation_and_recovery_are_hitless(
        fallback_macsec_environment, upstream_links):
    """Rotate one side first, fail over to fallback, then recover primary."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    old_cak = profile["primary_cak"]
    old_ckn = profile["primary_ckn"]
    new_cak, new_ckn = generate_macsec_key_pair(profile["cipher_suite"])
    traffic = []
    dut_updated = False
    updated_neighbors = []

    try:
        selected_port, selected_neighbor = _select_routed_link(
            environment, upstream_links)
        traffic = _start_bidirectional_traffic(
            environment, upstream_links)
        dut_state_before_pause = get_mka_state(
            duthost, selected_port)[0].get("last_updated")
        paused = _pause_macsecmgrd(duthost, selected_port)
        primary_removed = False
        try:
            removal_started = time.monotonic()
            delete_runtime_macsec_key(
                duthost, selected_port, profile["name"], old_cak, old_ckn)
            primary_removed = True
            assert wait_until(
                _transition_stage_timeout(
                    environment, selected_port,
                    MKA_LIVENESS_INTERVALS, removal_started),
                MKA_OBSERVATION_POLL_SECONDS, 0,
                lambda: old_ckn.lower() not in
                _runtime_participants(duthost, selected_port),
            ), "Deleted DUT primary CKN remains in runtime participants"

            expiry_started = time.monotonic()

            def _fallback_owns_remove_only_interval():
                participants = _runtime_participants(
                    duthost, selected_port)
                return (
                    old_ckn.lower() not in participants
                    and not validate_direct_actor_state(
                        participants,
                        profile["fallback_ckn"],
                        False,
                        True,
                        True,
                        True,
                        absent_ckn=old_ckn)
                    and _peer_ckn_transition_is_operational(
                        selected_neighbor, profile["fallback_ckn"])
                    and duthost.iface_macsec_ok(selected_port)
                )

            assert wait_until(
                _transition_stage_timeout(
                    environment, selected_port,
                    MKA_LIVENESS_INTERVALS, expiry_started),
                MKA_OBSERVATION_POLL_SECONDS, 0,
                _fallback_owns_remove_only_interval,
            ), "Fallback did not own the remove-only primary interval"

            add_started = time.monotonic()
            add_runtime_macsec_key(
                duthost, selected_port, profile["name"], old_cak, old_ckn)
            primary_removed = False
            _wait_dut_owner_then_peer_follow(
                environment,
                selected_port,
                selected_neighbor,
                old_ckn,
                add_started,
                True,
                description="DUT runtime primary restore",
            )
        finally:
            if primary_removed:
                add_runtime_macsec_key(
                    duthost, selected_port, profile["name"],
                    old_cak, old_ckn)
            _resume_macsecmgrd(duthost, paused)

        _wait_fresh_mka_state(
            duthost, selected_port, dut_state_before_pause)
        published_ready_started = time.monotonic()
        _wait_final_environment(
            environment, selected_port, published_ready_started,
            description="MKA state after DUT macsecmgrd resume")

        peer_state_before_pause = (
            None if isinstance(selected_neighbor["host"], EosHost)
            else get_mka_state(
                selected_neighbor["host"],
                selected_neighbor["port"])[0].get("last_updated")
        )
        peer_paused = (
            None if isinstance(selected_neighbor["host"], EosHost)
            else _pause_macsecmgrd(
                selected_neighbor["host"], selected_neighbor["port"])
        )
        peer_primary_removed = False
        try:
            _delete_peer_key_and_verify(
                environment, selected_port, old_cak, old_ckn,
                (profile["fallback_ckn"],),
                hot_update_failure="skip")
            peer_primary_removed = True
            peer_expiry_started = time.monotonic()

            def _peer_fallback_owns_remove_only_interval():
                return (
                    _peer_ckn_transition_is_operational(
                        selected_neighbor,
                        profile["fallback_ckn"],
                        absent_ckn=old_ckn)
                    and _participant_is_principal(
                        duthost, selected_port, profile["fallback_ckn"])
                )

            assert wait_until(
                _transition_stage_timeout(
                    environment, selected_port,
                    MKA_LIVENESS_INTERVALS, peer_expiry_started),
                MKA_OBSERVATION_POLL_SECONDS, 0,
                _peer_fallback_owns_remove_only_interval,
            ), "Peer fallback did not own its remove-only primary interval"

            peer_add_started = time.monotonic()
            add_runtime_macsec_key(
                selected_neighbor["host"], selected_neighbor["port"],
                environment["neighbor_profiles"][selected_port],
                old_cak, old_ckn)
            peer_primary_removed = False
            _wait_peer_actor_then_dut_owner(
                environment,
                selected_port,
                selected_neighbor,
                old_ckn,
                peer_add_started,
                True,
                description="peer runtime primary restore",
            )
        finally:
            if peer_primary_removed:
                add_runtime_macsec_key(
                    selected_neighbor["host"], selected_neighbor["port"],
                    environment["neighbor_profiles"][selected_port],
                    old_cak, old_ckn)
            if peer_paused:
                _resume_macsecmgrd(
                    selected_neighbor["host"], peer_paused)

        if peer_paused:
            _wait_fresh_mka_state(
                selected_neighbor["host"],
                selected_neighbor["port"],
                peer_state_before_pause)
            peer_published_ready_started = time.monotonic()
            _wait_final_environment(
                environment, selected_port, peer_published_ready_started,
                description="MKA state after peer macsecmgrd resume")
        else:
            _wait_final_environment(
                environment, selected_port, peer_add_started,
                description="MKA state after peer primary restore")

        dut_rotation_started = time.monotonic()
        _profile_update(
            duthost, profile["name"], old_cak, old_ckn, new_cak, new_ckn)
        dut_updated = True
        profile["primary_cak"] = new_cak
        profile["primary_ckn"] = new_ckn
        dut_rotation_timeout = remaining_transition_seconds(
            dut_rotation_started, time.monotonic(),
            MKA_TRANSITION_CONVERGENCE_TIMEOUT)
        assert dut_rotation_timeout > 0 and wait_until(
            dut_rotation_timeout, MKA_OBSERVATION_POLL_SECONDS, 0,
            _environment_is_healthy, environment, profile["fallback_ckn"],
            False, False,
        ), "Fallback did not become principal after one-sided primary rotation"
        for candidate_port in environment["links"]:
            _, participants = get_mka_state(duthost, candidate_port)
            assert old_ckn.lower() not in participants
            assert new_ckn.lower() in participants

        replacement_started = time.monotonic()
        _replace_peer_key_and_verify(
            environment, selected_port,
            old_cak, old_ckn, new_cak, new_ckn,
            hot_update_failure="skip")
        updated_neighbors.append(selected_port)
        _wait_peer_actor_then_dut_owner(
            environment,
            selected_port,
            selected_neighbor,
            new_ckn,
            replacement_started,
            True,
            absent_ckn=old_ckn,
            description="replacement primary",
        )
        _wait_final_link(
            environment, selected_port, replacement_started,
            new_ckn,
            description="selected replacement-primary link")
        _cleanup_traffic(traffic, assert_loss=True)
        traffic = []

        all_links_started = replacement_started
        for candidate_port, candidate_neighbor in remaining_link_items(
                environment["links"], selected_port):
            all_links_started = time.monotonic()
            _replace_peer_key_and_verify(
                environment, candidate_port,
                old_cak, old_ckn, new_cak, new_ckn,
                required_live_ckns=(
                    new_ckn, profile["fallback_ckn"]),
                hot_update_failure="skip")
            updated_neighbors.append(candidate_port)

        _wait_final_environment(
            environment, selected_port, all_links_started,
            principal_ckn=new_ckn,
            description="replacement primary on all links")
    finally:
        try:
            _cleanup_traffic(
                traffic, assert_loss=sys.exc_info()[0] is None)
        finally:
            cleanup_started = time.monotonic()
            if dut_updated:
                _profile_update(
                    duthost, profile["name"], new_cak, new_ckn,
                    old_cak, old_ckn)
            for candidate_port in updated_neighbors:
                cleanup_started = time.monotonic()
                _replace_peer_key_and_verify(
                    environment, candidate_port,
                    new_cak, new_ckn, old_cak, old_ckn,
                    required_live_ckns=(
                        old_ckn, profile["fallback_ckn"]))
            profile["primary_cak"] = old_cak
            profile["primary_ckn"] = old_ckn
            _wait_final_environment(
                environment, selected_port, cleanup_started,
                description="original primary cleanup")


def test_fallback_rotation_keeps_primary_and_traffic(
        fallback_macsec_environment, upstream_links):
    """Rotate the fallback participant while primary carries traffic."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    old_cak = profile["fallback_cak"]
    old_ckn = profile["fallback_ckn"]
    new_cak, new_ckn = generate_macsec_key_pair(profile["cipher_suite"])
    selected_port, _ = _select_routed_link(environment, upstream_links)
    selected_ports = [selected_port]
    traffic = []
    dut_updated = False
    updated_neighbors = []
    assert_no_forced_rekey = profile["rekey_period"] == 0
    initial_key_state = None
    initial_counters = None

    try:
        if assert_no_forced_rekey:
            initial_key_state = _wait_for_stable_active_key_state(
                environment, selected_ports)
            _, initial_counters = _snapshot_active_key_state(
                environment, selected_ports)
        traffic = _start_bidirectional_traffic(
            environment, upstream_links)
        dut_fallback_started = time.monotonic()
        _profile_update(
            duthost, profile["name"], old_cak, old_ckn, new_cak, new_ckn,
            is_fallback=True)
        dut_updated = True
        profile["fallback_cak"] = new_cak
        profile["fallback_ckn"] = new_ckn
        for candidate_port in environment["links"]:
            candidate_timeout = remaining_transition_seconds(
                dut_fallback_started,
                time.monotonic(),
                MKA_TRANSITION_CONVERGENCE_TIMEOUT,
            )
            assert candidate_timeout > 0 and wait_until(
                candidate_timeout, MKA_OBSERVATION_POLL_SECONDS, 0,
                _participant_is_principal,
                duthost, candidate_port, profile["primary_ckn"],
            ), "Primary lost ownership during fallback rotation"
        if assert_no_forced_rekey:
            current_state, current_counters = _snapshot_active_key_state(
                environment, selected_ports)
            assert current_state == initial_key_state, (
                "DUT fallback update changed the active SAK; "
                "counter delta context before={} after={}"
            ).format(initial_counters, current_counters)

        neighbor = environment["links"][selected_port]
        selected_transition_started = time.monotonic()
        _replace_peer_key_and_verify(
            environment, selected_port,
            old_cak, old_ckn, new_cak, new_ckn,
            is_fallback=True,
            required_live_ckns=(
                profile["primary_ckn"], new_ckn),
            hot_update_failure="skip")
        updated_neighbors.append(selected_port)
        selected_timeout = remaining_transition_seconds(
            selected_transition_started,
            time.monotonic(),
            MKA_TRANSITION_CONVERGENCE_TIMEOUT,
        )
        assert selected_timeout > 0 and wait_until(
            selected_timeout,
            MKA_OBSERVATION_POLL_SECONDS, 0,
            lambda: (
                _participant_is_principal(
                    duthost, selected_port, profile["primary_ckn"])
                and _peer_ckn_transition_is_operational(
                    neighbor, new_ckn, absent_ckn=old_ckn)
            ),
        ), "Selected link did not converge after fallback rotation"
        if assert_no_forced_rekey:
            current_state, current_counters = _snapshot_active_key_state(
                environment, selected_ports)
            assert current_state == initial_key_state, (
                "Selected peer fallback update changed the active SAK; "
                "counter delta context before={} after={}"
            ).format(initial_counters, current_counters)
        _cleanup_traffic(traffic, assert_loss=True)
        traffic = []

        for other_port in environment["links"]:
            if other_port == selected_port:
                continue
            _replace_peer_key_and_verify(
                environment, other_port,
                old_cak, old_ckn, new_cak, new_ckn,
                is_fallback=True,
                required_live_ckns=(
                    profile["primary_ckn"], new_ckn),
                hot_update_failure="skip")
            updated_neighbors.append(other_port)
        _wait_final_environment(
            environment, selected_port, time.monotonic(),
            description="replacement fallback")
    finally:
        try:
            _cleanup_traffic(
                traffic, assert_loss=sys.exc_info()[0] is None)
        finally:
            cleanup_started = time.monotonic()
            if dut_updated:
                _profile_update(
                    duthost, profile["name"], new_cak, new_ckn,
                    old_cak, old_ckn, is_fallback=True)
            for candidate_port in updated_neighbors:
                cleanup_started = time.monotonic()
                _replace_peer_key_and_verify(
                    environment, candidate_port,
                    new_cak, new_ckn, old_cak, old_ckn,
                    is_fallback=True,
                    required_live_ckns=(
                        profile["primary_ckn"], old_ckn))
            profile["fallback_cak"] = old_cak
            profile["fallback_ckn"] = old_ckn
            _wait_final_environment(
                environment, selected_port, cleanup_started,
                description="original fallback cleanup")


def test_crossed_roles_follow_key_server_primary(
        fallback_macsec_environment, upstream_links):
    """Verify crossed local roles follow the elected key server's primary."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    port, neighbor = _select_routed_link(environment, upstream_links)
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
    traffic = []

    try:
        crossed_started = time.monotonic()
        _replace_peer_profile(
            neighbor, peer_profile_name, crossed_profile, peer_priority)
        _wait_authoritative_peer_then_dut_follow(
            environment,
            port,
            neighbor,
            profile["fallback_ckn"],
            crossed_started,
            False,
            description="crossed-role peer primary",
        )

        assert wait_until(
            60, 2, 0,
            _peer_state_is_healthy,
            neighbor, crossed_profile, peer_profile_name,
            profile["fallback_ckn"],
        ), "Crossed-role peer session did not become operational"

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

        crossed_timeout = remaining_transition_seconds(
            crossed_started, time.monotonic(),
            MKA_TRANSITION_CONVERGENCE_TIMEOUT)
        assert crossed_timeout > 0 and wait_until(
            crossed_timeout,
            MKA_OBSERVATION_POLL_SECONDS, 0,
            _crossed_roles_converged,
        ), "Crossed primary/fallback roles did not converge: {}".format(
            _redacted_diagnostics(environment, port))

        traffic = _start_bidirectional_traffic(
            environment, upstream_links)
        time.sleep(3)
    finally:
        try:
            _cleanup_traffic(
                traffic, assert_loss=sys.exc_info()[0] is None)
        finally:
            cleanup_started = time.monotonic()
            _replace_peer_profile(
                neighbor, peer_profile_name, profile,
                environment["neighbor_priorities"][port])
            _wait_final_environment(
                environment, port, cleanup_started,
                description="normal primary/fallback role cleanup")


def test_fallback_rotation_rejected_without_live_primary(
        fallback_macsec_environment, upstream_links):
    """Reject fallback rotation while fallback carries a failed primary."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    port, neighbor = _select_routed_link(environment, upstream_links)
    invalid_cak, invalid_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    replacement_cak, replacement_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    traffic = []
    traffic_phases = []
    peer_updated = False

    try:
        traffic = _start_bidirectional_traffic(
            environment, upstream_links)
        traffic_phases.append(
            _macsec_traffic_phase(environment, port, "baseline"))
        _replace_peer_key_and_verify(
            environment, port,
            profile["primary_cak"], profile["primary_ckn"],
            invalid_cak, invalid_ckn,
            required_live_ckns=(profile["fallback_ckn"],),
            hot_update_failure="skip")
        peer_updated = True
        expiry_started = time.monotonic()
        assert wait_until(
            _transition_stage_timeout(
                environment, port, MKA_LIVENESS_INTERVALS,
                expiry_started),
            MKA_OBSERVATION_POLL_SECONDS, 0,
            lambda: (
                get_mka_state(duthost, port)[1]
                [profile["primary_ckn"].lower()].get("live_peers") == "0"
                and _participant_is_principal(
                    duthost, port, profile["fallback_ckn"])
            ),
        ), "Fallback did not take over: {}".format(
            _redacted_diagnostics(environment, port))
        traffic_phases.append(
            _macsec_traffic_phase(environment, port, "fallback-takeover"))

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
        traffic_phases.append(
            _macsec_traffic_phase(environment, port, "rotation-rejected"))
    finally:
        try:
            if peer_updated:
                restore_started = time.monotonic()
                _replace_peer_key_and_verify(
                    environment, port,
                    invalid_cak, invalid_ckn,
                    profile["primary_cak"], profile["primary_ckn"])
                _wait_peer_actor_then_dut_owner(
                    environment,
                    port,
                    neighbor,
                    profile["primary_ckn"],
                    restore_started,
                    True,
                    description="rejected-rotation primary cleanup",
                )
                _wait_final_environment(
                    environment, port, restore_started,
                    description="rejected-rotation cleanup")
        finally:
            _cleanup_traffic(
                traffic, assert_loss=sys.exc_info()[0] is None,
                phase_diagnostics=traffic_phases)


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
        port, _ = _select_routed_link(environment, upstream_links)
        selected_ports = [port]
        before = _snapshot_active_key_state(
            environment, selected_ports)[0]
        assert wait_until(
            90, 2, 0,
            lambda: _sa_identity_changed(
                before,
                _snapshot_active_key_state(
                    environment, selected_ports)[0]),
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
            _cleanup_traffic(
                traffic, assert_loss=sys.exc_info()[0] is None)


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
            _cleanup_traffic(
                traffic, assert_loss=sys.exc_info()[0] is None)


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

    old_fallback_cak = profile["fallback_cak"]
    old_fallback_ckn = profile["fallback_ckn"]
    mismatched_cak, mismatched_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    replacement_cak, replacement_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    namespace = get_namespace_option(duthost, unsafe_port)
    neighbor_updated = False

    try:
        _replace_peer_key_and_verify(
            environment, unsafe_port,
            old_fallback_cak, old_fallback_ckn,
            mismatched_cak, mismatched_ckn,
            is_fallback=True,
            required_live_ckns=(profile["primary_ckn"],),
            hot_update_failure="skip")
        neighbor_updated = True

        def _preconditions_ready():
            participants_by_port = {
                port: get_mka_state(duthost, port)[1]
                for port in ports
            }
            peer_participants_by_port = {
                port: _direct_participants(
                    environment["links"][port]["host"],
                    environment["links"][port]["port"])
                for port in (unsafe_port, safe_port)
            }
            peer_configured_ckns_by_port = {
                port: _get_peer_profile_ckns(
                    environment["links"][port],
                    environment["neighbor_profiles"][port])
                for port in (unsafe_port, safe_port)
            }
            return not validate_multi_port_alternate_state(
                participants_by_port,
                old_fallback_ckn,
                unsafe_port,
                [safe_port],
                peer_participants_by_port,
                peer_configured_ckns_by_port,
            )

        assert wait_until(
            _protocol_timeout(environment, unsafe_port, 4), 1, 0,
            _preconditions_ready,
        ), "Multi-port preconditions failed: unsafe={}, safe={}".format(
            _redacted_diagnostics(environment, unsafe_port),
            _redacted_diagnostics(environment, safe_port),
        )

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
            _replace_peer_key_and_verify(
                environment, unsafe_port,
                mismatched_cak, mismatched_ckn,
                old_fallback_cak, old_fallback_ckn,
                is_fallback=True,
                required_live_ckns=(
                    profile["primary_ckn"], old_fallback_ckn))
        assert wait_until(
            _protocol_timeout(environment, unsafe_port, 6), 1, 0,
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
        fallback_macsec_environment, upstream_links):
    """Delete state on port disable and rebuild it after macsecmgrd restart."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
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
    """Lose both shared CAKs, then recover service with the fallback CA."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    port, neighbor = _select_routed_link(
        environment, upstream_links)
    invalid_primary_cak, invalid_primary_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    invalid_fallback_cak, invalid_fallback_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    primary_updated = False
    fallback_updated = False

    try:
        _replace_peer_key_and_verify(
            environment, port,
            profile["primary_cak"], profile["primary_ckn"],
            invalid_primary_cak, invalid_primary_ckn,
            required_live_ckns=(profile["fallback_ckn"],),
            hot_update_failure="skip")
        primary_updated = True
        primary_expiry_started = time.monotonic()
        assert wait_until(
            _transition_stage_timeout(
                environment, port, MKA_LIVENESS_INTERVALS,
                primary_expiry_started),
            MKA_OBSERVATION_POLL_SECONDS, 0,
            lambda: (
                get_mka_state(duthost, port)[1]
                [profile["primary_ckn"].lower()].get("live_peers") == "0"
                and _participant_is_principal(
                    duthost, port, profile["fallback_ckn"])
            ),
        ), "Fallback did not carry the port: {}".format(
            _redacted_diagnostics(environment, port))

        teardown_marker = (
            "KaY: No CA has a live peer; tearing down the controlled port")
        teardown_log_count = _mka_log_marker_count(
            duthost, port, teardown_marker)
        _replace_peer_key_and_verify(
            environment, port,
            profile["fallback_cak"], profile["fallback_ckn"],
            invalid_fallback_cak, invalid_fallback_ckn,
            is_fallback=True,
            hot_update_failure="skip")
        fallback_updated = True
        expiry_started = time.monotonic()
        expiry_timeout = _transition_stage_timeout(
            environment, port, MKA_LIVENESS_INTERVALS,
            expiry_started)

        def _all_dut_peers_expired():
            _, participants = get_mka_state(duthost, port)
            return (
                bool(participants)
                and all(
                    int(participant.get("live_peers", "0")) == 0
                    for participant in participants.values()
                )
            )

        assert wait_until(
            expiry_timeout, 1, 0, _all_dut_peers_expired,
        ), "DUT participants retained live peers after peer actor removal: {}".format(
            _redacted_diagnostics(environment, port))

        def _teardown_complete():
            _, participants = get_mka_state(duthost, port)
            state = get_macsec_teardown_state(duthost, port)
            log_seen = _mka_log_marker_count(
                duthost, port, teardown_marker) > teardown_log_count
            return classify_macsec_teardown(
                participants,
                state["port_enable"],
                state["egress_sa_keys"],
                state["ingress_sa_keys"],
                log_seen,
            ) in ("complete", "complete-without-observed-log")

        remaining = max(
            1, expiry_timeout - (time.monotonic() - expiry_started))
        assert wait_until(
            remaining, 1, 0, _teardown_complete,
        ), "Both-invalid teardown failed: classification={}, state={}, mka={}".format(
            classify_macsec_teardown(
                get_mka_state(duthost, port)[1],
                get_macsec_teardown_state(
                    duthost, port)["port_enable"],
                get_macsec_teardown_state(
                    duthost, port)["egress_sa_keys"],
                get_macsec_teardown_state(
                    duthost, port)["ingress_sa_keys"],
                _mka_log_marker_count(
                    duthost, port, teardown_marker) > teardown_log_count,
            ),
            get_macsec_teardown_state(duthost, port),
            _redacted_diagnostics(environment, port),
        )
        assert not neighbor["host"].iface_macsec_ok(neighbor["port"]), \
            "Peer controlled port remained open with both CAKs mismatched"
        traffic_results = _selected_link_ping_results(
            environment, upstream_links, port)
        assert not any(traffic_results), (
            "Traffic still forwarded with both CAKs mismatched: "
            "dut_to_peer={}, peer_to_dut={}"
        ).format(*traffic_results)

        recovery_started = time.monotonic()
        _replace_peer_key_and_verify(
            environment, port,
            invalid_fallback_cak, invalid_fallback_ckn,
            profile["fallback_cak"], profile["fallback_ckn"],
            is_fallback=True)
        fallback_updated = False
        _wait_peer_actor_then_dut_owner(
            environment,
            port,
            neighbor,
            profile["fallback_ckn"],
            recovery_started,
            False,
            description="both-invalid fallback recovery",
        )
        _wait_final_environment(
            environment, port, recovery_started,
            principal_ckn=profile["fallback_ckn"],
            description="both-invalid fallback recovery")
        assert _selected_link_ping_succeeds(
            environment, upstream_links, port), \
            "Traffic did not recover on the matching fallback CA"
    finally:
        cleanup_started = time.monotonic()
        if fallback_updated:
            _replace_peer_key_and_verify(
                environment, port,
                invalid_fallback_cak, invalid_fallback_ckn,
                profile["fallback_cak"], profile["fallback_ckn"],
                is_fallback=True,
                required_live_ckns=(profile["fallback_ckn"],))
        if primary_updated:
            cleanup_started = time.monotonic()
            _replace_peer_key_and_verify(
                environment, port,
                invalid_primary_cak, invalid_primary_ckn,
                profile["primary_cak"], profile["primary_ckn"],
                required_live_ckns=(
                    profile["primary_ckn"],
                    profile["fallback_ckn"],
                ))
        _wait_final_environment(
            environment, port, cleanup_started,
            description="both-invalid primary/fallback cleanup")
