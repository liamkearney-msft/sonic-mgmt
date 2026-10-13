import ipaddress
import logging
import re
import shlex
import sys
import time
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

import pytest

from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_config_helper import (
    delete_macsec_profile,
    eos_macsec_key_line,
    disable_macsec_port,
    enable_macsec_port,
    generate_macsec_key_pair,
    get_macsec_profile_ckns,
    set_macsec_profile,
    update_macsec_profile_key,
    update_macsec_profile_key as _profile_update,
    restore_macsec_profile_key,
)
from tests.common.macsec.failure_safe_cleanup import FailureSafeCleanup
from tests.common.macsec.macsec_helper import (
    get_ipnetns_prefix,
)
from tests.common.macsec.macsec_platform_helper import find_portchannel_from_member, get_portchannel
from tests.common.macsec.mka_state_helper import (
    cleanup_all,
    get_namespace_option,
    get_public_mka_status as _mka_status,
    mka_hello_timeout_seconds,
    mka_state_cli_supported,
    parse_eos_mka_participants,
    parse_eos_profile_ckns,
    parse_eos_profile_rekey_period,
    parse_eos_profile_priority,
    validate_eos_mka_participants,
    select_independent_port_pair,
    show_macsec_output as _show_macsec,
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


def _profile_ckns(host, port, name):
    return get_macsec_profile_ckns(host, name, get_namespace_option(host, port))


def _macsec_sa_status(host, port):
    """Read public show output; keep SAKs in memory, never log the raw text."""
    output = _show_macsec(host, port, port)
    if not re.search(r"(?m)^MACsec port\({}\)".format(re.escape(port)), output):
        raise ValueError("Public MACsec port output missing for {}".format(port))
    result = {"port": {}, "egress": {}, "ingress": {}}
    direction = None
    sci = None
    row = None
    for line in output.splitlines():
        match = re.search(r"MACsec (Egress|Ingress) (SC|SA) \(([^)]+)\)", line)
        if match:
            direction = match.group(1).lower()
            if match.group(2) == "SC":
                sci = match.group(3)
                if sci in result[direction]:
                    raise ValueError("Duplicate public MACsec SC on {}".format(port))
                result[direction][sci] = {"sc": {}, "sas": {}, "sci": sci}
                row = result[direction][sci]["sc"]
            else:
                if sci is None or sci not in result[direction]:
                    raise ValueError("Public MACsec SA without SC on {}".format(port))
                try:
                    an = int(match.group(3))
                except ValueError as error:
                    raise ValueError("Invalid public MACsec association number") from error
                if an in result[direction][sci]["sas"]:
                    raise ValueError("Duplicate public MACsec SA on {}".format(port))
                row = result[direction][sci]["sas"].setdefault(an, {})
            continue
        stripped = line.strip()
        if not stripped or re.fullmatch(r"[- ]+", stripped) or stripped.startswith("MACsec port("):
            if stripped.startswith("MACsec port("):
                row = result["port"]
            continue
        if row is None:
            continue
        name, _, value = stripped.partition(" ")
        if name in ("profile", "enable", "encoding_an", "active", "sak"):
            row[name] = value.strip()
    return result


def get_macsec_profile_config(host, port, name):
    return _profile_ckns(host, port, name)


@dataclass
class LinkSnapshot:
    port: str
    profile_name: str
    status: dict
    macsec: dict

    @property
    def participants(self):
        return self.status["participants"] if self.status is not None else {}

    def principal_ckns(self):
        return sorted(
            ckn for ckn, participant in self.participants.items()
            if participant["principal"])

    def protected_errors(
            self, profile, expected_principal, require_all_live=True):
        status = self.status
        errors = []
        if status is None:
            return ["public MACsec MKA status is missing"]
        if status["query"] != "ok" or not status["fresh"]:
            errors.append("public MACsec status is not a fresh successful query")
        if status["profile"] != profile["name"]:
            errors.append("unexpected public MACsec profile")
        if self.macsec["port"].get("enable") != "true":
            errors.append("public MACsec port is not enabled")
        if status["mode"] != "secured" or status["kay"] != "active":
            errors.append("public MACsec port is not secured")
        if status["config"] != "in-sync":
            errors.append("public MACsec configuration is not in-sync")
        expected = {
            profile["primary_ckn"].lower(): "primary",
            profile["fallback_ckn"].lower(): "fallback",
        }
        if set(self.participants) != set(expected):
            errors.append("unexpected public MACsec participant CKNs")
        if self.principal_ckns() != [expected_principal.lower()]:
            errors.append("unexpected public principal CKN")
        for ckn, role in expected.items():
            participant = self.participants.get(ckn, {})
            if participant.get("role") != role or not participant.get("active"):
                errors.append("{} public MACsec participant is not active as {}".format(ckn, role))
            if (require_all_live or ckn == expected_principal.lower()) and participant.get("live", 0) < 1:
                errors.append("{} public MACsec participant has no live peer".format(ckn))
        transmitting = []
        for tx in self.macsec["egress"].values():
            try:
                an = int(tx["sc"]["encoding_an"])
            except (KeyError, TypeError, ValueError):
                continue
            sak = tx["sas"].get(an, {}).get("sak")
            if sak:
                transmitting.append(sak)
        if len(transmitting) != 1:
            errors.append("expected one public encoding transmit SAK")
        if not any(
                sa.get("active") == "true" and sa.get("sak") in transmitting
                for sc in self.macsec["ingress"].values()
                for sa in sc["sas"].values()):
            errors.append("public receive SAK does not match active transmit SAK")
        return errors

    def blocked_errors(self, expected_ckns):
        errors = []
        if self.status is None:
            return errors
        if self.status["query"] != "ok" or not self.status["fresh"]:
            return ["public MACsec status is not a fresh successful query"]
        if self.status["mode"] == "secured":
            errors.append("public MACsec controlled port remains secured")
        if any(sc["sas"] for sc in self.macsec["egress"].values()) or any(
                sc["sas"] for sc in self.macsec["ingress"].values()):
            errors.append("public MACsec SAs remain installed")
        if set(self.participants) != {ckn.lower() for ckn in expected_ckns}:
            errors.append("participant CKN set does not match")
        for ckn, participant in self.participants.items():
            if not participant["active"]:
                errors.append("{} is not active".format(ckn))
            if participant["live"] != 0:
                errors.append("{} retains a live peer".format(ckn))
        return errors

    def active_key_identity(self):
        for sc in self.macsec["egress"].values():
            an = sc["sc"].get("encoding_an")
            if an and an.isdigit():
                sak = sc["sas"].get(int(an), {}).get("sak")
                if sak:
                    return sak
        return None

    def rollover_errors(self, before, require_rekey=True):
        current = self.active_key_identity()
        previous = before.active_key_identity()
        errors = []
        if current is None:
            errors.append("public active transmit SAK is missing")
        if require_rekey is True and current == previous:
            errors.append("public transmit SAK did not change")
        if require_rekey is False and current != previous:
            errors.append("public standby rotation changed transmit SAK")
        if current is not None and not any(
                sa.get("active") == "true" and sa.get("sak") == current
                for sc in self.macsec["ingress"].values()
                for sa in sc["sas"].values()):
            errors.append("public active receive SAK does not match transmit SAK")
        return errors

    def redacted(self):
        return self.status


def read_link_snapshot(duthost, port, profile_name, rows=None):
    status = _mka_status(duthost, port) if rows is None else rows
    macsec = _macsec_sa_status(duthost, port) if status is not None else {
        "port": {}, "egress": {}, "ingress": {}}
    return LinkSnapshot(port=port, profile_name=profile_name, status=status, macsec=macsec)


class PeerAdapter:
    provider = "peer"
    supports_primary_delete = False
    primary_delete_unsupported_reason = (
        "delete-only CA fault injection is not exposed by the supported "
        "SONiC configuration API"
    )

    def __init__(self, environment, port):
        self.environment = environment
        self.port = port
        self.host = environment["links"][port]["host"]
        self.peer_port = environment["links"][port]["port"]
        self.profile_name = environment["neighbor_profiles"][port]

    @property
    def namespace_option(self):
        return get_namespace_option(self.host, self.peer_port)

    @property
    def scope(self):
        return self.host.hostname, self.namespace_option, self.profile_name

    @property
    def scope_ports(self):
        return [
            port for port in self.environment["links"]
            if peer_adapter(self.environment, port).scope == self.scope
        ]

    @staticmethod
    def profile_with_pair(profile, role, pair):
        updated = dict(profile)
        updated["{}_cak".format(role)] = pair[0]
        updated["{}_ckn".format(role)] = pair[1]
        return updated

    def commit_profile(self, profile):
        for port in self.scope_ports:
            self.environment["peer_profiles"][port] = dict(profile)

    def rotate(
            self, role, old_pair, new_pair, commit=True,
            base_profile=None):
        update_macsec_profile_key(
            self.host,
            self.profile_name,
            old_pair[0],
            old_pair[1],
            new_pair[0],
            new_pair[1],
            is_fallback=role == "fallback",
            namespace_option=self.namespace_option,
        )
        updated = self.profile_with_pair(
            base_profile or self.environment["peer_profiles"][self.port],
            role,
            new_pair,
        )
        if commit:
            self.commit_profile(updated)

    def restore_key(self, role, original_profile, replacement_pair):
        original_pair = (
            original_profile["{}_cak".format(role)],
            original_profile["{}_ckn".format(role)],
        )
        restore_macsec_profile_key(
            self.host, self.profile_name,
            original_pair[0], original_pair[1],
            replacement_pair[0], replacement_pair[1],
            is_fallback=role == "fallback",
            namespace_options=[self.namespace_option])

    def create_profile(self, profile_name, profile, priority=None):
        set_macsec_profile(
            self.host, profile_name,
            profile["priority"] if priority is None else priority,
            profile["cipher_suite"],
            profile["primary_cak"], profile["primary_ckn"],
            profile["policy"], profile["send_sci"],
            profile["rekey_period"], profile.get("fallback_cak"),
            profile.get("fallback_ckn"),
            namespace_option=self.namespace_option,
        )

    def rebind(self, profile_name, profile=None):
        disable_macsec_port(self.host, self.peer_port)
        enable_macsec_port(self.host, self.peer_port, profile_name)
        self.profile_name = profile_name
        self.environment["neighbor_profiles"][self.port] = profile_name
        if profile is not None:
            self.environment["peer_profiles"][self.port] = dict(profile)

    def replace_profile(self, profile_name, profile, priority=None):
        ports = self.scope_ports
        for port in ports:
            disable_macsec_port(self.host, self.environment["links"][port]["port"])
        delete_macsec_profile(
            self.host, profile_name, namespace_option=self.namespace_option)
        self.create_profile(profile_name, profile, priority=priority)
        for port in ports:
            enable_macsec_port(
                self.host, self.environment["links"][port]["port"], profile_name)
            self.environment["neighbor_profiles"][port] = profile_name
            self.environment["peer_profiles"][port] = dict(profile)
        self.profile_name = profile_name

    def protected_errors(
            self, profile, expected_principal, require_all_live=True):
        snapshot = self.snapshot()
        peer_profile = dict(profile, name=snapshot.profile_name)
        return snapshot.protected_errors(
            peer_profile,
            expected_principal,
            require_all_live=require_all_live,
        )

    def blocked_errors(self, expected_ckns):
        return self.snapshot().blocked_errors(expected_ckns)

    def snapshot(self):
        profile_name = self.environment["neighbor_profiles"][self.port]
        return read_link_snapshot(
            self.host, self.peer_port, profile_name)

    def normalized_state(self):
        snapshot = self.snapshot()
        configured = _profile_ckns(self.host, self.peer_port, self.profile_name)
        if configured is None:
            raise AssertionError("Peer public MACsec profile is missing")
        return {
            "participants": snapshot.participants,
            "configured_ckns": set(configured.values()),
        }

    def diagnostics(self):
        return self.snapshot().redacted()


class EosPeerAdapter(PeerAdapter):
    provider = "ceos"
    supports_primary_delete = True

    @property
    def namespace_option(self):
        return ""

    def _configure_key(self, pair, fallback=False, remove=False):
        self.host.eos_config(
            lines=[eos_macsec_key_line(
                pair[1], pair[0], is_fallback=fallback, remove=remove)],
            parents=["mac security", "profile {}".format(self.profile_name)],
        )

    def delete_primary_if_supported(self, primary_pair):
        self._configure_key(primary_pair, remove=True)

    def add_primary(self, primary_pair):
        self._configure_key(primary_pair)

    def delete_fallback(self, fallback_pair):
        self._configure_key(fallback_pair, fallback=True, remove=True)

    def add_fallback(self, fallback_pair):
        self._configure_key(fallback_pair, fallback=True)

    def primary_removed_errors(self, original_profile):
        snapshot = self.snapshot()
        primary_ckn = original_profile["primary_ckn"].lower()
        fallback_ckn = original_profile["fallback_ckn"].lower()
        errors = []
        if snapshot["configured_ckns"] != {fallback_ckn}:
            errors.append(
                "configured CKN set does not contain only fallback")
        if set(snapshot["participants"]) != {fallback_ckn}:
            errors.append(
                "runtime participant set does not contain only fallback")
        if primary_ckn in snapshot["participants"]:
            errors.append("removed primary remains in runtime participants")
        fallback = snapshot["participants"].get(fallback_ckn, {})
        if not fallback.get("success"):
            errors.append("fallback is not successful")
        if not fallback.get("active"):
            errors.append("fallback is not active")
        if fallback.get("live_peers", 0) < 1:
            errors.append("fallback has no live peer")
        if not snapshot["controlled_port"]:
            errors.append("cEOS controlled port is closed")
        return errors

    def restore_key(self, role, original_profile, mismatched_pair):
        configured_ckns = self.snapshot()["configured_ckns"]
        original_pair = (
            original_profile["{}_cak".format(role)],
            original_profile["{}_ckn".format(role)],
        )
        original_ckn = original_pair[1].lower()
        mismatched_ckn = mismatched_pair[1].lower()
        other_role = "fallback" if role == "primary" else "primary"
        other_ckn = original_profile["{}_ckn".format(other_role)].lower()
        unexpected = configured_ckns.difference({
            other_ckn, original_ckn, mismatched_ckn})
        if unexpected:
            raise AssertionError(
                "Peer profile contains unexpected CKNs during cleanup")

        is_fallback = role == "fallback"
        lines = []
        if mismatched_ckn in configured_ckns:
            lines.append(eos_macsec_key_line(
                mismatched_pair[1], mismatched_pair[0],
                is_fallback=is_fallback,
                remove=True,
            ))
        if original_ckn not in configured_ckns:
            lines.append(eos_macsec_key_line(
                original_pair[1], original_pair[0],
                is_fallback=is_fallback,
            ))
        if lines:
            self.host.eos_config(
                lines=lines,
                parents=["mac security",
                         "profile {}".format(self.profile_name)],
            )

    def snapshot(self):
        output = self.host.eos_command(commands=[
            "show mac security participants {} detail | json".format(
                self.peer_port),
            "show running-config section mac security",
        ])["stdout"]
        participants = parse_eos_mka_participants(
            output[0] if isinstance(output[0], dict) else {},
            self.peer_port,
        )
        configured_ckns = parse_eos_profile_ckns(
            output[1] if len(output) > 1 else "",
            self.profile_name,
        )
        return {
            "profile_name": self.profile_name,
            "configured_ckns": configured_ckns,
            "rekey_period": parse_eos_profile_rekey_period(
                output[1] if len(output) > 1 else "", self.profile_name),
            "priority": parse_eos_profile_priority(
                output[1] if len(output) > 1 else "", self.profile_name),
            "participants": participants,
            "controlled_port": self.host.iface_macsec_ok(self.peer_port),
            "controlled_port_authoritative": True,
        }

    def protected_errors(
            self, profile, expected_principal, require_all_live=True):
        snapshot = self.snapshot()
        expected_ckns = {
            profile["primary_ckn"].lower(),
            profile["fallback_ckn"].lower(),
        }
        errors = []
        if snapshot["configured_ckns"] != expected_ckns:
            errors.append("configured CKN set does not match")
        errors.extend(validate_eos_mka_participants(
            snapshot["participants"], profile, snapshot["controlled_port"],
            expected_principal.lower(), require_all_live))
        return errors

    def blocked_errors(self, expected_ckns):
        snapshot = self.snapshot()
        errors = []
        normalized_ckns = {ckn.lower() for ckn in expected_ckns}
        if snapshot["configured_ckns"] != normalized_ckns:
            errors.append("configured CKN set does not match")
        if set(snapshot["participants"]) != normalized_ckns:
            errors.append("runtime participant CKN set does not match")
        for ckn, participant in snapshot["participants"].items():
            if participant.get("live_peers", 0) != 0:
                errors.append("{} retains a live peer".format(ckn))
        if snapshot["controlled_port"]:
            errors.append("cEOS controlled port remains open")
        return errors

    def normalized_state(self):
        snapshot = self.snapshot()
        return {
            "participants": snapshot["participants"],
            "configured_ckns": snapshot["configured_ckns"],
        }

    def diagnostics(self):
        return self.snapshot()


def peer_adapter(environment, port):
    neighbor = environment["links"][port]
    adapter = EosPeerAdapter if isinstance(
        neighbor["host"], EosHost) else PeerAdapter
    return adapter(environment, port)


def peer_adapters(environment, ports=None):
    """Return one adapter per peer, namespace, and shared profile."""
    adapters = {}
    for port in environment["links"] if ports is None else ports:
        adapter = peer_adapter(environment, port)
        adapters.setdefault(adapter.scope, adapter)
    return list(adapters.values())


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


def _hello_timeout(snapshot, intervals):
    status = snapshot.status
    if status is None or not re.fullmatch(r"\d+ ms", status["hello"]):
        raise ValueError("Public MACsec hello interval unavailable on {}".format(snapshot.port))
    return mka_hello_timeout_seconds({"mka_hello_time_ms": status["hello"].split()[0]}, intervals)


def _protocol_timeout(environment, port, intervals):
    return _hello_timeout(_snapshot(environment, port), intervals)


def _snapshot(environment, port):
    return read_link_snapshot(
        environment["duthost"],
        port,
        environment["profile"]["name"],
    )


def _snapshots(environment, ports):
    return {
        port: _snapshot(environment, port)
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
        require_all_live=True, check_peers=False,
        on_dut_settled=None):
    """Settle publicly reported MKA selection and protected peer traffic."""
    settle = {
        port: _hello_timeout(snapshot, 3)
        for port, snapshot in before.items()
    }
    hello = {
        port: _hello_timeout(snapshot, 1)
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
        return problems

    def _observe(port, snapshot):
        problems = _problems(port, snapshot)
        now = time.monotonic()
        key = (snapshot.active_key_identity(), tuple(snapshot.principal_ckns()))
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
                errors[port] = ["public MKA selection settle interval pending"]
        if ready == len(before) and time.monotonic() < deadline:
            dut_settled = True
            break
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    assert dut_settled, "Public DUT MKA selection did not settle on {}: {}".format(
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
    periodic = environment["profile"]["rekey_period"] > 0
    for port, snapshot in final.items():
        problems = _problems(port, snapshot)
        if periodic:
            unchanged_selection = tuple(snapshot.principal_ckns()) == stable[port][0][1]
        else:
            unchanged_selection = (
                snapshot.active_key_identity(), tuple(snapshot.principal_ckns())) == stable[port][0]
        if not unchanged_selection:
            problems.append("public transmit SAK or principal CKN changed during peer inspection")
        if problems:
            final_errors[port] = problems
    assert not final_errors, "DUT regressed after peer confirmation: {}".format(
        final_errors)


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
    before = {}
    errors = []
    try:
        before = _snapshots(environment, environment["links"])
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
                    check_peers=True)
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


def _observe_periodic_sak_during_traffic(environment, selected_port, expected_principal=None):
    """Require a public SAK change without any test-driven CAK/CKN mutation."""
    profile = environment["profile"]
    if profile["rekey_period"] <= 0:
        raise AssertionError("Fallback E2E coverage requires periodic rekey")
    expected_ckns = {
        field: profile[field].lower() for field in ("primary_ckn", "fallback_ckn")}
    principal = expected_principal or profile["primary_ckn"]

    def _known_profile():
        return _profile_ckns(
            environment["duthost"], selected_port, profile["name"]) == expected_ckns

    assert _known_profile(), "Public fallback profile CKNs differ before periodic observation"
    baseline = [None]

    def _baseline_ready():
        current = _snapshot(environment, selected_port)
        if (not current.protected_errors(profile, principal)
                and current.active_key_identity()):
            baseline[0] = current.active_key_identity()
            return True
        return False

    assert wait_until(MKA_STATE_PUBLISH_TIMEOUT, 1, 0, _baseline_ready), (
        "Protected public SAK unavailable before periodic observation")

    def _changed():
        current = _snapshot(environment, selected_port)
        return (
            not current.protected_errors(profile, principal)
            and current.active_key_identity() != baseline[0]
        )

    assert wait_until(MKA_CONVERGE_TIMEOUT, 1, 0, _changed), (
        "No natural public SAK change observed with unchanged CAK/CKN "
        "during protected bidirectional traffic")
    assert _known_profile(), "Public fallback profile CKNs changed during periodic observation"


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
    attempted = []
    completed = [False]
    with FailureSafeCleanup("{} rotation".format(role)) as cleanup:
        cleanup.callback(
            _restore_rotation, environment, role, original_profile,
            peer_originals, new_pair, attempted, completed)
        with _TrafficWindow(environment, upstream_links, port=selected_port) as traffic:
            _observe_periodic_sak_during_traffic(environment, selected_port)
            before = _snapshots(environment, environment["links"])
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
                        "Transit link {} did not show the expected public SAK transition".format(port))
                completed[0] = True
                _observe_periodic_sak_during_traffic(
                    environment, selected_port, expected_principal=profile["primary_ckn"])
                traffic.assert_zero_loss()

            _wait_rotations_settled(
                environment, before, profile["primary_ckn"],
                require_rekey=require_rekey, check_peers=True,
                on_dut_settled=_finish_measured_rotation)
        yield


def _wait_link_blocked(
        environment, port, expected_ckns, timeout=MKA_STATE_PUBLISH_TIMEOUT):
    errors = [None]

    def _blocked():
        snapshot = _snapshot(environment, port)
        errors[0] = snapshot.blocked_errors(expected_ckns)
        return not errors[0]

    assert wait_until(timeout, 2, 0, _blocked), (
        "Link {} did not block: {}"
    ).format(port, errors[0])


def _wait_peer_blocked(
        adapter, expected_ckns, timeout=MKA_STATE_PUBLISH_TIMEOUT):
    errors = [None]

    def _blocked():
        errors[0] = adapter.blocked_errors(expected_ckns)
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

    with FailureSafeCleanup("fallback mismatch") as cleanup:
        cleanup.callback(
            _restore_mismatch, environment, port, adapter,
            original_profile, invalid_pair, "fallback")
        adapter.delete_fallback(original_pair)
        _wait_link_blocked(
            environment, port,
            (profile["primary_ckn"], profile["fallback_ckn"]))
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


def _dut_transit_route_correct(duthost, portchannels, sources, port, destination_port, via=None):
    incoming = find_portchannel_from_member(port, portchannels)
    outgoing = find_portchannel_from_member(destination_port, portchannels)
    incoming_dev = incoming["name"] if incoming else port
    expected_dev = outgoing["name"] if outgoing else destination_port
    route = _route_result(
        duthost, destination_port,
        "ip -4 route get {} from {} iif {}".format(
            sources[destination_port], sources[port], incoming_dev))
    return (_route_value(route, "dev") == expected_dev
            and _route_value(route, "via") == via
            and "nexthop" not in route.split())


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
        if _running_static(prefix) != ["ip route {} {}".format(prefix, nexthop)]:
            return False
        return bool(_route_result(duthost, port, "ip -4 route show exact {}".format(prefix)))

    def _dut_route_correct(port, destination_port):
        return _dut_transit_route_correct(
            duthost, portchannels, sources, port, destination_port,
            via=upstream_links[destination_port]["local_ipv4_addr"])

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
            90, "DUT static routes did not reach the selected forwarding paths")
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
            "DUT routes did not recover after MACsec restoration")
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
    sources = {port: upstream_links[port]["local_ipv4_addr"]
               for port in (selected_port, other_port)}

    def _dut_route_correct(port, destination_port):
        return _dut_transit_route_correct(
            duthost, portchannels, sources, port, destination_port)

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


@contextmanager
def _periodic_fallback_profile(environment):
    """Use a fresh public profile if the existing fixture lacks periodic rekey."""
    duthost = environment["duthost"]
    profile = environment["profile"]
    links = environment["links"]
    period = profile["rekey_period"]
    assert period > 0, "Fallback E2E profiles must explicitly configure periodic rekey"
    expected_ckns = {
        field: profile[field].lower() for field in ("primary_ckn", "fallback_ckn")}

    def _sonic_profile(host, port, name):
        fields = get_macsec_profile_ckns(
            host, name, get_namespace_option(host, port),
            include_rekey_period=True, include_priority=True)
        if fields is not None and any(fields.get(field) != ckn
                                      for field, ckn in expected_ckns.items()):
            raise AssertionError("Public fallback profile CKNs differ from the known fixture")
        if fields is not None and "priority" not in fields:
            raise AssertionError("Public fallback key-server priority is unavailable")
        return fields

    def _sonic_period(host, port, name):
        fields = _sonic_profile(host, port, name)
        return int(fields["rekey_period"]) if fields and "rekey_period" in fields else None

    def _peer_period(port):
        adapter = peer_adapter(environment, port)
        if isinstance(adapter.host, EosHost):
            peer_state = adapter.snapshot()
            if peer_state["configured_ckns"] != set(expected_ckns.values()):
                raise AssertionError("Public EOS fallback CKNs differ from the known fixture")
            if peer_state["priority"] is None:
                raise AssertionError("Public EOS key-server priority is unavailable")
            return peer_state["rekey_period"]
        return _sonic_period(adapter.host, adapter.peer_port, adapter.profile_name)

    if all(_sonic_period(duthost, port, profile["name"]) == period
           and _peer_period(port) == period for port in links):
        yield
        return

    original = dict(profile)
    original_names = dict(environment["neighbor_profiles"])
    original_peer_profiles = {
        port: dict(value) for port, value in environment["peer_profiles"].items()}
    periodic_name = "MACSEC_R{}_{}".format(
        period, "INTEGRITY" if profile["policy"] == "integrity" else "SECURITY")
    dut_scopes = {}
    peer_scopes = {}
    peer_priorities = {}
    original_bindings = {}

    def _eos_bound_profile(host, port):
        result = host.eos_command(commands=[
            "show running-config interfaces {}".format(port)])
        if result.get("failed") or result.get("rc", 0) != 0:
            raise RuntimeError("Unable to read public EOS MACsec interface binding")
        output = result.get("stdout", [])
        if not output or not isinstance(output[0], str):
            raise ValueError("Malformed public EOS interface configuration")
        names = re.findall(
            r"(?m)^\s*mac security profile\s+(\S+)\s*$", output[0])
        if len(names) != 1:
            raise AssertionError("EOS interface has no unique MACsec profile binding")
        return names[0]

    for port, neighbor in links.items():
        dut_binding = _macsec_sa_status(duthost, port)["port"].get("profile")
        peer_binding = (
            _eos_bound_profile(neighbor["host"], neighbor["port"])
            if isinstance(neighbor["host"], EosHost)
            else _macsec_sa_status(neighbor["host"], neighbor["port"])["port"].get("profile"))
        assert dut_binding == original["name"], (
            "DUT port is not bound to the known fallback profile")
        assert peer_binding == original_names[port], (
            "Peer is not bound to the known fallback profile")
        original_bindings[port] = dut_binding, peer_binding
        namespace = get_namespace_option(duthost, port)
        dut_fields = _sonic_profile(duthost, port, profile["name"])
        if dut_fields is None:
            raise AssertionError("Original DUT fallback profile is missing")
        dut_scopes[namespace] = port, int(dut_fields["priority"])
        adapter = peer_adapter(environment, port)
        peer_scopes.setdefault(adapter.scope, adapter)
        if adapter.scope not in peer_priorities:
            if isinstance(adapter.host, EosHost):
                priority = adapter.snapshot()["priority"]
            else:
                fields = _sonic_profile(adapter.host, adapter.peer_port, adapter.profile_name)
                priority = int(fields["priority"]) if fields else None
            if priority is None:
                raise AssertionError("Original peer key-server priority is unavailable")
            peer_priorities[adapter.scope] = priority

    def _peer_profile_present(adapter):
        if isinstance(adapter.host, EosHost):
            output = adapter.host.eos_command(commands=[
                "show running-config section mac security"])["stdout"]
            if not output or not isinstance(output[0], str):
                raise ValueError("Unable to inspect public EOS profile names")
            return bool(re.search(
                r"(?m)^\s*profile {}\s*$".format(re.escape(periodic_name)), output[0]))
        return get_macsec_profile_ckns(
            adapter.host, periodic_name, adapter.namespace_option) is not None

    for namespace in dut_scopes:
        assert get_macsec_profile_ckns(duthost, periodic_name, namespace) is None, (
            "Test-owned periodic DUT profile already exists")
    for adapter in peer_scopes.values():
        assert not _peer_profile_present(adapter), (
            "Test-owned periodic peer profile already exists")
    logger.info(
        "MACsec periodic fixture will rebind %d selected DUT/peer interfaces "
        "across %d DUT namespaces and %d peer profile scopes",
        2 * len(links), len(dut_scopes), len(peer_scopes))

    def _delete_profile(host, namespace):
        delete_macsec_profile(host, periodic_name, namespace_option=namespace)
        if isinstance(host, EosHost):
            if any(_peer_profile_present(adapter) for adapter in peer_scopes.values()
                   if adapter.host is host):
                raise AssertionError("Test-owned EOS periodic profile remains")
        elif get_macsec_profile_ckns(host, periodic_name, namespace) is not None:
            raise AssertionError("Test-owned SONiC periodic profile remains")

    def _restore_binding(host, port, original_name):
        try:
            disable_macsec_port(host, port)
        finally:
            enable_macsec_port(host, port, original_name)

    def _restore_environment():
        profile.clear()
        profile.update(original)
        environment["neighbor_profiles"].update(original_names)
        environment["peer_profiles"].update(original_peer_profiles)

    with FailureSafeCleanup("periodic fallback profile restoration") as cleanup:
        cleanup.callback(_wait_environment, environment, original["primary_ckn"])
        cleanup.callback(_restore_environment)
        for namespace, (port, priority) in dut_scopes.items():
            cleanup.callback(_delete_profile, duthost, namespace)
            _set_profile(duthost, periodic_name, profile,
                         priority=priority, namespace_option=namespace)
        for adapter in peer_scopes.values():
            cleanup.callback(_delete_profile, adapter.host, adapter.namespace_option)
            _set_profile(adapter.host, periodic_name, profile,
                         priority=peer_priorities[adapter.scope],
                         namespace_option=adapter.namespace_option)
        for port, neighbor in links.items():
            cleanup.callback(_restore_binding, duthost, port, original_bindings[port][0])
            disable_macsec_port(duthost, port)
            enable_macsec_port(duthost, port, periodic_name)
            cleanup.callback(
                _restore_binding, neighbor["host"], neighbor["port"], original_bindings[port][1])
            disable_macsec_port(neighbor["host"], neighbor["port"])
            enable_macsec_port(neighbor["host"], neighbor["port"], periodic_name)
            environment["neighbor_profiles"][port] = periodic_name
            environment["peer_profiles"][port]["name"] = periodic_name
        profile["name"] = periodic_name
        assert all(_sonic_period(duthost, port, periodic_name) == period
                   and _peer_period(port) == period for port in links), (
                       "Public fallback periodic profile did not configure on both ends")
        yield


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
    base_profile_name = profile["name"]
    neighbor_priorities = {
        port: profile["priority"] + (1 if index % 2 else -1)
        for index, port in enumerate(links)
    }
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
        "base_profile_name": base_profile_name,
    }
    with _periodic_fallback_profile(environment):
        assert wait_until(
            MKA_CONVERGE_TIMEOUT, 5, 0,
            _environment_is_healthy, environment,
        ), "Dual-CA MKA operational state did not become healthy"
        yield environment


def test_fallback_operational_state_and_config(
        fallback_macsec_environment):
    """Verify public dual-CA profile, active principal and protected traffic."""
    environment = fallback_macsec_environment
    profile = environment["profile"]

    for port in environment["links"]:
        snapshot = _snapshot(environment, port)
        expected = {field: profile[field].lower()
                    for field in ("primary_ckn", "fallback_ckn")}
        assert get_macsec_profile_config(environment["duthost"], port, profile["name"]) == expected

        assert not snapshot.protected_errors(profile, profile["primary_ckn"])
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

    with _TrafficWindow(environment, upstream_links, port=port) as traffic:
        _observe_periodic_sak_during_traffic(environment, port)
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


def test_primary_mismatch_fallback_takeover_and_recovery_is_hitless(
        fallback_macsec_environment, upstream_links):
    """Fail over to fallback after primary mismatch without traffic loss."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    port, _ = _select_routed_link(environment, upstream_links)
    invalid_pair = generate_macsec_key_pair(
        profile["cipher_suite"])

    with _TrafficWindow(environment, upstream_links, port=port) as traffic:
        _observe_periodic_sak_during_traffic(environment, port)
        with _primary_mismatch(environment, port, invalid_pair):
            pass
        traffic.assert_zero_loss()


@pytest.mark.stress_test
def test_back_to_back_cak_rotation_stress(
        fallback_macsec_environment, upstream_links):
    """Measure each forward replacement, restoring between rotations."""
    environment = fallback_macsec_environment
    profile = environment["profile"]
    if environment["base_profile_name"] != FALLBACK_PROFILE:
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
        expected = dict(original, primary_ckn=new_ckn.lower())
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
            unsafe = _snapshot(environment, unsafe_port)
            safe = _snapshot(environment, safe_port)
            unsafe_peer = adapter.normalized_state()
            safe_peer = safe_adapter.normalized_state()
            alternate = old_pair[1].lower()
            errors = []
            if (unsafe.status is None or unsafe.status["mode"] != "secured"
                    or unsafe.participants.get(alternate, {}).get("live") != 0
                    or unsafe.participants.get(original_primary[1].lower(), {}).get("live", 0) < 1):
                errors.append("unsafe public MKA alternate/primary precondition absent")
            if (alternate in unsafe_peer["configured_ckns"]
                    or alternate in unsafe_peer["participants"]):
                errors.append("unsafe peer still has fallback configured")
            if (safe.status is None or safe.participants.get(alternate, {}).get("live", 0) < 1
                    or alternate not in safe_peer["configured_ckns"]
                    or alternate not in safe_peer["participants"]):
                errors.append("safe peer fallback is not live")
            return errors

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
        assert before.participants[profile["primary_ckn"].lower()]["live"] > 0, \
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
            dict(primary_ckn=replacement_ckn.lower(),
                 fallback_ckn=profile["fallback_ckn"].lower()),
            get_macsec_profile_config(duthost, unsafe_port, profile["name"]),
            "Accepted desired profile update",
        )

        def _deferred():
            current = _snapshot(environment, unsafe_port)
            return (current.status is not None
                    and current.status["query"] == "ok"
                    and current.status["fresh"]
                    and current.status["config"] == "degraded"
                    and current.status["mode"] == "secured"
                    and current.principal_ckns() == [original_primary[1].lower()]
                    and current.participants.get(original_primary[1].lower(), {}).get("live", 0) > 0
                    and replacement_ckn.lower() not in current.participants
                    and (profile["rekey_period"] or
                         current.active_key_identity() == before.active_key_identity()))

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
            dict(primary_ckn=replacement_ckn.lower(),
                 fallback_ckn=profile["fallback_ckn"].lower()),
            get_macsec_profile_config(duthost, unsafe_port, profile["name"]),
            "Desired profile during pending recovery",
        )


def test_disable_closes_public_macsec_session(fallback_macsec_environment):
    """Disable a protected port and restore public MACsec health afterward."""
    environment = fallback_macsec_environment
    duthost = environment["duthost"]
    profile = environment["profile"]
    selected_port = next(iter(environment["links"]))

    with FailureSafeCleanup("MACsec explicit disable") as cleanup:
        cleanup.callback(_wait_environment, environment, profile["primary_ckn"])
        cleanup.callback(enable_macsec_port, duthost, selected_port, profile["name"])
        disable_macsec_port(duthost, selected_port)

        def _closed():
            status = _mka_status(duthost, selected_port)
            return status is None or (
                status["query"] == "ok" and status["fresh"]
                and status["mode"] != "secured")

        assert wait_until(
            MKA_TIMEOUT, 2, 0, _closed,
        ), "Public MACsec status remained secured after explicit port disable"


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
                def _bound():
                    attachment = _mka_status(adapter.host, adapter.peer_port)
                    return (
                        attachment is not None
                        and attachment["query"] == "ok"
                        and attachment["fresh"]
                        and attachment["profile"] == original_profile_name
                    )

                assert wait_until(60, 2, 0, _bound), (
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
                    (profile["primary_ckn"], profile["fallback_ckn"]))
                _wait_peer_blocked(
                    adapter, (invalid_primary_ckn, invalid_fallback_ckn))
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
