import hashlib
from dataclasses import dataclass

from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_config_helper import (
    delete_macsec_profile,
    disable_macsec_port,
    enable_macsec_port,
    eos_macsec_key_line,
    restore_macsec_profile_key,
    set_macsec_profile,
    update_macsec_profile_key,
)
from tests.common.macsec.macsec_helper import get_appl_db
from tests.common.macsec.mka_state_helper import (
    get_macsec_ingress_sc_state,
    get_macsec_profile_config,
    get_mka_state,
    get_namespace_option,
    parse_eos_mka_participants,
    parse_eos_profile_ckns,
    validate_mka_snapshot,
    validate_eos_mka_participants,
    validate_point_to_point_ingress_sc,
)


@dataclass
class LinkSnapshot:
    port: str
    profile_name: str
    profile_config: dict
    session: dict
    participants: dict
    appl_port: dict
    egress_sc: dict
    egress_sas: dict
    ingress_scs: list
    controlled_port: bool
    controlled_port_authoritative: bool

    def principal_ckns(self):
        return sorted(
            ckn for ckn, participant in self.participants.items()
            if participant.get("is_principal") == "true")

    def protected_errors(
            self, profile, expected_principal, require_all_live=True):
        errors = validate_mka_snapshot(
            self.session,
            self.participants,
            profile,
            expected_principal,
            require_all_live=require_all_live,
        )
        if self.appl_port.get("enable") != "true":
            errors.append("APPL_DB controlled port is not enabled")
        if not self.egress_sc:
            errors.append("egress SC is missing")
        else:
            try:
                encoding_an = int(self.egress_sc.get("encoding_an"))
            except (TypeError, ValueError):
                errors.append("egress encoding AN is invalid")
            else:
                active_sa = self.egress_sas.get(encoding_an, {})
                if not active_sa.get("sak"):
                    errors.append(
                        "egress encoding SA {} is missing".format(
                            encoding_an))
        errors.extend(validate_point_to_point_ingress_sc(
            self.ingress_scs))
        if self.controlled_port_authoritative and not self.controlled_port:
            errors.append("provider controlled port is closed")
        return errors

    def blocked_errors(self, expected_ckns):
        errors = []
        if set(self.participants) != {
                ckn.lower() for ckn in expected_ckns}:
            errors.append("participant CKN set does not match")
        for ckn, participant in self.participants.items():
            if participant.get("active") != "true":
                errors.append("{} is not active".format(ckn))
            try:
                live_peers = int(participant.get("live_peers", "0"))
            except (TypeError, ValueError):
                errors.append("{} has invalid live_peers".format(ckn))
                continue
            if live_peers != 0:
                errors.append("{} retains a live peer".format(ckn))
        if self.session.get("query_status") != "ok":
            errors.append("query_status is not ok")
        if self.session.get("config_status") != "in-sync":
            errors.append("config_status is not in-sync")
        if self.session.get("secured") != "false":
            errors.append("session is still secured")
        if self.appl_port.get("enable") != "false":
            errors.append("APPL_DB controlled port is enabled")
        teardown = self.teardown_state()
        if teardown["egress_sa_keys"] or teardown["ingress_sa_keys"]:
            errors.append("MACsec SAs remain installed")
        if self.controlled_port_authoritative and self.controlled_port:
            errors.append("provider controlled port remains open")
        return errors

    def teardown_state(self):
        return {
            "port_enable": self.appl_port.get("enable"),
            "egress_sa_keys": [
                "{}:{}".format(self.port, an)
                for an in sorted(self.egress_sas)
            ],
            "ingress_sa_keys": [
                "{}:{}:{}".format(
                    self.port, entry.get("sci"), an)
                for entry in self.ingress_scs
                for an in sorted(entry.get("sas", {}))
            ],
        }

    def active_key_identity(self):
        def _fingerprint(value):
            if not value:
                return None
            return hashlib.sha256(str(value).encode()).hexdigest()

        encoding_an = str(self.egress_sc.get("encoding_an", ""))
        try:
            active_egress = self.egress_sas.get(int(encoding_an), {})
        except ValueError:
            active_egress = {}
        ingress = []
        for entry in self.ingress_scs:
            ingress.append((
                entry.get("sci"),
                tuple(sorted(
                    str(an) for an, sa in entry.get("sas", {}).items()
                    if sa.get("active") == "true")),
            ))
        return (
            encoding_an,
            _fingerprint(active_egress.get("sak")),
            active_egress.get("ssci"),
            tuple(ingress),
        )

    def rollover_errors(self, before, require_rekey=True):
        """Require a converged shared SAK with the old SAs actually retired."""
        errors = []
        current_key = self.active_key_identity()[1]
        previous_key = before.active_key_identity()[1]
        if not current_key:
            errors.append("active transmit SAK is missing")
        if require_rekey is True:
            if current_key == previous_key:
                errors.append("no new transmit SAK was observed")
            if sum(int(self.session[field]) for field in ("keys_distributed", "keys_received")) <= sum(
                    int(before.session[field]) for field in ("keys_distributed", "keys_received")):
                errors.append("new SAK distribution/reception has not been published")
        elif require_rekey is False and current_key != previous_key:
            errors.append("standby rotation changed the active SAK")
        if len(self.egress_sas) != 1:
            errors.append("old transmit SAs have not retired")
        if len(self.ingress_scs) != 1:
            errors.append("expected one receive SC after rollover")
        else:
            sas = self.ingress_scs[0]["sas"]
            if len(sas) != 1:
                errors.append("old receive SAs have not retired")
            elif self.egress_sas:
                transmit = next(iter(self.egress_sas.values()))
                receive = next(iter(sas.values()))
                if receive.get("active") != "true" or receive.get("sak") != transmit.get("sak"):
                    errors.append("bidirectional SAK state has not converged")
        return errors

    def redacted(self):
        return {
            "port": self.port,
            "profile": self.profile_name,
            "session": self.session,
            "participants": self.participants,
            "appl_port": self.appl_port,
            "egress_encoding_an": self.egress_sc.get("encoding_an"),
            "egress_ans": sorted(self.egress_sas),
            "ingress": [
                {
                    "sci": entry.get("sci"),
                    "active_ans": sorted(
                        an for an, sa in entry.get("sas", {}).items()
                        if sa.get("active") == "true"),
                }
                for entry in self.ingress_scs
            ],
            "controlled_port": self.controlled_port,
            "controlled_port_authoritative":
                self.controlled_port_authoritative,
            "key_server_sci": self.session.get("key_server_sci"),
        }


def read_link_snapshot(duthost, port, neighbor, profile_name):
    session, participants = get_mka_state(duthost, port)
    appl_port, egress_sc, _, egress_sas, _ = get_appl_db(
        duthost, port, neighbor["host"], neighbor["port"])
    return LinkSnapshot(
        port=port,
        profile_name=profile_name,
        profile_config=get_macsec_profile_config(
            duthost, port, profile_name),
        session=session,
        participants=participants,
        appl_port=appl_port,
        egress_sc=egress_sc,
        egress_sas=egress_sas,
        ingress_scs=get_macsec_ingress_sc_state(duthost, port),
        controlled_port=duthost.iface_macsec_ok(port),
        controlled_port_authoritative=False,
    )


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
        self.neighbor = environment["links"][port]
        self.profile_name = environment["neighbor_profiles"][port]
        self.priority = environment["neighbor_priorities"][port]

    @property
    def host(self):
        return self.neighbor["host"]

    @property
    def peer_port(self):
        return self.neighbor["port"]

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

    def delete_primary_if_supported(self, primary_pair):
        raise NotImplementedError(self.primary_delete_unsupported_reason)

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
        self.priority = (
            profile["priority"] if priority is None else priority)

    def protected_errors(
            self, profile, expected_principal, require_all_live=True):
        snapshot = self.snapshot(profile)
        peer_profile = dict(profile, name=snapshot.profile_name)
        return snapshot.protected_errors(
            peer_profile,
            expected_principal,
            require_all_live=require_all_live,
        )

    def blocked_errors(self, expected_ckns, previous_last_updated=None):
        snapshot = self.snapshot()
        errors = snapshot.blocked_errors(expected_ckns)
        if (
                previous_last_updated is not None
                and snapshot.session.get("last_updated")
                == previous_last_updated):
            errors.append("peer STATE_DB publication is stale")
        return errors

    def publication_marker(self):
        return self.snapshot().session.get("last_updated")

    def snapshot(self, profile=None):
        profile_name = self.environment["neighbor_profiles"][self.port]
        return read_link_snapshot(
            self.host,
            self.peer_port,
            {
                "host": self.environment["duthost"],
                "port": self.port,
            },
            profile_name,
        )

    def normalized_state(self):
        snapshot = self.snapshot()
        return {
            "participants": snapshot.participants,
            "configured_ckns": {
                str(snapshot.profile_config[field]).lower()
                for field in ("primary_ckn", "fallback_ckn")
                if snapshot.profile_config.get(field)
            },
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
        snapshot = self.snapshot(original_profile)
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
        configured_ckns = self.snapshot(original_profile)["configured_ckns"]
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

    def snapshot(self, profile=None):
        profile = profile or self.environment["peer_profiles"][self.port]
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
            "participants": participants,
            "controlled_port": self.host.iface_macsec_ok(self.peer_port),
            "controlled_port_authoritative": True,
        }

    def protected_errors(
            self, profile, expected_principal, require_all_live=True):
        snapshot = self.snapshot(profile)
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

    def blocked_errors(self, expected_ckns, previous_last_updated=None):
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

    def publication_marker(self):
        return None

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
