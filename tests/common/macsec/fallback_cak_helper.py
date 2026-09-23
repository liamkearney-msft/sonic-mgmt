import hashlib
from dataclasses import dataclass

from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_config_helper import (
    delete_macsec_profile,
    disable_macsec_port,
    enable_macsec_port,
    set_macsec_profile,
    update_macsec_profile_key,
)
from tests.common.macsec.macsec_helper import get_appl_db
from tests.common.macsec.mka_state_helper import (
    get_macsec_ingress_sc_state,
    get_macsec_profile_config,
    get_mka_state,
    parse_eos_mka_participants,
    parse_eos_profile_ckns,
    validate_mka_snapshot,
    validate_point_to_point_ingress_sc,
)


@dataclass(frozen=True)
class MutationResult:
    provider: str
    operation: str
    supported: bool = True
    diagnostics: str = ""


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

    @property
    def optional_key_server_sci(self):
        """Return optional STATE_DB diagnostics outside the core contract."""
        return self.session.get("key_server_sci")

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
            "key_server_sci": self.optional_key_server_sci,
        }


class MkaStateReader:
    """Normalized MKA reader seam.

    The normalized session contract includes profile, protected state,
    query/config status, actor/key-server priorities, key-server role,
    counters, hello time and last_updated. Participant state includes CKN,
    active/primary/principal/live/elected/key-server roles.

    TODO: add a ``show macsec --mka`` reader when its primary/fallback
    ``live_peers`` view is finalized. Callers must not depend on that external
    JSON or text layout. ``key_server_sci`` is optional diagnostic metadata
    when STATE_DB still publishes it.
    """

    def read(self, host, port):
        raise NotImplementedError


class StateDbMkaReader(MkaStateReader):
    def read(self, host, port):
        return get_mka_state(host, port)


STATE_DB_READER = StateDbMkaReader()


def read_link_snapshot(
        duthost, port, neighbor, profile_name,
        reader=STATE_DB_READER):
    session, participants = reader.read(duthost, port)
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

    def rotate(self, role, old_pair, new_pair):
        update_macsec_profile_key(
            self.host,
            self.profile_name,
            old_pair[0],
            old_pair[1],
            new_pair[0],
            new_pair[1],
            is_fallback=role == "fallback",
        )
        updated = dict(self.environment["peer_profiles"][self.port])
        updated["{}_cak".format(role)] = new_pair[0]
        updated["{}_ckn".format(role)] = new_pair[1]
        self.environment["peer_profiles"][self.port] = updated
        return MutationResult(self.provider, "rotate_{}".format(role))

    def delete_primary_if_supported(self, primary_pair):
        return MutationResult(
            self.provider,
            "delete_primary",
            supported=False,
            diagnostics=self.primary_delete_unsupported_reason,
        )

    def bind_profile(self, profile_name, profile):
        self.create_profile(profile_name, profile)
        self.rebind(profile_name, profile)
        return MutationResult(self.provider, "bind_profile")

    def create_profile(self, profile_name, profile):
        set_macsec_profile(
            self.host, profile_name,
            profile["priority"], profile["cipher_suite"],
            profile["primary_cak"], profile["primary_ckn"],
            profile["policy"], profile["send_sci"],
            profile["rekey_period"], profile.get("fallback_cak"),
            profile.get("fallback_ckn"),
        )
        return MutationResult(self.provider, "create_profile")

    def rebind(self, profile_name, profile=None):
        disable_macsec_port(self.host, self.peer_port)
        enable_macsec_port(self.host, self.peer_port, profile_name)
        self.profile_name = profile_name
        self.environment["neighbor_profiles"][self.port] = profile_name
        if profile is not None:
            self.environment["peer_profiles"][self.port] = dict(profile)
        return MutationResult(self.provider, "rebind_profile")

    def replace_profile(self, profile_name, profile, priority=None):
        disable_macsec_port(self.host, self.peer_port)
        delete_macsec_profile(self.host, profile_name)
        set_macsec_profile(
            self.host, profile_name,
            profile["priority"] if priority is None else priority,
            profile["cipher_suite"],
            profile["primary_cak"], profile["primary_ckn"],
            profile["policy"], profile["send_sci"],
            profile["rekey_period"], profile.get("fallback_cak"),
            profile.get("fallback_ckn"),
        )
        enable_macsec_port(self.host, self.peer_port, profile_name)
        self.profile_name = profile_name
        self.priority = (
            profile["priority"] if priority is None else priority)
        self.environment["neighbor_profiles"][self.port] = profile_name
        self.environment["peer_profiles"][self.port] = dict(profile)
        return MutationResult(self.provider, "replace_profile")

    def restore(self, profile_name, profile):
        disable_macsec_port(self.host, self.peer_port)
        delete_macsec_profile(self.host, profile_name)
        self.create_profile(profile_name, profile)
        enable_macsec_port(self.host, self.peer_port, profile_name)
        self.profile_name = profile_name
        self.priority = profile["priority"]
        self.environment["neighbor_profiles"][self.port] = profile_name
        self.environment["peer_profiles"][self.port] = dict(profile)
        return MutationResult(self.provider, "restore")

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

    def _key_line(self, cak, ckn, fallback=False, remove=False):
        line = "key {} 7 {}".format(ckn, cak)
        if fallback:
            line += " fallback"
        return "no " + line if remove else line

    def delete_primary_if_supported(self, primary_pair):
        self.host.eos_config(
            lines=[self._key_line(
                primary_pair[0], primary_pair[1], remove=True)],
            parents=[
                "mac security",
                "profile {}".format(self.profile_name),
            ],
        )
        return MutationResult(self.provider, "delete_primary")

    def add_primary(self, primary_pair):
        self.host.eos_config(
            lines=[self._key_line(primary_pair[0], primary_pair[1])],
            parents=[
                "mac security",
                "profile {}".format(self.profile_name),
            ],
        )
        return MutationResult(self.provider, "add_primary")

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
        if set(snapshot["participants"]) != expected_ckns:
            errors.append("runtime participant CKN set does not match")
        for ckn, participant in snapshot["participants"].items():
            if not participant.get("success"):
                if require_all_live or ckn == expected_principal.lower():
                    errors.append("{} is not successful".format(ckn))
            if not participant.get("active"):
                if require_all_live or ckn == expected_principal.lower():
                    errors.append("{} is not active".format(ckn))
            if (
                    participant.get("live_peers", 0) < 1
                    and (require_all_live
                         or ckn == expected_principal.lower())):
                errors.append("{} has no live peer".format(ckn))
        if not snapshot["controlled_port"]:
            errors.append("cEOS controlled port is closed")
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
