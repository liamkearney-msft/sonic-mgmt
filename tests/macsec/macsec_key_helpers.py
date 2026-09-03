"""Shared link and traffic helpers for MACsec key tests."""
import logging
import re
import shlex

import pytest

from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_config_helper import (
    delete_macsec_profile,
    disable_macsec_port,
    enable_macsec_port,
    generate_macsec_key_pair,
    replace_macsec_profile,
    set_macsec_profile,
)
from tests.common.macsec.macsec_helper import (
    get_ipnetns_prefix,
    get_principal_ckn,
    getns_prefix,
    wait_for_ckn_live,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

LOSS_TOLERANCE = 1.0
REKEY_PERIOD = 5
REKEY_INTERVAL_MAX = 15
_SETTLE_CLEAN_PROBES = 4


def _nbr_key(host):
    """Stable identity for a neighbor host object."""
    return getattr(host, "hostname", None) or id(host)


_CLAIMED_PORTS = {}


def _claim_port(duthost, dut_port):
    _CLAIMED_PORTS.setdefault(_nbr_key(duthost), set()).add(dut_port)


def _release_port(duthost, dut_port):
    _CLAIMED_PORTS.get(_nbr_key(duthost), set()).discard(dut_port)


def _claimed_ports(duthost):
    return _CLAIMED_PORTS.get(_nbr_key(duthost), set())


def select_ctrl_link(ctrl_links, upstream_links, exclude_ports=(),
                     require_sonic_peer=False):
    """Select a non-LAG link with an upstream IP, preferring SONiC peers."""
    link_count = {}
    for entry in ctrl_links.values():
        key = _nbr_key(entry["host"])
        link_count[key] = link_count.get(key, 0) + 1

    best = {}
    for dut_port, nbr in ctrl_links.items():
        nbr_key = _nbr_key(nbr["host"])
        if (dut_port not in upstream_links
                or dut_port in exclude_ports
                or link_count[nbr_key] != 1
                or (require_sonic_peer
                    and isinstance(nbr["host"], EosHost))):
            continue
        rank = isinstance(nbr["host"], EosHost)
        best.setdefault(rank, (dut_port, nbr))
    for rank in (False, True):
        if rank in best:
            return best[rank]
    return None, None


def start_bg_ping(duthost, dut_port, dst_ip, duration):
    """Start a 10 pps continuity ping and confirm its process is running."""
    ping = duthost.shell(
        "sudo {} ping {} -q -w {} -i 0.1".format(
            get_ipnetns_prefix(duthost, dut_port), dst_ip, duration),
        module_async=True)
    pattern = "[p]ing {} -q -w {} -i 0\\.1".format(
        re.escape(dst_ip), duration)

    def _ping_running():
        result = duthost.shell(
            "pgrep -f -- {}".format(shlex.quote(pattern)),
            module_ignore_errors=True)
        return result["rc"] == 0

    if not wait_until(10, 0.25, 0, _ping_running):
        pool, _ = ping
        pool.terminate()
        raise RuntimeError(
            "Continuity ping to {} did not start before the test action".format(
                dst_ip))
    return ping


def read_ping_loss(ping):
    """Wait for a background ping and return its packet-loss percentage."""
    pool, result = ping
    try:
        output = result.get()["stdout"]
    finally:
        pool.terminate()
    return float(re.search(r"([\d\.]+)% packet loss", output).group(1))


def _bgp_established(duthost, dut_port, peer_ip):
    """Return whether the BGP session toward ``peer_ip`` is established."""
    match = re.search(r"asic(\d+)", get_ipnetns_prefix(duthost, dut_port))
    vtysh = "sudo vtysh -n {}".format(match.group(1)) if match else "sudo vtysh"
    output = duthost.shell(
        '{} -c "show bgp neighbors {}"'.format(vtysh, peer_ip),
        module_ignore_errors=True)["stdout"]
    return "BGP state = Established" in output


def wait_link_settled(duthost, dut_port, dst_ip, timeout=300):
    """Wait for BGP and four consecutive lossless ping probes."""
    prefix = get_ipnetns_prefix(duthost, dut_port)
    consecutive = [0]

    def _clean():
        output = duthost.shell(
            "sudo {} ping {} -q -w 3 -i 0.1".format(prefix, dst_ip),
            module_ignore_errors=True)["stdout"]
        match = re.search(r"([\d\.]+)% packet loss", output)
        if match is None or float(match.group(1)) != 0.0:
            consecutive[0] = 0
            return False
        consecutive[0] += 1
        return consecutive[0] >= _SETTLE_CLEAN_PROBES

    if not wait_until(120, 5, 0, lambda: _bgp_established(duthost, dut_port, dst_ip)):
        logger.warning("BGP towards %s has not come back; measuring anyway", dst_ip)
    return wait_until(timeout, 5, 0, _clean)


def sa_saks(duthost, dut_port, direction="EGRESS"):
    """Return SAKs installed for a port and direction, reading only the DUT."""
    ns = getns_prefix(duthost, dut_port)
    cmd = ("for k in $(sonic-db-cli {ns} APPL_DB KEYS "
           "'MACSEC_{direction}_SA_TABLE:{port}:*'); "
           "do sonic-db-cli {ns} APPL_DB HGET \"$k\" sak; done").format(
        ns=ns, direction=direction, port=dut_port)
    lines = duthost.shell(cmd, module_ignore_errors=True)["stdout_lines"]
    return set(line.strip() for line in lines if line.strip())


def wait_principal_ckn(host, port, expected_ckn, timeout=60):
    """Block until ``port``'s principal CA is the one named by ``expected_ckn``."""
    expected = expected_ckn.lower()
    return wait_until(timeout, 2, 0,
                      lambda: get_principal_ckn(host, port) == expected)


def wait_macsec_ok(duthost, dut_port, nbr, timeout=300):
    """Block until MACsec is up on both ends of the link."""
    return wait_until(timeout, 3, 0,
                      lambda: duthost.iface_macsec_ok(dut_port) and
                      nbr["host"].iface_macsec_ok(nbr["port"]))


def wait_cas_live(host, port, shape, timeout=180):
    """Wait for every CA named in ``shape`` to have negotiated a live peer.

    ``shape`` is any mapping carrying ``primary_ckn`` and optionally
    ``fallback_ckn`` -- a :class:`DedicatedLink` shape or a deployed profile
    dict both qualify.
    """
    for field in ("primary_ckn", "fallback_ckn"):
        ckn = shape.get(field)
        if ckn and not wait_for_ckn_live(host, port, ckn, timeout=timeout):
            logger.error("CKN %s never reached live_peers>=1 on %s", ckn, port)
            return False
    return True


class DeployedLink(object):
    """A control link running its deployed profile."""

    def __init__(self, duthost, dut_port, nbr, upstream_ip, profile):
        self.duthost = duthost
        self.dut_port = dut_port
        self.nbr = nbr
        self.upstream_ip = upstream_ip
        self.profile = profile
        self.profile_name = profile["name"]

    @property
    def primary_ckn(self):
        return self.profile["primary_ckn"]

    @property
    def fallback_ckn(self):
        return self.profile.get("fallback_ckn")

    def wait_cas_live(self, timeout=180):
        return wait_cas_live(self.duthost, self.dut_port, self.profile, timeout)

    def release(self):
        """Give the port back so another fixture may use it."""
        _release_port(self.duthost, self.dut_port)


def make_deployed_link(duthost, ctrl_links, upstream_links, get_port_profile,
                       require_fallback=False):
    """Pick an unclaimed link that is still using its deployed profile."""
    tried = set()
    profiles_without_fallback = set()
    while True:
        dut_port, nbr = select_ctrl_link(
            ctrl_links, upstream_links, exclude_ports=tried | _claimed_ports(duthost))
        if dut_port is None:
            if require_fallback and profiles_without_fallback:
                pytest.skip(
                    "Available deployed MACsec profiles carry no fallback CA: "
                    "{}".format(", ".join(sorted(profiles_without_fallback))))
            pytest.skip("No control link still running its deployed MACsec profile is "
                        "available for MACsec key testing")
        tried.add(dut_port)

        profile = get_port_profile(dut_port)
        if require_fallback and not (profile.get("fallback_cak") and profile.get("fallback_ckn")):
            profiles_without_fallback.add(profile["name"])
            continue

        cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' 'macsec'".format(
            getns_prefix(duthost, dut_port), dut_port)
        if duthost.command(cmd)['stdout'].strip() == profile["name"]:
            _claim_port(duthost, dut_port)
            return DeployedLink(
                duthost, dut_port, nbr,
                upstream_links[dut_port]["local_ipv4_addr"], profile)
        logger.info("Port %s is not bound to its deployed profile %s; trying another link",
                    dut_port, profile["name"])


class DedicatedLink(object):
    """A control link using a profile not shared with other ports."""

    def __init__(self, duthost, dut_port, nbr, upstream_ip, base_profile,
                 profile_name, priority, cipher_suite, policy, send_sci):
        self.duthost = duthost
        self.dut_port = dut_port
        self.nbr = nbr
        self.upstream_ip = upstream_ip
        self.base_profile = base_profile
        self.profile_name = profile_name
        self.cipher_suite = cipher_suite
        self.policy = policy
        self.send_sci = send_sci
        self.dut_priority = priority
        self.nbr_priority = priority - 1
        self.shape = {}

    @property
    def hosts(self):
        """``[(host, port, priority)]`` for both ends of the link."""
        return [(self.duthost, self.dut_port, self.dut_priority),
                (self.nbr["host"], self.nbr["port"], self.nbr_priority)]

    def new_key_pair(self, *exclude_ckns):
        """A CAK/CKN pair for this link's cipher suite, distinct from the
        profile's current CKNs and from anything else named here.
        """
        excluded = [self.shape.get("primary_ckn"), self.shape.get("fallback_ckn")]
        excluded.extend(exclude_ckns)
        return generate_macsec_key_pair(self.cipher_suite, excluded)

    def create(self, primary_cak, primary_ckn, rekey_period=0,
               fallback_cak=None, fallback_ckn=None):
        """Add the dedicated profile on both ends and bind the link to it."""
        shape = dict(primary_cak=primary_cak, primary_ckn=primary_ckn,
                     rekey_period=rekey_period, fallback_cak=fallback_cak,
                     fallback_ckn=fallback_ckn)
        for host, port, priority in self.hosts:
            set_macsec_profile(host, self.profile_name, priority,
                               self.cipher_suite, primary_cak, primary_ckn,
                               self.policy, self.send_sci, rekey_period,
                               fallback_cak, fallback_ckn)
            enable_macsec_port(host, port, self.profile_name)
        self.shape = shape
        return shape

    def apply_shape(self, **overrides):
        """Replace both profiles with the current shape plus overrides."""
        shape = dict(self.shape)
        shape.update(overrides)
        for host, port, priority in self.hosts:
            replace_macsec_profile(host, port, self.profile_name, priority,
                                   self.cipher_suite, shape["primary_cak"],
                                   shape["primary_ckn"], self.policy,
                                   self.send_sci, shape["rekey_period"],
                                   shape["fallback_cak"], shape["fallback_ckn"])
        self.shape = shape
        return shape

    def settled(self):
        """Wait for MACsec, then for clean forwarding, then report success."""
        if not wait_macsec_ok(self.duthost, self.dut_port, self.nbr):
            logger.error("MACsec did not come back on %s", self.dut_port)
            return False
        return wait_link_settled(self.duthost, self.dut_port, self.upstream_ip)

    def wait_cas_live(self, timeout=180):
        """Wait for every CA the profile currently defines to have a live peer."""
        return wait_cas_live(self.duthost, self.dut_port, self.shape, timeout)

    def destroy(self):
        """Unbind the dedicated profile and drop it from both ends."""
        for host, port, _ in self.hosts:
            disable_macsec_port(host, port)
            delete_macsec_profile(host, self.profile_name)


def make_dedicated_link(duthost, ctrl_links, upstream_links, get_port_profile,
                        default_priority, cipher_suite, policy, send_sci,
                        rekey_period, require_sonic_peer=False):
    """Move an available control link onto an isolated two-CA profile."""
    dut_port, nbr = select_ctrl_link(ctrl_links, upstream_links,
                                     exclude_ports=_claimed_ports(duthost),
                                     require_sonic_peer=require_sonic_peer)
    if dut_port is None:
        peer_requirement = " to a SONiC neighbor" if require_sonic_peer else ""
        pytest.skip(
            "No control link{} with an upstream IP is available for MACsec "
            "key testing".format(peer_requirement))
    _claim_port(duthost, dut_port)

    base = get_port_profile(dut_port)
    link = DedicatedLink(
        duthost=duthost,
        dut_port=dut_port,
        nbr=nbr,
        upstream_ip=upstream_links[dut_port]["local_ipv4_addr"],
        base_profile=base,
        profile_name="{}_KEYTEST".format(base["name"]),
        priority=default_priority,
        cipher_suite=cipher_suite,
        policy=policy,
        send_sci=send_sci,
    )

    fallback_cak, fallback_ckn = generate_macsec_key_pair(
        cipher_suite, base["primary_ckn"])

    attempted_hosts = []
    try:
        for host, port, _ in link.hosts:
            attempted_hosts.append((host, port))
            disable_macsec_port(host, port)
        link.create(base["primary_cak"], base["primary_ckn"], rekey_period,
                    fallback_cak, fallback_ckn)
    except Exception as setup_error:
        cleanup_errors = []
        for host, port in attempted_hosts:
            try:
                try:
                    disable_macsec_port(
                        host, port, module_ignore_errors=True)
                    delete_macsec_profile(host, link.profile_name)
                finally:
                    enable_macsec_port(host, port, base["name"])
            except Exception as cleanup_error:
                cleanup_errors.append(
                    "{} {}: {}".format(
                        host.hostname, port, cleanup_error))
        if cleanup_errors:
            raise RuntimeError(
                "Dedicated MACsec setup failed and baseline restoration also "
                "failed on {}".format("; ".join(cleanup_errors))
            ) from setup_error
        _release_port(duthost, dut_port)
        raise
    return link


def restore_baseline_link(link):
    """Restore the deployed profile and verify forwarding."""
    link.destroy()
    for host, port, _ in link.hosts:
        enable_macsec_port(host, port, link.base_profile["name"])
    assert wait_macsec_ok(link.duthost, link.dut_port, link.nbr), \
        "Link {} did not recover on its baseline profile {}".format(
            link.dut_port, link.base_profile["name"])
    assert wait_link_settled(
        link.duthost, link.dut_port, link.upstream_ip), \
        "Link {} did not resume forwarding on its baseline profile {}".format(
            link.dut_port, link.base_profile["name"])
    _release_port(link.duthost, link.dut_port)
