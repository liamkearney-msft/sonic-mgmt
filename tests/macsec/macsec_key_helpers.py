"""Shared scaffolding for the MACsec fallback-CA and key-rotation tests.

Both suites need the same three things: a control link they are allowed to
disrupt, a way to measure whether disrupting it cost any packets, and a way to
put that link on a MACsec profile of their own so a profile can be replaced
without touching the rest of the DUT.

Everything here drives the DUT and its neighbor the way an operator does, with
``config macsec ...`` commands. CONFIG_DB is written once, at deployment; from
then on the CLI is the only supported way to change a profile, so tests that
reach past it into CONFIG_DB or into the wpa_supplicant control socket are not
testing the product.
"""
import logging
import re
import time

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

# Packet-loss tolerance (percent) across a rekey or a hitless CAK rotation.
# Matches the continuity tolerance used by test_controlplane.py.
LOSS_TOLERANCE = 1.0

# A deliberately short rekey period so a test can watch several automatic SAK
# rotations inside a sane measurement window.
REKEY_PERIOD = 5
# A rotation completes a while after the timer fires -- the SAK still has to be
# distributed and installed on both ends -- so window sizes are derived from
# this observed worst case rather than from the period itself.
REKEY_INTERVAL_MAX = 15

# A link that merely pings is not a link that has settled: rebinding a MACsec
# profile bounces the port, and forwarding resumes well before MKA and the
# routing session on top of it have finished converging. Demand this many
# consecutive clean probes so a measurement window opens on a stable link.
_SETTLE_CLEAN_PROBES = 4


def _nbr_key(host):
    """Stable identity for a neighbor host object."""
    return getattr(host, "hostname", None) or id(host)


def peer_links(ctrl_links, nbr):
    """Every ``(dut_port, nbr_port)`` control link terminating on ``nbr``'s host.

    A MACsec key belongs to a *profile*, and a neighbor normally binds a single
    profile to every interface it has towards the DUT. Changing a key therefore
    changes all of those links at once, so the matching DUT-side ports have to
    be treated together -- otherwise the ports left untouched no longer share a
    CAK with their peer and go dark.
    """
    want = _nbr_key(nbr["host"])
    return [(dut_port, entry["port"]) for dut_port, entry in ctrl_links.items()
            if _nbr_key(entry["host"]) == want]


def select_ctrl_link(ctrl_links, upstream_links):
    """Return one ``(dut_port, nbr)`` control link that has an upstream IP we
    can ping for continuity measurement, or ``(None, None)``.

    Links are ranked so that a neighbor owning exactly one link to the DUT wins
    over one owning several. A multi-link neighbor shares its MACsec profile
    across those links, so profile edits leak onto the siblings, and the links
    are usually LAG members -- which lets the continuity ping hash onto a
    member that is not the one under test and silently measure nothing.
    """
    link_count = {}
    for entry in ctrl_links.values():
        key = _nbr_key(entry["host"])
        link_count[key] = link_count.get(key, 0) + 1

    best = {}
    for dut_port, nbr in ctrl_links.items():
        if dut_port not in upstream_links:
            continue
        rank = (isinstance(nbr["host"], EosHost),
                link_count[_nbr_key(nbr["host"])] > 1)
        best.setdefault(rank, (dut_port, nbr))
    for rank in ((False, False), (True, False), (False, True), (True, True)):
        if rank in best:
            return best[rank]
    return None, None


def start_bg_ping(duthost, dut_port, dst_ip, duration, tmp_file):
    """Launch a detached background ping across the MACsec link.

    The ping runs for ``duration`` seconds at 10 pps; running it under nohup
    keeps it alive past the SSH session so a long continuity window does not
    trip the Ansible SSH timeout (same approach as test_controlplane.py).
    """
    duthost.shell(
        "bash -c 'sudo nohup {} ping {} -q -w {} -i 0.1 > {} &'".format(
            get_ipnetns_prefix(duthost, dut_port), dst_ip, duration, tmp_file))


def read_ping_loss(duthost, tmp_file):
    """Return the percentage of packets lost by a background ping."""
    output = duthost.command("cat {}".format(tmp_file))["stdout_lines"]
    duthost.command("rm -f {}".format(tmp_file))
    return float(re.search(r"([\d\.]+)% packet loss", output[-2]).group(1))


def _bgp_established(duthost, dut_port, peer_ip):
    """Return True once the BGP session towards ``peer_ip`` is Established.

    The routing session is the most demanding consumer of the link -- it only
    comes back after MKA has installed SAs and traffic has flowed steadily for
    a while -- which makes it a far better "this link has converged" signal
    than a single successful ping.
    """
    match = re.search(r"asic(\d+)", get_ipnetns_prefix(duthost, dut_port))
    vtysh = "sudo vtysh -n {}".format(match.group(1)) if match else "sudo vtysh"
    output = duthost.shell(
        '{} -c "show bgp neighbors {}"'.format(vtysh, peer_ip),
        module_ignore_errors=True)["stdout"]
    return "BGP state = Established" in output


def wait_link_settled(duthost, dut_port, dst_ip, timeout=300):
    """Block until the link forwards cleanly again, then return True.

    A continuity measurement only means something if the link is already
    healthy when the window opens. Provisioning performed by an earlier test --
    replacing a MACsec profile, restoring a baseline CA -- tears the SecY down
    and brings it back up, and that recovery takes several seconds. Measuring
    across it would charge the leftover outage to whatever event this test is
    about to trigger.
    """
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
    """Every SAK currently installed on ``dut_port``'s ``direction`` SC.

    A rekey is make-before-break, so both the outgoing and the incoming SAK are
    briefly present. Sampling the set (rather than the association number, which
    only alternates between 0 and 1) is what lets a caller count rotations.

    This reads the DUT and nothing else, which is the point: ``get_appl_db``
    answers the same question but reaches the neighbor through
    ``get_dut_iface_mac``, and on a routed EOS interface that toggles
    ``switchport`` to make the address readable -- dropping the link for several
    seconds each call. Never put it inside a window that measures continuity.
    """
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


class DedicatedLink(object):
    """One control link running a MACsec profile that only it is bound to.

    A profile cannot be replaced while a port other than the one under test is
    using it -- ``config macsec profile del`` refuses -- and in single-profile
    mode the module-wide profile is bound to every controlled port on the DUT.
    Moving one link onto a profile of its own is therefore what makes the
    profile-replacement and key-rotation scenarios possible at all, and it is
    also what keeps them from disturbing the other 30-odd links while they run.

    The same indirection makes the suites work unchanged under
    ``--per_interface_macsec``: the dedicated profile is derived from whatever
    profile the selected port actually runs, so the port is restored to its own
    per-interface profile on teardown rather than being silently moved onto the
    module-wide one.
    """

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
        # setup_macsec_configuration gives the DUT the configured priority and
        # the first neighbor one step below it; mirror that so key-server
        # election on this link matches every other link on the testbed.
        self.dut_priority = priority
        self.nbr_priority = priority - 1
        # The shape the fixture guarantees on entry to every test, and the one
        # each test has to hand back. Updated by apply_shape().
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
        """Replace the dedicated profile wholesale on both ends.

        This is the full-replacement path an operator uses to change anything
        the rotate command cannot: the cipher suite, the rekey period, or
        whether the profile carries a fallback CA at all. Fields not named here
        keep their current value; pass ``fallback_cak=None`` and
        ``fallback_ckn=None`` to drop the standby CA.
        """
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
        for field in ("primary_ckn", "fallback_ckn"):
            ckn = self.shape.get(field)
            if ckn and not wait_for_ckn_live(self.duthost, self.dut_port, ckn,
                                             timeout=timeout):
                logger.error("CKN %s never reached live_peers>=1 on %s",
                             ckn, self.dut_port)
                return False
        return True

    def destroy(self):
        """Unbind the dedicated profile and drop it from both ends."""
        for host, port, _ in self.hosts:
            disable_macsec_port(host, port)
            delete_macsec_profile(host, self.profile_name)


def make_dedicated_link(duthost, ctrl_links, upstream_links, get_port_profile,
                        default_priority, cipher_suite, policy, send_sci,
                        rekey_period, with_fallback=True):
    """Build a :class:`DedicatedLink`, or skip if the testbed has no usable link.

    ``with_fallback`` provisions a standby CA alongside the primary. It is on by
    default because ``config macsec profile update`` refuses to rotate the
    primary key of a profile that is in use and has no fallback -- there would
    be nothing left protecting the port while the primary is replaced -- so a
    rotation scenario needs the two-CA shape to exist at all.
    """
    dut_port, nbr = select_ctrl_link(ctrl_links, upstream_links)
    if dut_port is None:
        pytest.skip("No control link with an upstream IP is available for "
                    "MACsec key testing")

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

    fallback_cak = fallback_ckn = None
    if with_fallback:
        fallback_cak, fallback_ckn = generate_macsec_key_pair(
            cipher_suite, base["primary_ckn"])

    # Take the link off the shared profile before putting it on its own, so the
    # port is never bound to two profiles and the peer never sees a CA it does
    # not have.
    disable_macsec_port(duthost, dut_port)
    disable_macsec_port(nbr["host"], nbr["port"])
    link.create(base["primary_cak"], base["primary_ckn"], rekey_period,
                fallback_cak, fallback_ckn)
    return link


def restore_baseline_link(link):
    """Put the link back on the profile it ran before the suite touched it.

    Only the binding has to be restored: taking the port off the shared profile
    never removed that profile from either host -- in single-profile mode the
    other 30-odd ports are still using it, and in per-interface mode the port's
    own profile is simply left unbound.
    """
    link.destroy()
    for host, port, _ in link.hosts:
        enable_macsec_port(host, port, link.base_profile["name"])
    if not wait_macsec_ok(link.duthost, link.dut_port, link.nbr):
        logger.error("Link %s did not recover on its baseline profile %s",
                     link.dut_port, link.base_profile["name"])
    # Enabling MACsec flaps the port, which takes LACP and BGP with it; hold
    # for protocol recovery the way setup_macsec_configuration does.
    time.sleep(60)
