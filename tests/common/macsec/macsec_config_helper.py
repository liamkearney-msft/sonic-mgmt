import ast
import logging
import re
import secrets
import time
from passlib.hash import cisco_type7

from tests.common.macsec.macsec_helper import get_mka_session, getns_prefix, wait_all_complete, \
     submit_async_task
from tests.common.macsec.macsec_platform_helper import global_cmd, find_portchannel_from_member, get_portchannel
from tests.common.config_reload import config_reload
from tests.common.devices.eos import EosHost
from tests.common.errors import RunAnsibleModuleFail
from tests.common.utilities import wait_until

__all__ = [
    'enable_macsec_feature',
    'disable_macsec_feature',
    'setup_macsec_configuration',
    'cleanup_macsec_configuration',
    'set_macsec_profile',
    'delete_macsec_profile',
    'replace_macsec_profile',
    'rotate_macsec_profile_key',
    'enable_macsec_port',
    'disable_macsec_port',
    'get_macsec_enable_status',
    'get_macsec_profile',
    'wait_for_macsec_cleanup',
    'generate_macsec_profile',
    'generate_macsec_key_pair',
    'setup_macsec_multi_profile_configuration',
    'cleanup_macsec_multi_profile_configuration',
]

logger = logging.getLogger(__name__)


def get_macsec_enable_status(host):
    # Retrieve the enable_macsec flag passed by user for this testrun
    request = host.duthosts.request
    return request.config.getoption("--enable_macsec", default=False)


def get_macsec_profile(host):
    # Retrieve the macsec_profile passed by user for this testrun
    request = host.duthosts.request
    return request.config.getoption("--macsec_profile", default=None)


def _eos_set_rekey_period(host, profile_name, rekey_period):
    """Arm a periodic SAK refresh on an EOS profile where the release allows it.

    ``mka session rekey-period`` is not accepted by every EOS release, and it
    does not have to be: the SAK is generated and distributed by whichever end
    wins the key server election, so only the key server acts on the period. A
    follower installs the SAKs it is sent regardless of its own configuration.

    A rejection is therefore logged and tolerated rather than raised. It only
    costs the test something when the peer is the key server, which is why
    callers that depend on a rekey actually happening check that separately.

    Returns True when the period was accepted.
    """
    try:
        host.eos_config(
            lines=['mka session rekey-period {}'.format(rekey_period)],
            parents=['mac security', 'profile {}'.format(profile_name)])
        return True
    except RunAnsibleModuleFail as err:
        logger.warning(
            "%s rejected 'mka session rekey-period %s' on profile %s: %s. "
            "Continuing: the peer follows SAKs distributed by the key server.",
            host.hostname, rekey_period, profile_name, err)
        return False


def set_macsec_profile(host, profile_name, priority, cipher_suite,
                       primary_cak, primary_ckn, policy, send_sci, rekey_period=0,
                       fallback_cak=None, fallback_ckn=None):
    if isinstance(host, EosHost):
        eos_cipher_suite = {
            "GCM-AES-128": "aes128-gcm",
            "GCM-AES-256": "aes256-gcm",
            "GCM-AES-XPN-128": "aes128-gcm-xpn",
            "GCM-AES-XPN-256": "aes256-gcm-xpn"
        }
        lines = [
            'cipher {}'.format(eos_cipher_suite[cipher_suite]),
            'key {} 7 {}'.format(primary_ckn, primary_cak),
            'mka key-server priority {}'.format(priority)
            ]
        # EOS marks the standby CA with the trailing `fallback` keyword; it
        # inherits the profile cipher suite exactly like the SONiC side.
        if fallback_cak and fallback_ckn:
            lines.append('key {} 7 {} fallback'.format(fallback_ckn, fallback_cak))
        if send_sci == 'true':
            lines.append('sci')
        host.eos_config(
            lines=lines,
            parents=['mac security', 'profile {}'.format(profile_name)])
        # Armed separately: not every EOS release accepts the rekey-period
        # line, and it is not required on both ends. See _eos_set_rekey_period.
        if rekey_period:
            _eos_set_rekey_period(host, profile_name, rekey_period)
        return

    macsec_profile = {
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": primary_cak,
        "primary_ckn": primary_ckn,
        "policy": policy,
        "send_sci" if send_sci == "true" else "no_send_sci": "",
        "rekey_period": rekey_period,
    }

    # Fallback CAK/CKN bring up a standby MKA participant alongside the primary.
    # They are optional; only emit them when both are provided.
    if fallback_cak and fallback_ckn:
        macsec_profile["fallback_cak"] = fallback_cak
        macsec_profile["fallback_ckn"] = fallback_ckn

    opts = ""
    for k, v in list(macsec_profile.items()):
        opts += " --{} {}".format(k, v)

    if host.is_multi_asic:
        for ns in host.get_asic_namespace_list():
            cmd = "config macsec -n {} profile add {} {}".format(ns, profile_name, opts)
            host.command(cmd)
    else:
        cmd = "config macsec profile add {} {}".format(profile_name, opts)
        host.command(cmd)

    if send_sci == "false":
        # The MAC address of SONiC host is locally administrated
        # So, LLDPd will use an arbitrary fixed value (00:60:08:69:97:ef)
        # as the source MAC address of LLDP packet (https://lldpd.github.io/usage.html)
        # But the MACsec driver in Linux used by SONiC VM has a bug that
        # cannot handle the packet with different source MAC address to SCI if the send_sci = false
        # So, if send_sci = false and the neighbor device is SONiC VM,
        # LLDPd need to use the real MAC address as the source MAC address
        host.command("lldpcli configure system bond-slave-src-mac-type real")


def is_macsec_configured(host, mac_profile, ctrl_links):
    """Check the DUT already carries exactly the profile the tests want.

    Two things are verified: the profile exists in every ASIC namespace with the
    key material we are about to use, and every control link is bound to it.
    Matching on the name alone is not enough -- a profile left behind by an
    earlier deployment can carry different keys (or no fallback CA at all),
    which would silently skip setup and then fail deep inside a test.
    """
    profile_name = mac_profile['name']
    expected = {
        field: str(mac_profile.get(field, ""))
        for field in ('cipher_suite', 'primary_cak', 'primary_ckn',
                      'fallback_cak', 'fallback_ckn', 'priority',
                      'policy', 'send_sci')
    }

    namespaces = host.get_asic_namespace_list() if host.is_multi_asic else [None]
    for ns in namespaces:
        ns_prefix = "-n {}".format(ns) if ns is not None else ""
        cmd = "sonic-db-cli {} CONFIG_DB HGETALL 'MACSEC_PROFILE|{}'".format(ns_prefix, profile_name)
        output = host.command(cmd)['stdout'].strip()
        if not output or output == "{}":
            logger.info("Profile %s is not configured in namespace %s", profile_name, ns)
            return False
        try:
            configured = ast.literal_eval(output)
        except (ValueError, SyntaxError):
            logger.warning("Could not parse profile %s in namespace %s: %s", profile_name, ns, output)
            return False
        for field, value in expected.items():
            if str(configured.get(field, "")) != value:
                logger.info("Profile %s in namespace %s has unexpected %s, needs reconfiguring",
                            profile_name, ns, field)
                return False

    for port in ctrl_links:
        cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' 'macsec'".format(getns_prefix(host, port), port)
        if host.command(cmd)['stdout'].strip() != profile_name:
            logger.info("Port %s is not bound to profile %s", port, profile_name)
            return False

    return True


def delete_macsec_profile(host, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no profile {}'.format(profile_name)],
            parents=['mac security'])
        return

    if host.is_multi_asic:
        for ns in host.get_asic_namespace_list():
            CMD_PREFIX = "-n {}".format(ns) if ns is not None else " "
            cmd = "config macsec {} profile del {}".format(CMD_PREFIX, profile_name)
            host.command(cmd, module_ignore_errors=True)
    else:
        cmd = ("config macsec profile del {}".format(profile_name))
        host.command(cmd, module_ignore_errors=True)


def _eos_rotate_macsec_profile_key(host, profile_name, old_ckn, new_ckn, new_cak):
    """EOS counterpart of rotate_macsec_profile_key().

    EOS has no CONFIG_DB and no single rotate command; a key is replaced by
    configuring the new one and negating the line that configured the old one.
    """
    old_line = _eos_profile_key_lines(host, profile_name).get(old_ckn.lower())
    if old_line is None:
        raise ValueError(
            "Profile {} on {} has no key {} to rotate".format(
                profile_name, host.hostname, old_ckn))

    # EOS marks the standby CA with a trailing `fallback` keyword. The
    # replacement has to keep the role of the key it replaces, otherwise the
    # rotation would promote or demote the CA instead of re-keying it.
    role = ' fallback' if old_line.endswith(' fallback') else ''
    # Configure the replacement before negating the old line so the profile is
    # never momentarily left without the CA being rotated. EOS rejects a bare
    # `no key <ckn>`, hence negating the configured line verbatim.
    host.eos_config(
        lines=['key {} 7 {}{}'.format(new_ckn, new_cak, role),
               'no {}'.format(old_line)],
        parents=['mac security', 'profile {}'.format(profile_name)])


def _eos_profile_key_lines(host, profile_name):
    """Return configured EOS profile key lines indexed by lowercase CKN."""
    output = host.eos_command(
        commands=["show running-config section mac security"])["stdout"][0]
    if not isinstance(output, str):
        output = str(output)
    lines = {}
    in_profile = False
    for raw in output.splitlines():
        line = raw.strip()
        match = re.match(r"^profile (\S+)$", line)
        if match:
            in_profile = (match.group(1) == profile_name)
            continue
        if line.startswith("interface "):
            in_profile = False
            continue
        if in_profile:
            key_match = re.match(
                r"^key (\S+) \d+ \S+(\s+fallback)?$", line)
            if key_match:
                lines[key_match.group(1).lower()] = line
    return lines


def rotate_macsec_profile_key(host, profile_name, old_ckn, new_ckn, new_cak):
    """Rotate one CA of a MACsec profile with ``config macsec profile update``.

    This is the production path for a CAK rollover. ``old_ckn`` names the key
    being replaced and so selects which CA is rotated -- the same call rotates
    the primary or the fallback. Every other field of the profile is left
    alone and the profile's other CA stays live, which is what keeps the port
    protected while the rotation runs.

    ``new_cak`` is cisco_type7 encoded, the form CONFIG_DB stores and the form
    ``set_macsec_profile`` already passes around.

    Args:
        host: SONiC or EOS host object.
        profile_name: MACsec profile to rotate a key of.
        old_ckn: CKN of the key being replaced.
        new_ckn: CKN of the replacement key.
        new_cak: cisco_type7 encoded CAK of the replacement key.

    Returns:
        list: the namespaces the rotation was applied to (``[None]`` on a
        single-ASIC host or on EOS).
    """
    if isinstance(host, EosHost):
        _eos_rotate_macsec_profile_key(host, profile_name, old_ckn, new_ckn, new_cak)
        return [None]

    namespaces = host.get_asic_namespace_list() if host.is_multi_asic else [None]
    rotated = []
    for ns in namespaces:
        prefix = "-n {} ".format(ns) if ns is not None else ""
        cmd = ("config macsec {}profile update {} --old_ckn {} --new_ckn {} "
               "--new_cak {}").format(prefix, profile_name, old_ckn, new_ckn, new_cak)
        result = host.command(cmd, module_ignore_errors=True)
        if not result["rc"]:
            rotated.append(ns)
            continue

        output = "{}\n{}".format(result.get("stdout", ""), result.get("stderr", ""))
        # A per-interface profile only exists in the namespace of the port it
        # belongs to, so the other namespaces legitimately do not know it.
        if "doesn't exist" in output:
            continue
        raise RuntimeError(
            "'{}' failed on {}: {}".format(cmd, host.hostname, output.strip()))

    if not rotated:
        raise RuntimeError(
            "MACsec profile {} does not exist in any namespace of {}".format(
                profile_name, host.hostname))
    return rotated


def replace_macsec_profile(host, port, profile_name, priority, cipher_suite,
                           primary_cak, primary_ckn, policy, send_sci,
                           rekey_period=0, fallback_cak=None, fallback_ckn=None):
    """Replace a MACsec profile wholesale, using config commands only.

    ``config macsec profile add`` refuses to touch a profile that already
    exists and ``config macsec profile del`` refuses to drop one a port is
    still bound to, so changing anything other than a key -- the cipher suite,
    the rekey period, or whether the profile carries a fallback CA at all -- is
    the unbind / delete / add / rebind sequence an operator would run.

    Unbinding drops the port for the duration of the replacement. That is also
    what restarts the CA, and restarting the CA is the only thing that arms a
    new ``rekey_period``: wpa_supplicant reads the period when the CA starts,
    so hot-updating it on a running session has no effect.

    The profile named here has to be bound to ``port`` and to nothing else, or
    the delete step will fail on whichever other port is still using it.
    """
    disable_macsec_port(host, port)
    delete_macsec_profile(host, profile_name)
    set_macsec_profile(host, profile_name, priority, cipher_suite, primary_cak,
                       primary_ckn, policy, send_sci, rekey_period,
                       fallback_cak, fallback_ckn)
    enable_macsec_port(host, port, profile_name)


def enable_macsec_port(host, port, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['mac security profile {}'.format(profile_name)],
            parents=['interface {}'.format(port)])
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))

    dnx_platform = host.facts.get("platform_asic") == 'broadcom-dnx'

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member del {} {}".format(getns_prefix(host, port), pc["name"], port))

    cmd = "config macsec {} port add {} {}".format(getns_prefix(host, port), port, profile_name)
    host.command(cmd)

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member add {} {}".format(getns_prefix(host, port), pc["name"], port))


def disable_macsec_port(host, port, module_ignore_errors=False):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no mac security profile'],
            parents=['interface {}'.format(port)],
            module_ignore_errors=module_ignore_errors)
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))
    dnx_platform = host.facts.get("platform_asic") == 'broadcom-dnx'

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member del {} {}".format(getns_prefix(host, port), pc["name"], port))

    cmd = "config macsec {} port del {}".format(getns_prefix(host, port), port)
    host.command(cmd, module_ignore_errors=module_ignore_errors)

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member add {} {}".format(getns_prefix(host, port), pc["name"], port))


def replace_macsec_port(host, port, profile_name):
    disable_macsec_port(host, port)
    time.sleep(10)
    enable_macsec_port(host, port, profile_name)


def enable_macsec_feature(duthost, macsec_nbrhosts):
    nbrhosts = macsec_nbrhosts
    num_asics = duthost.num_asics()
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")

    def check_macsec_enabled():
        if len(duthost.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < num_asics:
            return False
        if len(duthost.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < num_asics:
            return False
        for nbr in [n["host"] for n in list(nbrhosts.values())]:
            if isinstance(nbr, EosHost):
                continue
            if len(nbr.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < 1:
                return False
            if len(nbr.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < 1:
                return False
        return True
    assert wait_until(180, 5, 10, check_macsec_enabled)


def disable_macsec_feature(duthost, macsec_nbrhosts):
    global_cmd(duthost, macsec_nbrhosts, "sudo config feature state macsec disabled")


def _wait_for_macsec_cleanup_with_vs_recovery(host, interfaces, is_dut):
    if wait_for_macsec_cleanup(host, interfaces):
        return False

    if host.facts["asic_type"] != "vs":
        return False

    logger.warning(
        "MACsec cleanup timed out on %s; reloading config to clear "
        "stale VS state",
        host.hostname,
    )
    if is_dut:
        config_reload(
            host,
            config_source="config_db",
            safe_reload=True,
            yang_validate=False,
        )
    else:
        host.shell("sudo config reload -y -f", executable="/bin/bash")
        assert wait_until(
            200, 10, 0, host.is_service_fully_started, "database"), \
            "Database did not recover on {}".format(host.hostname)
        assert wait_until(
            420, 10, 0, host.critical_processes_running, "swss"), \
            "Swss did not recover on {}".format(host.hostname)

    assert wait_for_macsec_cleanup(host, interfaces), \
        "MACsec entries remain on {} after config reload".format(host.hostname)
    return True


def _restore_macsec_feature_after_cleanup_recovery(
        duthost, ctrl_links):
    nbrhosts = {nbr["name"]: nbr for nbr in ctrl_links.values()}
    enable_macsec_feature(duthost, nbrhosts)


def cleanup_macsec_configuration(duthost, ctrl_links, profile_name):
    devices = set()
    if duthost.facts["asic_type"] == "vs":
        devices.add(duthost)

    logger.info("Cleanup macsec configuration step1: disable macsec port")
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        submit_async_task(disable_macsec_port, (duthost, dut_port))
        submit_async_task(disable_macsec_port, (nbr["host"], nbr["port"]))
        devices.add(nbr["host"])
    wait_all_complete(timeout=300)

    logger.info("Cleanup macsec configuration step2: delete macsec profile")
    # Delete the macsec profile once after it is removed from all interfaces.
    # On multi-asic the profile is removed from the DB in all namespaces.
    submit_async_task(delete_macsec_profile, (duthost, profile_name))

    # Delete the macsec profile in neighbors
    for d in devices:
        submit_async_task(delete_macsec_profile, (d, profile_name))
    wait_all_complete(timeout=300)

    logger.info("Cleanup macsec configuration step3: wait for automatic cleanup")

    # Extract DUT interface names from ctrl_links and wait for automatic
    # MACsec cleanup on the DUT side.
    interfaces = list(ctrl_links.keys())
    recovered = _wait_for_macsec_cleanup_with_vs_recovery(
        duthost, interfaces, is_dut=True)

    # Also wait for neighbor devices to complete automatic cleanup for their
    # corresponding ports.
    for dut_port, nbr in list(ctrl_links.items()):
        neighbor_recovered = _wait_for_macsec_cleanup_with_vs_recovery(
            nbr["host"], [nbr["port"]], is_dut=False)
        recovered = neighbor_recovered or recovered

    if recovered:
        _restore_macsec_feature_after_cleanup_recovery(
            duthost, ctrl_links)

    logger.info("Cleanup macsec configuration finished")

    # Waiting for all MKA sessions to be cleared on neighbor devices.
    for d in devices:
        if isinstance(d, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda d=d: not get_mka_session(d))


def setup_macsec_configuration(duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period, tbinfo,
                               fallback_cak=None, fallback_ckn=None):
    logger.info("Setup macsec configuration step1: set macsec profile")
    # 1. Set macsec profile. The profile is host-wide (no port arg), so the
    # DUT-side set runs once outside the per-link loop.
    submit_async_task(set_macsec_profile, (duthost, profile_name, default_priority,
                      cipher_suite, primary_cak, primary_ckn, policy,
                      send_sci, rekey_period, fallback_cak, fallback_ckn))
    i = 0
    for dut_port, nbr in ctrl_links.items():
        if i % 2 == 0:
            priority = default_priority - 1
        else:
            priority = default_priority + 1
        submit_async_task(set_macsec_profile,
                          (nbr["host"], profile_name, priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period,
                           fallback_cak, fallback_ckn))
        i += 1
    wait_all_complete(timeout=180)

    logger.info("Setup macsec configuration step2: enable macsec profile")
    # 2. Enable macsec profile
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        submit_async_task(enable_macsec_port, (duthost, dut_port, profile_name))
        submit_async_task(enable_macsec_port, (nbr["host"], nbr["port"], profile_name))
    wait_all_complete(timeout=180)

    # 3. Wait for interface's macsec ready
    for dut_port, nbr in list(ctrl_links.items()):
        assert wait_until(300, 3, 0,
                          lambda: duthost.iface_macsec_ok(dut_port) and
                          nbr["host"].iface_macsec_ok(nbr["port"]))

    # Enabling macsec may cause link flap, which impacts LACP, BGP, etc
    # protocols. To hold some time for protocol recovery.
    time.sleep(60)
    logger.info("Setup macsec configuration finished")


def generate_macsec_key_pair(cipher_suite="GCM-AES-128", exclude_ckns=()):
    """Generate a random CAK/CKN pair valid for ``cipher_suite``.

    The cipher suite fixes the key lengths: the AES-128 variants take a 32
    character CAK and CKN, the AES-256 variants take 64. ``secrets.token_hex``
    is asked for half that many bytes because it renders every byte as two
    characters, and the CKN is carried as the literal string it produces.

    The CAK is returned cisco_type7 encoded, which is how CONFIG_DB stores it
    and what both ``config macsec profile add`` and the EOS ``key ... 7 ...``
    syntax expect.

    Args:
        cipher_suite: Cipher suite the key pair has to satisfy.
        exclude_ckns: A CKN, or an iterable of CKNs, the generated one must not
            collide with. A CA is keyed by its CKN, so every key that has to
            coexist with -- or replace -- another one needs a distinct name.

    Returns:
        tuple: ``(cak, ckn)``, the CAK cisco_type7 encoded and the CKN plain hex.
    """
    if isinstance(exclude_ckns, str):
        exclude_ckns = (exclude_ckns,)
    excluded = {ckn.lower() for ckn in exclude_ckns if ckn}

    num_bytes = 16 if "128" in cipher_suite else 32
    while True:
        ckn = secrets.token_hex(num_bytes)
        if ckn.lower() not in excluded:
            return cisco_type7.hash(secrets.token_hex(num_bytes)), ckn


def generate_macsec_profile(port_name, cipher_suite="GCM-AES-128", priority=64,
                            policy="security", send_sci="true", rekey_period=0,
                            include_fallback=False):
    """Generate a MACsec profile with random CAK/CKN for a specific port.

    The profile is named ``MACSEC_PROFILE_<port_name>`` and the pre-shared keys
    are generated by :func:`generate_macsec_key_pair` so that every port
    receives a unique key pair.

    Args:
        port_name: Interface name (e.g. "Ethernet0"). Used in the profile name.
        cipher_suite: Cipher suite string. Determines key lengths.
        priority: MKA key-server priority (0-255).
        policy: "security" (encrypt) or "integrity_only" (auth only).
        send_sci: "true" or "false".
        rekey_period: Seconds between rekeying (0 = disabled).
        include_fallback: Generate a distinct fallback CAK/CKN for the port.

    Returns:
        dict: A profile dict compatible with set_macsec_profile().
    """
    cak, ckn = generate_macsec_key_pair(cipher_suite)

    profile = {
        "name": "MACSEC_PROFILE_{}".format(port_name),
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": cak,
        "primary_ckn": ckn,
        "policy": policy,
        "send_sci": send_sci,
        "rekey_period": rekey_period,
    }
    if include_fallback:
        fallback_cak, fallback_ckn = generate_macsec_key_pair(
            cipher_suite, ckn)
        profile["fallback_cak"] = fallback_cak
        profile["fallback_ckn"] = fallback_ckn
    return profile


def setup_macsec_multi_profile_configuration(duthost, ctrl_links, port_profiles, tbinfo):
    """Set up MACsec with a different profile per port.

    Each port in *ctrl_links* is configured with its own profile from
    *port_profiles*.  The DUT uses ``default_priority`` from the profile while
    neighbors alternate between ``priority - 1`` and ``priority + 1`` so the
    DUT is elected MKA key-server on most links.

    Args:
        duthost: DUT host object.
        ctrl_links: dict ``{dut_port: {name, host, port, ...}}``.
        port_profiles: dict ``{dut_port: profile_dict}`` where each
            ``profile_dict`` has keys matching ``generate_macsec_profile``
            output.
        tbinfo: Testbed info dict.
    """
    logger.info("Multi-profile setup step 1: set per-port macsec profiles")

    for dut_port, profile in port_profiles.items():
        set_macsec_profile(
            duthost, profile["name"], profile["priority"],
            profile["cipher_suite"], profile["primary_cak"],
            profile["primary_ckn"], profile["policy"],
            profile["send_sci"], profile["rekey_period"],
            profile.get("fallback_cak"), profile.get("fallback_ckn"))
    i = 0
    for dut_port, nbr in ctrl_links.items():
        profile = port_profiles[dut_port]

        if i % 2 == 0:
            nbr_priority = profile["priority"] - 1
        else:
            nbr_priority = profile["priority"] + 1
        set_macsec_profile(
            nbr["host"], profile["name"], nbr_priority,
            profile["cipher_suite"], profile["primary_cak"],
            profile["primary_ckn"], profile["policy"],
            profile["send_sci"], profile["rekey_period"],
            profile.get("fallback_cak"), profile.get("fallback_ckn"))
        i += 1
        time.sleep(3)

    logger.info("Multi-profile setup step 2: enable per-port macsec")

    for dut_port, nbr in list(ctrl_links.items()):
        profile = port_profiles[dut_port]
        time.sleep(3)
        enable_macsec_port(duthost, dut_port, profile["name"])
        enable_macsec_port(nbr["host"], nbr["port"], profile["name"])

    logger.info("Multi-profile setup step 3: wait for macsec ready on each port")

    for dut_port, nbr in list(ctrl_links.items()):
        assert wait_until(300, 3, 0,
                          lambda dp=dut_port, n=nbr: duthost.iface_macsec_ok(dp) and
                          n["host"].iface_macsec_ok(n["port"]))

    # Hold time for protocol recovery after link flaps.
    time.sleep(60)
    logger.info("Multi-profile setup finished")


def cleanup_macsec_multi_profile_configuration(duthost, ctrl_links, port_profiles):
    """Clean up per-port MACsec profiles.

    Disables MACsec on every controlled port, then deletes each unique profile
    from CONFIG_DB on both the DUT and neighbor devices.

    Args:
        duthost: DUT host object.
        ctrl_links: dict ``{dut_port: {name, host, port, ...}}``.
        port_profiles: dict ``{dut_port: profile_dict}``.
    """
    devices = set()
    if duthost.facts["asic_type"] == "vs":
        devices.add(duthost)

    logger.info("Multi-profile cleanup step 1: disable macsec on all ports")
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        disable_macsec_port(duthost, dut_port)
        disable_macsec_port(nbr["host"], nbr["port"])
        devices.add(nbr["host"])

    logger.info("Multi-profile cleanup step 2: delete per-port profiles")
    deleted_profiles = set()
    for dut_port, nbr in list(ctrl_links.items()):
        profile_name = port_profiles[dut_port]["name"]
        if profile_name not in deleted_profiles:
            delete_macsec_profile(duthost, profile_name)
            deleted_profiles.add(profile_name)

    for d in devices:
        for profile_name in deleted_profiles:
            delete_macsec_profile(d, profile_name)

    logger.info("Multi-profile cleanup step 3: wait for automatic cleanup")

    interfaces = list(ctrl_links.keys())
    recovered = _wait_for_macsec_cleanup_with_vs_recovery(
        duthost, interfaces, is_dut=True)

    for dut_port, nbr in list(ctrl_links.items()):
        neighbor_recovered = _wait_for_macsec_cleanup_with_vs_recovery(
            nbr["host"], [nbr["port"]], is_dut=False)
        recovered = neighbor_recovered or recovered

    if recovered:
        _restore_macsec_feature_after_cleanup_recovery(
            duthost, ctrl_links)

    logger.info("Multi-profile cleanup finished")

    for d in devices:
        if isinstance(d, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda d=d: not get_mka_session(d))


def wait_for_macsec_cleanup(host, interfaces, timeout=90):
    """Wait for MACsec daemon to automatically clean up all MACsec entries.

    This function implements proper synchronization to wait for the automatic
    cleanup process to complete, preserving the intended MACsec cleanup behavior.

    Args:
        host: SONiC DUT or neighbor host object
        interfaces: List of interface names to check
        timeout: Maximum time to wait in seconds for MACsec cleanup to finish (default: 90).

    Returns:
        bool: True if cleanup completed, False if timeout
    """
    if isinstance(host, EosHost):
        # EOS hosts don't use Redis databases
        logger.info("EOS host detected, skipping Redis cleanup verification")
        return True

    logger.info(f"Waiting for automatic MACsec cleanup (timeout: {timeout}s)")

    start_time = time.time()
    # Poll at most ~10 times over the full timeout, capped at 10 seconds between checks.
    poll_interval = min(10, max(1, timeout / 10.0))

    # We only care about APPL_DB and STATE_DB for MACsec tables. Instead of
    # trying to reverse-engineer numeric DB IDs from CONFIG_DB, rely on
    # sonic-db-cli with logical DB names and the same namespace logic used
    # elsewhere in MACsec helpers.

    while time.time() - start_time < timeout:
        all_clean = True
        remaining_entries = {}

        for interface in interfaces:
            ns_prefix = getns_prefix(host, interface)

            for db_name, sep in (("APPL_DB", ":"), ("STATE_DB", "|")):
                pattern = f"MACSEC_*{sep}{interface}*"
                cmd = f"sonic-db-cli {ns_prefix} {db_name} KEYS '{pattern}'"

                try:
                    result = host.command(cmd, verbose=False)
                    out_lines = result.get("stdout_lines", [])
                except Exception as e:
                    logger.warning(
                        "Failed to query MACsec keys on host %s, DB %s, interface %s: %r",
                        getattr(host, 'hostname', host),
                        db_name,
                        interface,
                        e,
                    )
                    # If we cannot query Redis for this DB/interface, be
                    # conservative and assume cleanup is not complete yet.
                    all_clean = False
                    continue

                keys = [k.strip() for k in out_lines if k.strip()]
                if keys:
                    all_clean = False
                    remaining_entries.setdefault((db_name, interface), []).extend(keys)

        elapsed = time.time() - start_time

        if all_clean:
            logger.info(
                f"Automatic MACsec cleanup completed successfully in {elapsed:.1f}s"
            )
            return True

        # Log progress every 30 seconds to reduce verbosity
        if int(elapsed) % 30 == 0 and elapsed > 0:
            logger.info(f"Still waiting for cleanup... ({elapsed:.0f}s elapsed)")

        time.sleep(poll_interval)

    # Timeout reached
    elapsed = time.time() - start_time
    logger.warning(f"Automatic MACsec cleanup timeout after {elapsed:.1f}s")

    # Log summary of remaining entries
    total_remaining = sum(len(entries) for entries in remaining_entries.values())
    if total_remaining > 0:
        logger.warning(
            f"  {total_remaining} MACsec entries still remain after timeout"
        )

    return False
