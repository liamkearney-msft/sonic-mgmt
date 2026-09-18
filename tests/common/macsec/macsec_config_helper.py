import logging
import re
import secrets
import shlex
import time
from passlib.hash import cisco_type7

from tests.common.macsec.macsec_helper import get_mka_session, getns_prefix, wait_all_complete, \
     submit_async_task
from tests.common.macsec.macsec_platform_helper import global_cmd, find_portchannel_from_member, get_portchannel
from tests.common.config_reload import config_reload
from tests.common.devices.eos import EosHost
from tests.common.utilities import wait_until

__all__ = [
    'enable_macsec_feature',
    'disable_macsec_feature',
    'setup_macsec_configuration',
    'cleanup_macsec_configuration',
    'set_macsec_profile',
    'delete_macsec_profile',
    'enable_macsec_port',
    'disable_macsec_port',
    'get_macsec_enable_status',
    'get_macsec_profile',
    'wait_for_macsec_cleanup',
    'macsec_profile_has_fallback',
    'ensure_macsec_profile_fallback',
    'generate_macsec_key_pair',
    'generate_macsec_profile',
    'generate_per_interface_macsec_profile',
    'generate_per_interface_macsec_profiles',
    'update_macsec_profile_key',
    'add_runtime_macsec_key',
    'delete_runtime_macsec_key',
    'list_runtime_macsec_participants',
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


def macsec_profile_has_fallback(profile):
    """Return whether *profile* contains a complete fallback CAK/CKN pair."""
    has_cak = bool(profile.get("fallback_cak"))
    has_ckn = bool(profile.get("fallback_ckn"))
    if has_cak != has_ckn:
        raise ValueError(
            "fallback_cak and fallback_ckn must be supplied together")
    return has_cak


def ensure_macsec_profile_fallback(profile):
    """Return a profile with a fallback pair, preserving one already present."""
    profile = dict(profile)
    if macsec_profile_has_fallback(profile):
        return profile, False
    fallback_cak, fallback_ckn = generate_macsec_key_pair(
        profile["cipher_suite"])
    profile.update({
        "fallback_cak": fallback_cak,
        "fallback_ckn": fallback_ckn,
    })
    return profile, True


def _build_macsec_profile_options(priority, cipher_suite, primary_cak,
                                  primary_ckn, policy, send_sci,
                                  rekey_period=0, fallback_cak=None,
                                  fallback_ckn=None):
    """Build ``config macsec profile add`` options."""
    if bool(fallback_cak) != bool(fallback_ckn):
        raise ValueError(
            "fallback_cak and fallback_ckn must be supplied together")
    if fallback_ckn and fallback_ckn.lower() == primary_ckn.lower():
        raise ValueError("primary and fallback CKNs must differ")

    macsec_profile = {
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": primary_cak,
        "primary_ckn": primary_ckn,
        "policy": policy,
        "send_sci" if send_sci == "true" else "no_send_sci": "",
        "rekey_period": rekey_period,
    }
    if fallback_cak:
        macsec_profile.update({
            "fallback_cak": fallback_cak,
            "fallback_ckn": fallback_ckn,
        })

    return "".join(
        " --{} {}".format(name, value)
        for name, value in macsec_profile.items()
    )


def _build_eos_macsec_profile_lines(
        priority, cipher_suite, primary_cak, primary_ckn, send_sci,
        rekey_period=0, fallback_cak=None, fallback_ckn=None):
    if bool(fallback_cak) != bool(fallback_ckn):
        raise ValueError(
            "fallback_cak and fallback_ckn must be supplied together")
    if fallback_ckn and fallback_ckn.lower() == primary_ckn.lower():
        raise ValueError("primary and fallback CKNs must differ")

    eos_cipher_suite = {
        "GCM-AES-128": "aes128-gcm",
        "GCM-AES-256": "aes256-gcm",
        "GCM-AES-XPN-128": "aes128-gcm-xpn",
        "GCM-AES-XPN-256": "aes256-gcm-xpn"
    }
    lines = [
        'cipher {}'.format(eos_cipher_suite[cipher_suite]),
        'key {} 7 {}'.format(primary_ckn, primary_cak),
    ]
    if fallback_cak:
        lines.append(
            'key {} 7 {} fallback'.format(
                fallback_ckn, fallback_cak))
    lines.append('mka key-server priority {}'.format(priority))
    if rekey_period:
        lines.append('mka session rekey-period {}'.format(rekey_period))
    if send_sci == 'true':
        lines.append('sci')
    return lines


def set_macsec_profile(host, profile_name, priority, cipher_suite,
                       primary_cak, primary_ckn, policy, send_sci,
                       rekey_period=0, fallback_cak=None, fallback_ckn=None):
    if isinstance(host, EosHost):
        lines = _build_eos_macsec_profile_lines(
            priority, cipher_suite, primary_cak, primary_ckn, send_sci,
            rekey_period, fallback_cak, fallback_ckn)
        host.eos_config(
            lines=lines,
            parents=['mac security', 'profile {}'.format(profile_name)])
        return

    opts = _build_macsec_profile_options(
        priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci,
        rekey_period, fallback_cak, fallback_ckn)

    if host.is_multi_asic:
        for ns in host.get_asic_namespace_list():
            cmd = "config macsec -n {} profile add {} {}".format(ns, profile_name, opts)
            host.command(cmd, verbose=False)
    else:
        cmd = "config macsec profile add {} {}".format(profile_name, opts)
        host.command(cmd, verbose=False)

    if send_sci == "false":
        # The MAC address of SONiC host is locally administrated
        # So, LLDPd will use an arbitrary fixed value (00:60:08:69:97:ef)
        # as the source MAC address of LLDP packet (https://lldpd.github.io/usage.html)
        # But the MACsec driver in Linux used by SONiC VM has a bug that
        # cannot handle the packet with different source MAC address to SCI if the send_sci = false
        # So, if send_sci = false and the neighbor device is SONiC VM,
        # LLDPd need to use the real MAC address as the source MAC address
        host.command("lldpcli configure system bond-slave-src-mac-type real")


def _eos_macsec_key_line(ckn, cak, is_fallback=False, remove=False):
    line = "key {} 7 {}".format(ckn, cak)
    if is_fallback:
        line += " fallback"
    if remove:
        line = "no " + line
    return line


def update_macsec_profile_key(
        host, profile_name, old_cak, old_ckn, new_cak, new_ckn,
        is_fallback=False, namespace_option=None, expect_success=True):
    """Rotate one primary or fallback CAK/CKN pair without detaching ports."""
    if isinstance(host, EosHost):
        result = host.eos_config(
            lines=[
                _eos_macsec_key_line(
                    new_ckn, new_cak, is_fallback=is_fallback),
                _eos_macsec_key_line(
                    old_ckn, old_cak, is_fallback=is_fallback, remove=True),
            ],
            parents=['mac security', 'profile {}'.format(profile_name)])
        failed = result.get("failed", False)
        assert failed != expect_success, (
            "Unexpected EOS MACsec key rotation result on {}"
        ).format(host.hostname)
        return [result]

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
        result = host.command(
            command, module_ignore_errors=True, verbose=False)
        results.append(result)
        failed = result.get("failed", False)
        assert failed != expect_success, (
            "Unexpected SONiC MACsec key rotation result on {}"
        ).format(host.hostname)
    return results


def _get_macsec_container_name(host, port):
    asic = host.get_port_asic_instance(port)
    return asic.get_docker_name("macsec")


def _parse_wpa_global_socket(socket_output, process_output):
    socket = socket_output.strip()
    if socket:
        return socket
    match = re.search(r"(?:^|\s)-g\s*(\S+)", process_output)
    return match.group(1) if match else ""


def _get_wpa_global_socket(host, port):
    container = _get_macsec_container_name(host, port)
    result = host.command(
        "docker exec {} sh -c {}".format(
            container,
            shlex.quote(
                "find /var/run /run -type s -name global -print -quit "
                "2>/dev/null")),
        verbose=False,
    )
    socket_output = result.get("stdout", "")
    process_output = ""
    if not socket_output.strip():
        process = host.command(
            "docker exec {} sh -c {}".format(
                container,
                shlex.quote(
                    "ps -eo args | grep '[w]pa_supplicant' | head -1")),
            verbose=False,
        )
        process_output = process.get("stdout", "")
    socket = _parse_wpa_global_socket(socket_output, process_output)
    assert socket, "Unable to discover wpa_supplicant global socket"
    return container, socket


def _run_wpa_macsec_command(host, port, args):
    container, socket = _get_wpa_global_socket(host, port)
    command = [
        "docker", "exec", container, "wpa_cli", "-g", socket,
        "IFNAME={}".format(port),
    ] + list(args)
    result = host.command(
        " ".join(shlex.quote(part) for part in command),
        module_ignore_errors=True,
        verbose=False,
    )
    output = result.get("stdout", "").strip()
    assert not result.get("failed") and output.splitlines()[-1:] != ["FAIL"], \
        "wpa_supplicant MACsec control command failed"
    return output


def delete_runtime_macsec_key(
        host, port, profile_name, cak, ckn, is_fallback=False):
    """Remove one running MKA participant without detaching the port."""
    if isinstance(host, EosHost):
        return host.eos_config(
            lines=[_eos_macsec_key_line(
                ckn, cak, is_fallback=is_fallback, remove=True)],
            parents=['mac security', 'profile {}'.format(profile_name)])
    return _run_wpa_macsec_command(
        host, port, ["macsec_del_mka", "ckn={}".format(ckn)])


def add_runtime_macsec_key(
        host, port, profile_name, cak, ckn, is_fallback=False):
    """Add one running MKA participant without detaching the port."""
    if isinstance(host, EosHost):
        return host.eos_config(
            lines=[_eos_macsec_key_line(
                ckn, cak, is_fallback=is_fallback)],
            parents=['mac security', 'profile {}'.format(profile_name)])
    args = [
        "macsec_add_mka",
        "ckn={}".format(ckn),
        "cak={}".format(cisco_type7.decode(cak)),
    ]
    if is_fallback:
        args.append("fallback=1")
    return _run_wpa_macsec_command(host, port, args)


def list_runtime_macsec_participants(host, port):
    """Return raw participant-list output from a running SONiC supplicant."""
    if isinstance(host, EosHost):
        raise ValueError("Use EOS participant show commands for EosHost")
    return _run_wpa_macsec_command(host, port, ["macsec_mka_list"])


def is_macsec_configured(host, mac_profile, ctrl_links):
    is_profile_present = False
    is_port_profile_present = False
    profile_name = mac_profile['name']

    expected_fallback_cak = mac_profile.get("fallback_cak", "")
    expected_fallback_ckn = mac_profile.get("fallback_ckn", "")

    # Check macsec profile is configured in all namespaces.
    if host.is_multi_asic:
        for ns in host.get_asic_namespace_list():
            CMD_PREFIX = "-n {}".format(ns) if ns is not None else " "
            cmd = "sonic-db-cli {} CONFIG_DB KEYS 'MACSEC_PROFILE|{}'".format(CMD_PREFIX, profile_name)
            output = host.command(cmd)['stdout'].strip()
            profile = output.split('|')[1] if output else None
            fallback_cak = host.command(
                "sonic-db-cli {} CONFIG_DB HGET "
                "'MACSEC_PROFILE|{}' fallback_cak".format(
                    CMD_PREFIX, profile_name))["stdout"].strip()
            fallback_ckn = host.command(
                "sonic-db-cli {} CONFIG_DB HGET "
                "'MACSEC_PROFILE|{}' fallback_ckn".format(
                    CMD_PREFIX, profile_name))["stdout"].strip()
            is_profile_present = (
                profile == profile_name
                and fallback_cak == expected_fallback_cak
                and fallback_ckn.lower() == expected_fallback_ckn.lower()
            )
            if not is_profile_present:
                break
    else:
        cmd = "sonic-db-cli CONFIG_DB KEYS 'MACSEC_PROFILE|{}'".format(profile_name)
        output = host.command(cmd)['stdout'].strip()
        profile = output.split('|')[1] if output else None
        fallback_cak = host.command(
            "sonic-db-cli CONFIG_DB HGET "
            "'MACSEC_PROFILE|{}' fallback_cak".format(
                profile_name))["stdout"].strip()
        fallback_ckn = host.command(
            "sonic-db-cli CONFIG_DB HGET "
            "'MACSEC_PROFILE|{}' fallback_ckn".format(
                profile_name))["stdout"].strip()
        is_profile_present = (
            profile == profile_name
            and fallback_cak == expected_fallback_cak
            and fallback_ckn.lower() == expected_fallback_ckn.lower()
        )

    # Check if macsec profile is configured on interfaces
    for port, nbr in ctrl_links.items():
        cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' 'macsec' ".format(getns_prefix(host, port), port)
        output = host.command(cmd)['stdout'].strip()
        is_port_profile_present = (output == profile_name)

    return is_profile_present and is_port_profile_present


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


def disable_macsec_port(host, port):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no mac security profile'],
            parents=['interface {}'.format(port)])
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))
    dnx_platform = host.facts.get("platform_asic") == 'broadcom-dnx'

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member del {} {}".format(getns_prefix(host, port), pc["name"], port))

    cmd = "config macsec {} port del {}".format(getns_prefix(host, port), port)
    host.command(cmd)

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


def setup_macsec_configuration(
        duthost, ctrl_links, profile_name, default_priority, cipher_suite,
        primary_cak, primary_ckn, policy, send_sci, rekey_period, tbinfo,
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
                           cipher_suite, primary_cak, primary_ckn, policy,
                           send_sci, rekey_period, fallback_cak, fallback_ckn))
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


def generate_macsec_key_pair(cipher_suite):
    """Generate one encoded CAK and CKN for *cipher_suite*."""
    key_bytes = 16 if "128" in cipher_suite else 32
    cak = cisco_type7.hash(secrets.token_hex(key_bytes))
    ckn = secrets.token_hex(key_bytes)
    return cak, ckn


def generate_macsec_profile(port_name, cipher_suite="GCM-AES-128", priority=64,
                            policy="security", send_sci="true", rekey_period=0,
                            include_fallback=False):
    """Generate a MACsec profile with random CAK/CKN pairs for a port.

    The profile is named ``MACSEC_PROFILE_<port_name>`` and the pre-shared keys
    are generated using ``secrets.token_hex`` so that every port receives a
    unique key pair. When *include_fallback* is true, a distinct fallback pair
    is included for dual-participant MKA testing.

    Args:
        port_name: Interface name (e.g. "Ethernet0"). Used in the profile name.
        cipher_suite: Cipher suite string. Determines key lengths.
        priority: MKA key-server priority (0-255).
        policy: "security" (encrypt) or "integrity" (auth only).
        send_sci: "true" or "false".
        rekey_period: Seconds between rekeying (0 = disabled).
        include_fallback: Include a fallback CAK/CKN pair.

    Returns:
        dict: A profile dict compatible with set_macsec_profile().
    """

    cak, ckn = generate_macsec_key_pair(cipher_suite)

    profile_name = "MACSEC_PROFILE_{}".format(port_name)
    profile = {
        "name": profile_name,
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": cak,
        "primary_ckn": ckn,
        "policy": policy,
        "send_sci": send_sci,
        "rekey_period": rekey_period,
    }
    if include_fallback:
        fallback_cak, fallback_ckn = generate_macsec_key_pair(cipher_suite)
        profile.update({
            "fallback_cak": fallback_cak,
            "fallback_ckn": fallback_ckn,
        })
    return profile


def generate_per_interface_macsec_profile(
        port_name, base_profile, existing_profile=None):
    """Generate a unique dual-CA profile while preserving existing fallback."""
    macsec_profile_has_fallback(base_profile)
    profile = generate_macsec_profile(
        port_name=port_name,
        cipher_suite=base_profile["cipher_suite"],
        priority=base_profile["priority"],
        policy=base_profile["policy"],
        send_sci=base_profile["send_sci"],
        rekey_period=base_profile.get("rekey_period", 0),
        include_fallback=True,
    )

    if existing_profile is not None:
        if macsec_profile_has_fallback(existing_profile):
            profile.update({
                "fallback_cak": existing_profile["fallback_cak"],
                "fallback_ckn": existing_profile["fallback_ckn"],
            })
    return profile


def generate_per_interface_macsec_profiles(
        port_names, base_profile, existing_profiles=None):
    """Generate collision-free dual-CA profiles for all selected interfaces."""
    existing_profiles = existing_profiles or {}
    profiles = {}
    used_caks = set()
    used_ckns = set()

    for port_name in port_names:
        existing_profile = existing_profiles.get(port_name)
        while True:
            profile = generate_per_interface_macsec_profile(
                port_name, base_profile, existing_profile)
            caks = {profile["primary_cak"], profile["fallback_cak"]}
            ckns = {profile["primary_ckn"], profile["fallback_ckn"]}
            if len(caks) != 2 or len(ckns) != 2:
                if existing_profile is not None:
                    raise ValueError(
                        "Existing primary/fallback keys must be distinct")
                continue
            if caks.isdisjoint(used_caks) and ckns.isdisjoint(used_ckns):
                break
            if existing_profile is not None:
                raise ValueError(
                    "Existing per-interface keys collide with another profile")

        profiles[port_name] = profile
        used_caks.update(caks)
        used_ckns.update(ckns)
    return profiles


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
