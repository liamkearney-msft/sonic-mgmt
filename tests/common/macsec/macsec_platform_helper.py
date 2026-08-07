import ast
import re
import logging
from multiprocessing.pool import ThreadPool

import pytest

from tests.common.devices.csonic import CsonicHost
from tests.common.devices.eos import EosHost


__all__ = [
    'find_portchannel_from_member',
    'get_eth_ifname',
    'get_macsec_ifname',
    'get_portchannel',
    'get_lldp_list',
    'get_platform',
    'global_cmd',
    'sonic_db_cli'
]


def global_cmd(duthost, nbrhosts, cmd):
    pool = ThreadPool(1 + len(nbrhosts))
    pool.apply_async(duthost.command, args=(cmd,))
    for nbr in list(nbrhosts.values()):
        if isinstance(nbr["host"], (EosHost, CsonicHost)):
            continue
        pool.apply_async(nbr["host"].command, args=(cmd, ))
    pool.close()
    pool.join()


def sonic_db_cli(host, cmd):
    return ast.literal_eval(host.shell(cmd)["stdout_lines"][0])


def get_all_ifnames(host, asic=None):
    cmd_prefix = " "
    if host.is_multi_asic and asic is not None:
        ns = host.get_namespace_from_asic_id(asic.asic_index)
        cmd_prefix = "sudo ip netns exec {} ".format(ns)

    cmd = "{} ls /sys/class/net/".format(cmd_prefix)
    output = host.command(cmd)["stdout_lines"]
    ports = {
        "Ethernet": [],
        "eth": [],
        "macsec": [],
    }
    for type in list(ports.keys()):
        ports[type] = [port
                       for port in output if port.startswith(type)]
        ports[type].sort(key=lambda no: int(re.search(r'\d+', no).group(0)))
    # Remove the eth0
    ports["eth"].pop(0)
    return ports


def get_eth_ifname(host, port_name):
    asic = None
    if "x86_64-kvm_x86_64" in get_platform(host):
        logging.info("Get the eth ifname on the virtual SONiC switch")
        if host.is_multi_asic:
            asic = host.get_port_asic_instance(port_name)
        ports = get_all_ifnames(host, asic)
        assert port_name in ports["Ethernet"]
        return ports["eth"][ports["Ethernet"].index(port_name)]
    # Same as port_name
    return port_name


def get_macsec_ifname(host, port_name):
    asic = None
    if "x86_64-kvm_x86_64" not in get_platform(host):
        logging.info(
            "Can only get the macsec ifname on the virtual SONiC switch")
        return None
    if host.is_multi_asic:
        asic = host.get_port_asic_instance(port_name)
    ports = get_all_ifnames(host, asic)
    assert port_name in ports["Ethernet"]
    eth_port = ports["eth"][ports["Ethernet"].index(port_name)]
    macsec_infname = "macsec_"+eth_port
    assert macsec_infname in ports["macsec"]
    return macsec_infname


def get_platform(host):
    if isinstance(host, EosHost):
        return "Arista"
    for line in host.command("show platform summary")["stdout_lines"]:
        if "Platform" == line.split(":")[0]:
            return line.split(":")[1].strip()
    pytest.fail("No platform was found.")


def get_portchannel(host):
    '''
        Here is an output example of `show interfaces portchannel`
        admin@sonic:~$ show interfaces portchannel
        Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
            S - selected, D - deselected, * - not synced
        No.  Team Dev         Protocol     Ports
        -----  ---------------  -----------  ---------------------------
        0001  PortChannel0001  LACP(A)(Up)  Ethernet112(S) Ethernet108(D)
        0002  PortChannel0002  LACP(A)(Up)  Ethernet116(S)
        0003  PortChannel0003  LACP(A)(Up)  Ethernet120(S)
        0004  PortChannel0004  LACP(A)(Up)  N/A
    '''
    output = host.command("show interfaces portchannel", module_ignore_errors=True)
    if output.get("rc", 0) != 0:
        return {}
    lines = output.get("stdout_lines", [])
    lines = lines[4:]  # Remove the output header
    portchannel_list = {}
    for line in lines:
        items = line.split()
        if len(items) < 4:
            continue
        portchannel = items[1]
        portchannel_list[portchannel] = {
            "name": portchannel, "status": None, "members": []}
        if items[-1] == "N/A":
            continue
        status = re.search(r"\((Up|Dw)\)", items[2])
        if status is None:
            continue
        portchannel_list[portchannel]["status"] = status.group(1)
        for item in items[3:]:
            port = re.search(r"(Ethernet.*)\(", item)
            if port is not None:
                portchannel_list[portchannel]["members"].append(port.group(1))
    return portchannel_list


def find_portchannel_from_member(port_name, portchannel_list):
    for k, v in list(portchannel_list.items()):
        if port_name in v["members"]:
            return v
    return None


def get_portchannel_status(host, port_name):
    """Return the status of the PortChannel that port_name belongs to.

    Returns None when the port is not a member of any PortChannel, which is the
    case on routed topologies such as the T2 cSONiC testbed. Callers must not
    subscript find_portchannel_from_member() directly: it returns None for a
    non-member, so doing so raises TypeError instead of the intended assertion
    message.
    """
    portchannel = find_portchannel_from_member(port_name, get_portchannel(host))
    if portchannel is None:
        return None
    return portchannel["status"]


def get_lldp_list(host):
    '''
        Here is an output example of `show lldp table`
            Capability codes: (R) Router, (B) Bridge, (O) Other
            LocalPort    RemoteDevice    RemotePortID    Capability    RemotePortDescr
            -----------  --------------  --------------  ------------  -----------------
            Ethernet112  ARISTA01T1      Ethernet1       BR
            Ethernet116  ARISTA02T1      Ethernet1       BR
            Ethernet120  ARISTA03T1      Ethernet1       BR
            Ethernet124  ARISTA04T1      Ethernet1       BR
            --------------------------------------------------
            Total entries displayed:  4
    '''
    lines = host.command("show lldp table")["stdout_lines"]
    lines = lines[3:-2]  # Remove the output header
    lldp_list = {}
    for line in lines:
        items = line.split()
        lldp = items[1]
        lldp_list[lldp] = {"name": lldp, "localport": items[0], "remoteport": items[2]}
    return lldp_list
