import binascii
import re
import json
import logging
import time
from collections import defaultdict, deque
from multiprocessing import Process

import cryptography.exceptions
import ptf
import ptf.mask as mask
import ptf.packet as packet
import ptf.testutils as testutils
import scapy.all as scapy
import scapy.contrib.macsec as scapy_macsec

from tests.common.macsec.macsec_platform_helper import sonic_db_cli
from tests.common.devices.eos import EosHost
from tests.common.utilities import convert_scapy_packet_to_bytes, wait_until

__all__ = [
    'check_wpa_supplicant_process',
    'check_appl_db',
    'check_mka_session',
    'check_macsec_pkt',
    'create_pkt',
    'create_exp_pkt',
    'get_appl_db',
    'get_macsec_attr',
    'get_mka_session',
    'get_macsec_sa_name',
    'get_macsec_counters',
    'get_sci',
    'getns_prefix',
    'get_ipnetns_prefix',
]

logger = logging.getLogger(__name__)
process_queue = []


def submit_async_task(target, args):
    global process_queue
    proc = Process(target=target, args=args)
    process_queue.append(proc)
    proc.start()
    return proc


def wait_all_complete(timeout=300):
    """Join every queued process, treating `timeout` as one overall deadline.

    The queue is taken and cleared up front so that a caller which catches the
    timeout and retries starts from a clean queue instead of re-joining the
    processes this call already terminated.
    """
    global process_queue
    procs = process_queue
    process_queue = []
    deadline = time.time() + timeout
    for proc in procs:
        proc.join(max(0, deadline - time.time()))
        # If process timeout, terminate all processes, otherwise the pytest process will never finish.
        if proc.is_alive():
            [p.terminate() for p in procs]
            raise RuntimeError("Process {} timeout {}".format(proc, timeout))


def check_wpa_supplicant_process(host, ctrl_port_name):
    cmd = "ps aux | grep -w 'wpa_supplicant' | grep -w '{}' | grep -v 'grep'".format(
        ctrl_port_name)
    output = host.shell(cmd)["stdout_lines"]
    assert len(output) == 1, "The wpa_supplicant for the port {} wasn't started on the host {}".format(
        host, ctrl_port_name)


def get_sci(macaddress, port_identifer=1):
    system_identifier = macaddress.replace(":", "").replace("-", "")
    sci = "{}{}".format(
        system_identifier,
        str(port_identifer).zfill(4))
    return sci


QUERY_MACSEC_PORT = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_PORT_TABLE:{}'"

QUERY_MACSEC_INGRESS_SC = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_INGRESS_SC_TABLE:{}:{}'"

QUERY_MACSEC_EGRESS_SC = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_EGRESS_SC_TABLE:{}:{}'"

QUERY_MACSEC_INGRESS_SA = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_INGRESS_SA_TABLE:{}:{}:{}'"

QUERY_MACSEC_EGRESS_SA = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_EGRESS_SA_TABLE:{}:{}:{}'"

QUERY_MACSEC_TABLE_KEYS = "sonic-db-cli {} APPL_DB KEYS '{}:{}:*'"


def getns_prefix(host, intf):
    ns_prefix = " "
    if host.is_multi_asic:
        asic = host.get_port_asic_instance(intf)
        ns = host.get_namespace_from_asic_id(asic.asic_index)
        ns_prefix = "-n {}".format(ns)

    return ns_prefix


def get_ipnetns_prefix(host, intf):
    ns_prefix = " "
    if host.is_multi_asic:
        asic = host.get_port_asic_instance(intf)
        ns = host.get_namespace_from_asic_id(asic.asic_index)
        ns_prefix = "sudo ip netns exec {}".format(ns)

    return ns_prefix


def get_dict_macsec_counters(duthost, port):  # noqa: F811
    '''
    Queries get_macsec_counter and returns flattened dictionary.
    '''
    egr_counter, ing_counter = get_macsec_counters(duthost, port)
    new_stats = {}
    new_stats[duthost.hostname] = {}
    new_stats[duthost.hostname][port] = egr_counter
    new_stats[duthost.hostname][port].update(ing_counter)

    return (new_stats)


def get_macsec_sa_name(sonic_asic, port_name, egress=True):
    if egress:
        table = 'MACSEC_EGRESS_SA_TABLE'
    else:
        table = 'MACSEC_INGRESS_SA_TABLE'

    cmd = "APPL_DB KEYS '{}:{}:*'".format(table, port_name)
    names = sonic_asic.run_sonic_db_cli_cmd(cmd)['stdout_lines']
    if names:
        names.sort()
        return ':'.join(names[0].split(':')[1:])
    return None


def get_appl_db(host, host_port_name, peer, peer_port_name):
    port_table = sonic_db_cli(
        host, QUERY_MACSEC_PORT.format(getns_prefix(host, host_port_name), host_port_name))
    host_sci = get_sci(host.get_dut_iface_mac(host_port_name))
    if isinstance(peer, EosHost):
        re_match = re.search(r'\d+', peer_port_name)
        peer_port_identifer = int(re_match.group())
        peer_sci = get_sci(peer.get_dut_iface_mac(peer_port_name), peer_port_identifer)
    else:
        peer_sci = get_sci(peer.get_dut_iface_mac(peer_port_name))
    egress_sc_table = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SC.format(getns_prefix(host, host_port_name), host_port_name, host_sci))
    ingress_sc_table = sonic_db_cli(
        host, QUERY_MACSEC_INGRESS_SC.format(getns_prefix(host, host_port_name), host_port_name, peer_sci))
    egress_sa_table = {}
    ingress_sa_table = {}
    for an in range(4):
        sa_table = sonic_db_cli(host, QUERY_MACSEC_EGRESS_SA.format(
            getns_prefix(host, host_port_name), host_port_name, host_sci, an))
        if sa_table:
            egress_sa_table[an] = sa_table
        sa_table = sonic_db_cli(host, QUERY_MACSEC_INGRESS_SA.format(
            getns_prefix(host, host_port_name), host_port_name, peer_sci, an))
        if sa_table:
            ingress_sa_table[an] = sa_table
    return port_table, egress_sc_table, ingress_sc_table, egress_sa_table, ingress_sa_table


def __macsec_table_keys(host, table, port_name):
    """Return the APPL_DB keys of ``table`` for ``port_name``, whatever the SCI.

    The ingress tables are keyed by the *peer's* SCI, and for an EOS peer
    ``get_appl_db`` can only guess that SCI from the interface name. A wildcard
    lookup answers "is anything installed" without depending on that guess.
    """
    cmd = QUERY_MACSEC_TABLE_KEYS.format(getns_prefix(host, port_name), table, port_name)
    return [line for line in host.shell(cmd)["stdout_lines"] if line.strip()]


def __check_macsec_port_table(port_table, host_name, port_name, policy, cipher_suite, send_sci):
    assert port_table, \
        "No MACSEC_PORT_TABLE for {} on {}".format(port_name, host_name)
    assert port_table["enable"] == "true", \
        "MACsec not enabled on {} {}".format(host_name, port_name)
    assert port_table["cipher_suite"] == cipher_suite, \
        "Cipher suite on {} {} is {}, expected {}".format(
            host_name, port_name, port_table["cipher_suite"], cipher_suite)
    assert port_table["enable_protect"] == "true", \
        "Protection not enabled on {} {}".format(host_name, port_name)
    if policy == "security":
        assert port_table["enable_encrypt"] == "true", \
            "Encryption not enabled on {} {} under the security policy".format(host_name, port_name)
    else:
        assert port_table["enable_encrypt"] == "false", \
            "Encryption enabled on {} {} under the {} policy".format(host_name, port_name, policy)
    assert port_table["send_sci"] == send_sci, \
        "send_sci on {} {} is {}, expected {}".format(
            host_name, port_name, port_table["send_sci"], send_sci)


def __check_sas_installed(host, port_name, egress_sc_table, egress_sa_table):
    """Assert the link has SAs, not just SCs.

    This is the failure this gate exists to catch. MKA can form the CA and
    create both SCs while no SAK is ever installed, and in that state the port
    still reports STATE_DB ``MACSEC_PORT_TABLE`` state ``ok`` and the peer still
    reports a live session -- so every cheaper check passes while the link
    carries nothing. Recovering it needs the per-port wpa_supplicant KaY
    participant rebuilt (``config macsec -n <ns> port del/add <port>``); a link
    bounce does not clear it.

    The ingress side is looked up by wildcard rather than by the peer SCI that
    ``get_appl_db`` computes, because that SCI is guessed from the interface
    name when the peer is an EOS host and a wrong guess would fail every link.
    """
    host_name = host.hostname
    assert egress_sc_table, \
        "No egress SC on {} {}".format(host_name, port_name)

    encoding_an = int(egress_sc_table["encoding_an"])
    assert encoding_an in egress_sa_table, \
        "Egress SC on {} {} is up but has no SA at its encoding_an {} (installed ANs: {})".format(
            host_name, port_name, encoding_an, sorted(egress_sa_table) or "none")

    assert __macsec_table_keys(host, "MACSEC_INGRESS_SC_TABLE", port_name), \
        "No ingress SC on {} {}".format(host_name, port_name)
    assert __macsec_table_keys(host, "MACSEC_INGRESS_SA_TABLE", port_name), \
        "Ingress SC on {} {} is up but no ingress SA is installed".format(host_name, port_name)


def __check_appl_db(duthost, dut_ctrl_port_name, nbrhost, nbr_ctrl_port_name, policy, cipher_suite, send_sci):
    """Validate both halves of a link whose peer is also a SONiC host."""
    dut_port_table, dut_egress_sc_table, _, dut_egress_sa_table, dut_ingress_sa_table = get_appl_db(
        duthost, dut_ctrl_port_name, nbrhost, nbr_ctrl_port_name)
    nbr_port_table, nbr_egress_sc_table, _, nbr_egress_sa_table, nbr_ingress_sa_table = get_appl_db(
        nbrhost, nbr_ctrl_port_name, duthost, dut_ctrl_port_name)

    __check_macsec_port_table(dut_port_table, duthost.hostname, dut_ctrl_port_name,
                              policy, cipher_suite, send_sci)
    __check_macsec_port_table(nbr_port_table, nbrhost.hostname, nbr_ctrl_port_name,
                              policy, cipher_suite, send_sci)

    __check_sas_installed(duthost, dut_ctrl_port_name, dut_egress_sc_table, dut_egress_sa_table)
    __check_sas_installed(nbrhost, nbr_ctrl_port_name, nbr_egress_sc_table, nbr_egress_sa_table)

    # Check MACsec SA Table.  Only the active encoding_an SA needs to be
    # consistent between egress and peer ingress.  Non-encoding ANs may linger
    # in APPL_DB after a dirty container kill (macsecmgrd had no chance to
    # clean them up), while the peer correctly only re-installs the current AN
    # after MKA re-establishes.  Checking all ANs would cause spurious
    # convergence failures in the post-dirty-kill window.
    for egress_sc, egress_sa_table, peer_ingress_sa_table in \
            ((dut_egress_sc_table, dut_egress_sa_table, nbr_ingress_sa_table),
             (nbr_egress_sc_table, nbr_egress_sa_table, dut_ingress_sa_table)):
        encoding_an = int(egress_sc["encoding_an"])
        assert encoding_an in peer_ingress_sa_table, \
            "Peer has not installed an ingress SA for the active AN {}".format(encoding_an)
        egress_sa = egress_sa_table[encoding_an]
        ingress_sa = peer_ingress_sa_table[encoding_an]
        assert egress_sa["sak"] == ingress_sa["sak"]
        assert egress_sa["auth_key"] == ingress_sa["auth_key"]
        assert egress_sa["next_pn"] >= ingress_sa["lowest_acceptable_pn"]


def __check_appl_db_dut_side(duthost, dut_ctrl_port_name, nbrhost, nbr_ctrl_port_name,
                             policy, cipher_suite, send_sci):
    """Validate a link whose peer keeps no APPL_DB to compare against.

    An EOS neighbour has no SONiC APPL_DB, so the peer half of the comparison in
    ``__check_appl_db`` cannot be made. The DUT half is still fully readable and
    is where the interesting failures land, so it is checked in full; the peer
    contributes the one health signal it does expose, its own MACsec state.
    """
    dut_port_table, dut_egress_sc_table, _, dut_egress_sa_table, _ = get_appl_db(
        duthost, dut_ctrl_port_name, nbrhost, nbr_ctrl_port_name)

    __check_macsec_port_table(dut_port_table, duthost.hostname, dut_ctrl_port_name,
                              policy, cipher_suite, send_sci)
    __check_sas_installed(duthost, dut_ctrl_port_name, dut_egress_sc_table, dut_egress_sa_table)

    assert nbrhost.iface_macsec_ok(nbr_ctrl_port_name), \
        "MACsec is not up on peer {} {}".format(nbrhost.hostname, nbr_ctrl_port_name)


def check_appl_db(duthost, ctrl_links, policy, cipher_suite, send_sci):
    """Return True only when every control link is fully converged.

    Returns False instead of raising so that the caller's ``wait_until`` retries:
    ``wait_until`` swallows exceptions from its predicate, so an assert raised
    here would be turned into a silent retry until the whole timeout expired
    rather than a reported failure.
    """
    logger.info("Check appl_db start")
    if not ctrl_links:
        logger.error("Check appl_db: no control links to check")
        return False

    procs = {}
    for port_name, nbr in list(ctrl_links.items()):
        if isinstance(nbr["host"], EosHost):
            target = __check_appl_db_dut_side
        else:
            target = __check_appl_db
        procs[port_name] = submit_async_task(
            target,
            (duthost, port_name, nbr["host"], nbr["port"], policy, cipher_suite, send_sci))

    try:
        wait_all_complete(timeout=180)
    except RuntimeError as e:
        logger.info("Check appl_db: timed out waiting for the per-link checks: %s", e)
        return False

    failed = sorted(port for port, proc in procs.items() if proc.exitcode != 0)
    if failed:
        logger.info("Check appl_db: %d/%d link(s) not converged: %s",
                    len(failed), len(procs), ", ".join(failed))
        return False
    logger.info("Check appl_db finished")
    return True


def get_mka_session(host):
    cmd = "docker exec syncd ip -j macsec show"
    '''
    Here is an output example of `ip macsec show`
    admin@vlab-01:~$ ip macsec show
    130: macsec_eth29: protect on validate strict sc off sa off encrypt
    on send_sci on end_station off scb off replay off
        cipher suite: GCM-AES-128, using ICV length 16
        TXSC: 52540041303f0001 on SA 0
            0: PN 1041, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
            3: PN 2044, state off, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
        RXSC: 525400b5be690001, state on
            0: PN 1041, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
            3: PN 0, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
    131: macsec_eth30: protect on validate strict sc off sa off encrypt
    on send_sci on end_station off scb off replay off
        cipher suite: GCM-AES-128, using ICV length 16
        TXSC: 52540041303f0001 on SA 0
            0: PN 1041, state on, key daa8169cde2fe1e238aaa83672e40279
        RXSC: 525400fb9b220001, state on
            0: PN 1041, state on, key daa8169cde2fe1e238aaa83672e40279

    Here is an output example of `ip -j macsec show` (JSON format), not related to above output:
    admin@vlab-02:~$ ip -j macsec show | jq
    [
      {
        "ifindex": 219,
        "ifname": "macsec_eth1",
        "protect": true,
        "validate": "strict",
        "sc": false,
        "sa": false,
        "encrypt": true,
        "send_sci": true,
        "end_station": false,
        "scb": false,
        "replay": false,
        "cipher_suite": "GCM-AES-128",
        "icv_length": 16,
        "sci": "0x525400953a020001",
        "encoding_sa": 0,
        "sa_list": [
          {
            "an": 0,
            "pn": 153,
            "active": true,
            "key": "18f16ec57c97dcdd5d011d8161de34b5"
          }
        ],
        "rx_sc": [
          {
            "sci": "0x525400a00dc70001",
            "active": true,
            "sa_list": [
              {
                "an": 0,
                "pn": 127,
                "active": true,
                "key": "18f16ec57c97dcdd5d011d8161de34b5"
              }
            ]
          }
        ],
        "offload": "off"
      }
    [
    '''
    output = host.command(cmd)["stdout"]
    ports = json.loads(output)
    mka_session = {}

    for port in ports:
        port_obj = {
            "protect": port["protect"],
            "validate": {
                "mode": port["validate"],
                "sc": port["sc"],
                "sa": port["sa"],
            },
            "encrypt": port["encrypt"],
            "send_sci": port["send_sci"],
            "end_station": port["end_station"],
            "scb": port["scb"],
            "replay": port["replay"],
            "cipher_suite": port["cipher_suite"],
            "ICV_length": port["icv_length"],
            "egress_scs": {
                port["sci"].replace("0x", ""): {
                    "sas": {},
                    "enabled": True,
                    "active_an": port["encoding_sa"]
                }
            },
            "ingress_scs": {},
        }
        for sa in port["sa_list"]:
            sci = port["sci"].replace("0x", "")
            port_obj["egress_scs"][sci]["sas"][sa["an"]] = {}
            port_obj["egress_scs"][sci]["sas"][sa["an"]]["pn"] = sa["pn"]
            port_obj["egress_scs"][sci]["sas"][sa["an"]]["enabled"] = sa["active"]
            port_obj["egress_scs"][sci]["sas"][sa["an"]]["key"] = sa["key"]
        for rx_sc in port["rx_sc"]:
            sci = rx_sc["sci"].replace("0x", "")
            port_obj["ingress_scs"][sci] = {}
            port_obj["ingress_scs"][sci]["enabled"] = rx_sc["active"]
            port_obj["ingress_scs"][sci]["sas"] = {}
            for sa in rx_sc["sa_list"]:
                port_obj["ingress_scs"][sci]["sas"][sa["an"]] = {}
                port_obj["ingress_scs"][sci]["sas"][sa["an"]]["pn"] = sa["pn"]
                port_obj["ingress_scs"][sci]["sas"][sa["an"]]["enabled"] = sa["active"]
                port_obj["ingress_scs"][sci]["sas"][sa["an"]]["key"] = sa["key"]
        mka_session[port["ifname"]] = port_obj
    return mka_session


def check_mka_sc(egress_sc, ingress_sc):
    assert egress_sc["enabled"]
    assert ingress_sc["enabled"]
    active_an = egress_sc["active_an"]
    assert active_an in egress_sc["sas"]
    assert active_an in ingress_sc["sas"]
    assert egress_sc["sas"][active_an]["enabled"]
    assert ingress_sc["sas"][active_an]["enabled"]
    assert egress_sc["sas"][active_an]["key"] == ingress_sc["sas"][active_an]["key"]


def check_mka_session(dut_mka_session, dut_sci, nbr_mka_session, nbr_sci, policy, cipher_suite, send_sci):
    assert dut_mka_session["protect"]
    assert nbr_mka_session["protect"]
    if policy == "security":
        assert dut_mka_session["encrypt"]
        assert nbr_mka_session["encrypt"]
    else:
        assert not dut_mka_session["encrypt"]
        assert not nbr_mka_session["encrypt"]
    if send_sci == "true":
        assert dut_mka_session["send_sci"]
        assert nbr_mka_session["send_sci"]
    else:
        assert not dut_mka_session["send_sci"]
        assert not nbr_mka_session["send_sci"]
    assert dut_mka_session["cipher_suite"] == cipher_suite
    assert nbr_mka_session["cipher_suite"] == cipher_suite
    assert dut_sci in nbr_mka_session["ingress_scs"]
    assert dut_sci in dut_mka_session["egress_scs"]
    assert nbr_sci in dut_mka_session["ingress_scs"]
    assert nbr_sci in nbr_mka_session["egress_scs"]
    check_mka_sc(dut_mka_session["egress_scs"][dut_sci],
                 nbr_mka_session["ingress_scs"][dut_sci])
    check_mka_sc(nbr_mka_session["egress_scs"][nbr_sci],
                 dut_mka_session["ingress_scs"][nbr_sci])


def create_pkt(eth_src, eth_dst, ip_src, ip_dst, payload=None):
    pkt = testutils.simple_ipv4ip_packet(
        eth_src=eth_src, eth_dst=eth_dst, ip_src=ip_src, ip_dst=ip_dst, inner_frame=payload)
    return pkt


def create_exp_pkt(pkt, ttl):
    exp_pkt = pkt.copy()
    exp_pkt[scapy.IP].ttl = ttl
    exp_pkt = mask.Mask(exp_pkt, ignore_extra_bytes=True)
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
    return exp_pkt


def get_macsec_attr(host, port):
    eth_src = host.get_dut_iface_mac(port)
    macsec_port = sonic_db_cli(host, QUERY_MACSEC_PORT.format(getns_prefix(host, port), port))
    if macsec_port["enable_encrypt"] == "true":
        encrypt = 1
    else:
        encrypt = 0
    if macsec_port["send_sci"] == "true":
        send_sci = 1
    else:
        send_sci = 0
    xpn_en = "XPN" in macsec_port["cipher_suite"]
    sci = get_sci(eth_src)
    macsec_sc = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SC.format(getns_prefix(host, port), port, sci))
    an = int(macsec_sc["encoding_an"])
    macsec_sa = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SA.format(getns_prefix(host, port), port, sci, an))
    sak = binascii.unhexlify(macsec_sa["sak"])
    sci = int(get_sci(eth_src), 16)
    if xpn_en:
        ssci = int(macsec_sa["ssci"])
        salt = binascii.unhexlify(macsec_sa["salt"])
    else:
        ssci = None
        salt = None

    # Get the peer sci and an from the ingress macsec SA name
    asic = host.get_port_asic_instance(port)
    macsec_ingress_sa_name = get_macsec_sa_name(asic, port, False)
    peer_sci = macsec_ingress_sa_name.split(':')[1]
    peer_an = macsec_ingress_sa_name.split(':')[2]

    # Get the ingress macsec sa
    macsec_ingress_sa = sonic_db_cli(
        host, QUERY_MACSEC_INGRESS_SA.format(getns_prefix(host, port), port, peer_sci, peer_an))
    if xpn_en:
        peer_ssci = int(macsec_ingress_sa["ssci"])
    else:
        peer_ssci = None

    # Get the packet number from ingress SA
    egress_dict, ingress_dict = get_macsec_counters(host, port)
    pn = ingress_dict['SAI_MACSEC_SA_ATTR_CURRENT_XPN']

    return encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, int(peer_sci, 16), int(peer_an), peer_ssci, pn


def encap_macsec_pkt(macsec_pkt, sci, an, sak, encrypt, send_sci, pn, xpn_en=False, ssci=None, salt=None):
    sa = scapy_macsec.MACsecSA(sci=sci,
                               an=an,
                               pn=pn,
                               key=sak,
                               icvlen=16,
                               encrypt=encrypt,
                               send_sci=send_sci,
                               xpn_en=xpn_en,
                               ssci=ssci,
                               salt=salt)
    macsec_pkt = sa.encap(macsec_pkt)
    pkt = sa.encrypt(macsec_pkt)
    return pkt


def decap_macsec_pkt(macsec_pkt, sci, an, sak, encrypt, send_sci, pn, xpn_en=False, ssci=None, salt=None):
    sa = scapy_macsec.MACsecSA(sci=sci,
                               an=an,
                               pn=pn,
                               key=sak,
                               icvlen=16,
                               encrypt=encrypt,
                               send_sci=send_sci,
                               xpn_en=xpn_en,
                               ssci=ssci,
                               salt=salt)
    try:
        pkt = sa.decrypt(macsec_pkt)
    except cryptography.exceptions.InvalidTag:
        # Invalid MACsec packets
        return macsec_pkt, False
    pkt = sa.decap(pkt)
    return convert_scapy_packet_to_bytes(pkt), True


def check_macsec_pkt(test, ptf_port_id, exp_pkt, timeout=3):
    device, ptf_port = testutils.port_to_tuple(ptf_port_id)
    ret = testutils.dp_poll(
        test, device_number=device, port_number=ptf_port, timeout=timeout, exp_pkt=exp_pkt)
    if isinstance(ret, test.dataplane.PollSuccess):
        return
    else:
        return ret.format()


def find_portname_from_ptf_id(mg_facts, ptf_id):
    for k, v in list(mg_facts["minigraph_ptf_indices"].items()):
        if ptf_id == v:
            return k
    return None


def load_macsec_info(duthost, port, force_reload=None):
    if force_reload or port not in __macsec_infos:
        __macsec_infos[port] = get_macsec_attr(duthost, port)
    return __macsec_infos[port]


def load_macsec_info_for_ptf_id(duthost, ptf_id, port, force_reload=None):
    if force_reload:
        MACSEC_INFO[ptf_id] = get_macsec_attr(duthost, port)


# This API load the macsec session details from all ctrl links
def load_all_macsec_info(duthost, ctrl_links, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for port, nbr in ctrl_links.items():
        ptf_id = mg_facts["minigraph_ptf_indices"][port]
        MACSEC_INFO[ptf_id] = get_macsec_attr(duthost, port)


def macsec_send(test, port_id, pkt, count=1):
    global MACSEC_GLOBAL_PN_OFFSET
    global MACSEC_GLOBAL_PN_INCR

    # Check if the port is macsec enabled, if so send the macsec encap/encrypted frame
    device, port_number = testutils.port_to_tuple(port_id)
    if port_number in MACSEC_INFO and MACSEC_INFO[port_number]:
        encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, peer_sci, peer_an, peer_ssci, pn = MACSEC_INFO[port_number]

        for n in range(count):
            if isinstance(pkt, bytes):
                # If in bytes, convert it to an Ether packet
                pkt = scapy.Ether(pkt)

            # Increment the PN in packet so that the packet s not marked as late in DUT
            MACSEC_GLOBAL_PN_OFFSET += MACSEC_GLOBAL_PN_INCR
            pn += MACSEC_GLOBAL_PN_OFFSET

            macsec_pkt = encap_macsec_pkt(pkt, peer_sci, peer_an, sak, encrypt, send_sci, pn, xpn_en, peer_ssci, salt)
            # send the packet
            __origin_send_packet(test, port_id, macsec_pkt, 1)
    else:
        # send the packet
        __origin_send_packet(test, port_id, pkt, count)


def macsec_dp_poll(test, device_number=0, port_number=None, timeout=None, exp_pkt=None):
    recent_packets = deque(maxlen=test.dataplane.POLL_MAX_RECENT_PACKETS)
    packet_count = 0
    if timeout is None:
        timeout = ptf.ptfutils.default_timeout
    force_reload = defaultdict(lambda: False)
    if hasattr(test, "force_reload_macsec"):
        force_reload = defaultdict(lambda: test.force_reload_macsec)
    while True:
        start_time = time.time()
        ret = __origin_dp_poll(
            test, device_number=device_number, port_number=port_number, timeout=timeout, exp_pkt=None)
        timeout -= time.time() - start_time
        # Since we call __origin_dp_poll with exp_pkt=None, it should only ever fail if no packets are received at all.
        # In this case, continue normally
        # until we exceed the timeout value provided to macsec_dp_poll.
        if isinstance(ret, test.dataplane.PollFailure):
            if timeout <= 0:
                break
            else:
                continue
        # The device number of PTF host is 0, if the target port isn't a injected port(belong to ptf host),
        # Don't need to do MACsec further.
        if ret.device != 0:
            return ret
        pkt = scapy.Ether(ret.packet)
        if pkt.haslayer(scapy.Ether):
            if pkt[scapy.Ether].type != 0x88e5:
                if exp_pkt is None or ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                    return ret
            else:
                if ret.port in MACSEC_INFO and MACSEC_INFO[ret.port]:
                    # Reload the macsec session if the session was restarted
                    if force_reload[ret.port]:
                        load_macsec_info_for_ptf_id(
                            test.duthost, ret.port, find_portname_from_ptf_id(test.mg_facts, ret.port),
                            force_reload[ret.port])
                    encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, peer_sci, peer_an, peer_ssci, pn = \
                        MACSEC_INFO[ret.port]
                    force_reload[ret.port] = False
                    pkt, decap_success = decap_macsec_pkt(pkt, sci, an, sak, encrypt, send_sci, 0, xpn_en, ssci, salt)
                    if exp_pkt is None or decap_success and ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                        # Here we explicitly create the PollSuccess struct and send the pkt which us decoded
                        # and the caller test can validate the pkt fields. Without this fix in case of macsec
                        # the encrypted packet is being send back to caller which it will not be able to dissect
                        return test.dataplane.PollSuccess(ret.device, ret.port, pkt, exp_pkt, time.time())
        # Normally, if __origin_dp_poll returns a PollFailure, the PollFailure object will contain a list of
        # recently received packets to help with debugging. However, since we call __origin_dp_poll multiple times,
        # only the packets from the most recent call is retained. If we don't find a matching packet (either with or
        # without MACsec decoding), we need to manually store the packet we received. Later if we return a PollFailure,
        # we can provide the received packets to emulate the behavior of __origin_dp_poll.
        recent_packets.append(pkt)
        packet_count += 1
        if timeout <= 0:
            break
    return test.dataplane.PollFailure(exp_pkt, recent_packets, packet_count)


def _parse_show_macsec_counters(text):
    '''
    This function takes the output of a show macsec <interface> command, and returns a dict
    of the counters.
    Returns following dict format:
    {
        'egress': {<dict of counters>},
        'ingress': {<dict of counters>}
    }
    TODO: enhance show macsec command to output in json directly

    Here is an example of `show macsec Ethernet216`
    MACsec port(Ethernet216)
    ---------------------  ---------------
    cipher_suite           GCM-AES-XPN-256
    enable                 true
    enable_encrypt         true
    enable_protect         true
    enable_replay_protect  false
    profile                MACSEC_PROFILE
    replay_window          0
    send_sci               true
    ---------------------  ---------------
            MACsec Egress SC (XXX)
            -----------  -
            encoding_an  1
            -----------  -
            MACsec Egress SA (1)
            -------------------------------------  ----------------------------------------------------------------
            auth_key                               XXX
            next_pn                                1
            sak                                    XXX
            salt                                   XXX
            ssci                                   2
            SAI_MACSEC_SA_ATTR_CURRENT_XPN         8
            SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED    28532
            SAI_MACSEC_SA_STAT_OCTETS_PROTECTED    0
            SAI_MACSEC_SA_STAT_OUT_PKTS_ENCRYPTED  7
            SAI_MACSEC_SA_STAT_OUT_PKTS_PROTECTED  0
            -------------------------------------  ----------------------------------------------------------------
            MACsec Ingress SC (XXX)

            MACsec Ingress SA (1)
            ---------------------------------------  ----------------------------------------------------------------
            active                                   true
            auth_key                                 XXX
            lowest_acceptable_pn                     1
            sak                                      XXX
            salt                                     XXX
            ssci                                     1
            SAI_MACSEC_SA_ATTR_CURRENT_XPN           6661
            SAI_MACSEC_SA_STAT_IN_PKTS_DELAYED       0
            SAI_MACSEC_SA_STAT_IN_PKTS_INVALID       0
            SAI_MACSEC_SA_STAT_IN_PKTS_LATE          0
            SAI_MACSEC_SA_STAT_IN_PKTS_NOT_USING_SA  1
            SAI_MACSEC_SA_STAT_IN_PKTS_NOT_VALID     0
            SAI_MACSEC_SA_STAT_IN_PKTS_OK            8
            SAI_MACSEC_SA_STAT_IN_PKTS_UNCHECKED     0
            SAI_MACSEC_SA_STAT_IN_PKTS_UNUSED_SA     0
            SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED      523517
            SAI_MACSEC_SA_STAT_OCTETS_PROTECTED      0
            ---------------------------------------  ----------------------------------------------------------------
    '''
    out = {'egress': {}, 'ingress': {}}
    stats = None
    reg = re.compile(r'(SAI_MACSEC.*?) *(\d+)')
    for line in text.splitlines():
        line = line.strip()

        # Found the egress header, following stats will be for egress
        if line.startswith("MACsec Egress SA"):
            stats = 'egress'
            continue
        # Found the ingress header, following stats will be for ingress
        elif line.startswith("MACsec Ingress SA"):
            stats = 'ingress'
            continue
        # No header yet, so no stats coming
        if not stats:
            continue

        found = reg.match(line)
        if found:
            out[stats].update({found.group(1): int(found.group(2))})
    return out


def get_macsec_counters(duthost, port):
    cmd = f"show macsec {port}"
    output = duthost.command(cmd)["stdout"]

    out_dict = _parse_show_macsec_counters(output)

    return (out_dict['egress'], out_dict['ingress'])


def clear_macsec_counters(duthost):
    assert duthost.command("sonic-clear macsec")["failed"] is False


__origin_dp_poll = testutils.dp_poll
__origin_send_packet = testutils.send_packet
__macsec_infos = defaultdict(lambda: None)
MACSEC_INFO = defaultdict(lambda: None)
MACSEC_GLOBAL_PN_OFFSET = 1000
MACSEC_GLOBAL_PN_INCR = 100
testutils.dp_poll = macsec_dp_poll
testutils.send_packet = macsec_send
