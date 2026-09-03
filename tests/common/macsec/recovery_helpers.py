import logging
import time

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import (
    restart_service_with_startlimit_guard,
    is_container_running,
    is_hitting_start_limit,
)
from tests.common.macsec.macsec_helper import (
    check_appl_db,
    get_macsec_container,
    get_sci,
    getns_prefix,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
# Seconds to wait after SIGKILL before polling for the container to be up.
KILL_SETTLE_SECONDS = 5
# Maximum seconds to wait for the macsec container to respawn.
CONTAINER_UP_TIMEOUT = 120
# Maximum seconds to wait for MKA (re-)convergence.
MKA_CONVERGE_TIMEOUT = 300
MKA_CONVERGE_INTERVAL = 6
MKA_CONVERGE_DELAY = 12
# Maximum seconds to wait for orchagent/syncd to program a freshly negotiated
# SAK into SAI.  ASIC_DB is written asynchronously, well after APPL_DB and
# after MKA reports converged, so the SAK comparison has to be given time to
# settle or a programming lag is indistinguishable from the stale-SAK bug.
SAK_PROGRAM_TIMEOUT = 120
SAK_PROGRAM_INTERVAL = 5


# ---------------------------------------------------------------------------
# MACSEC_PROFILE CONFIG_DB access (namespace aware)
# ---------------------------------------------------------------------------

def macsec_profile_namespaces(duthost, profile_name):
    """
    Return the namespaces whose CONFIG_DB actually holds ``profile_name``.

    On a multi-ASIC chassis the MACsec profile is provisioned once per ASIC
    namespace and is deliberately absent from the host namespace.  A bare
    ``sonic-db-cli CONFIG_DB HSET`` therefore does not update the profile at
    all -- it *creates* a new one in the host namespace containing only the
    field being written.  That partial entry has no ``primary_cak``, which is
    a mandatory node in the sonic-macsec YANG model, so every subsequent
    config validation on the DUT fails with::

        Mandatory node "primary_cak" instance does not exist.

    which errors out unrelated test modules for the rest of the run.  Callers
    must only ever touch namespaces where the profile already exists.
    """
    namespaces = []
    for ns in duthost.get_asic_namespace_list():
        prefix = "-n {}".format(ns) if ns is not None else ""
        keys = duthost.shell(
            "sonic-db-cli {} CONFIG_DB KEYS 'MACSEC_PROFILE|{}'".format(
                prefix, profile_name),
            module_ignore_errors=True,
        )["stdout"].strip()
        if keys:
            namespaces.append(ns)
    return namespaces


def get_macsec_profile_field(duthost, profile_name, field, default=None):
    """Read ``field`` from the MACsec profile, from whichever namespace has it."""
    for ns in macsec_profile_namespaces(duthost, profile_name):
        prefix = "-n {}".format(ns) if ns is not None else ""
        value = duthost.shell(
            "sonic-db-cli {} CONFIG_DB HGET 'MACSEC_PROFILE|{}' {}".format(
                prefix, profile_name, field),
            module_ignore_errors=True,
        )["stdout"].strip()
        if value:
            return value
    return default


def set_macsec_profile_fields(duthost, profile_name, **fields):
    """
    Set one or more fields on the MACsec profile in every namespace that
    already defines it, so both ASICs of a multi-ASIC DUT stay consistent.

    This deliberately keeps writing CONFIG_DB directly, which is *not* how
    config changes should normally be made -- new code should go through
    ``config macsec`` (see ``DedicatedLink`` and ``replace_macsec_profile``).
    It is kept here because the CLI has no in-place field update:
    ``profile update`` only rotates a CAK/CKN, ``profile add`` refuses a
    profile that already exists and ``profile del`` refuses one a port is
    still bound to.  Changing ``priority`` or ``rekey_period`` through the
    CLI therefore means moving every bound port -- on the DUT *and* on each
    neighbor -- onto a replacement profile and back again.  The recovery
    tests do one of these changes while the macsec container is deliberately
    dead, and that port churn would disturb the surviving SA they exist to
    observe.

    What this wrapper does fix is the namespace: upstream issued a bare
    ``sonic-db-cli ... HSET``, which lands in the host namespace where a
    multi-ASIC chassis has no profile at all.  See
    ``macsec_profile_namespaces`` for why that silently poisons the rest of
    the run.
    """
    namespaces = macsec_profile_namespaces(duthost, profile_name)
    pytest_assert(
        namespaces,
        "MACSEC_PROFILE|{} does not exist in any namespace; refusing to "
        "create a partial profile".format(profile_name))
    assignments = " ".join(
        "{} {}".format(key, value) for key, value in fields.items())
    for ns in namespaces:
        prefix = "-n {}".format(ns) if ns is not None else ""
        duthost.shell(
            "sonic-db-cli {} CONFIG_DB HSET 'MACSEC_PROFILE|{}' {}".format(
                prefix, profile_name, assignments),
            module_ignore_errors=False,
        )


# ---------------------------------------------------------------------------
# macsec container/service instances (namespace aware)
# ---------------------------------------------------------------------------

def _macsec_service_for_container(container_name):
    """Map a macsec container name to the systemd unit that manages it."""
    suffix = container_name[len("macsec"):]
    return "macsec@{}".format(suffix) if suffix else "macsec"


def macsec_instances(duthost):
    """
    Return ``[(container_name, systemd_service_name), ...]`` for every macsec
    instance on ``duthost``.

    A multi-ASIC DUT runs one macsec container per ASIC -- ``macsec0``,
    ``macsec1``, ... driven by the templated units ``macsec@0``, ``macsec@1``,
    ... and the un-suffixed ``macsec.service`` is masked there. Acting on the
    bare name therefore fails outright, and hardcoding instance 0 silently
    leaves every other ASIC's container untouched, so a disruption test would
    report success while never having disturbed most of the links it checks.
    """
    if not duthost.is_multi_asic:
        return [("macsec", "macsec")]
    return [("macsec{}".format(asic_id), "macsec@{}".format(asic_id))
            for asic_id in duthost.get_frontend_asic_ids()]


def macsec_instance_for_port(duthost, port_name):
    """Return ``(container_name, service_name)`` of the macsec instance owning ``port_name``."""
    container_name = get_macsec_container(duthost, port_name)
    return (container_name, _macsec_service_for_container(container_name))


# ---------------------------------------------------------------------------
# Disruption primitives
# ---------------------------------------------------------------------------

def graceful_restart_macsec(duthost):
    """`systemctl restart macsec` via the startlimit-aware helper, on every ASIC."""
    for container_name, service_name in macsec_instances(duthost):
        logger.info("Graceful restart of %s on %s", service_name, duthost.hostname)
        restart_service_with_startlimit_guard(
            duthost, service_name,
            backoff_seconds=35,
            verify_timeout=CONTAINER_UP_TIMEOUT,
            container_name=container_name,
        )


def dirty_kill_macsec_container(duthost):
    """`docker kill -s 9 macsec` — bypasses macsecmgrd's per-port disable loop."""
    containers = [container for container, _ in macsec_instances(duthost)]
    logger.info("Sending SIGKILL to macsec container(s) %s on %s",
                ", ".join(containers), duthost.hostname)
    duthost.shell("docker kill -s 9 {}".format(" ".join(containers)),
                  module_ignore_errors=False)


def dirty_kill_macsecmgrd(duthost, signal=9):
    """
    Send a signal to macsecmgrd inside every macsec container.

    signal=9 (SIGKILL) skips graceful shutdown; signal=6 (SIGABRT) generates a
    core dump.  supervisord inside the container respawns macsecmgrd; the
    container itself stays up, as do the per-port wpa_supplicant processes
    and their UNIX control sockets.
    """
    for container_name, _ in macsec_instances(duthost):
        logger.info("Sending signal %d to macsecmgrd inside %s on %s",
                    signal, container_name, duthost.hostname)
        duthost.shell(
            "docker exec {} pkill -{} -x macsecmgrd".format(container_name, signal),
            module_ignore_errors=False,
        )


def dirty_kill_wpa_supplicant(duthost, port_name):
    """
    SIGKILL the wpa_supplicant process bound to one MACsec port.

    The wpa_supplicant command line includes the per-port control socket
    path (/var/run/Ethernet<N>), so we use that to scope the pkill to one
    instance.  macsecmgrd respawns it; other ports' wpa_supplicants are
    untouched.  The process lives in the macsec container of the port's own
    ASIC, so the port has to be mapped to its instance first.
    """
    container_name, _ = macsec_instance_for_port(duthost, port_name)
    logger.info("SIGKILL wpa_supplicant for %s in %s on %s",
                port_name, container_name, duthost.hostname)
    duthost.shell(
        "docker exec {} pkill -9 -f '/var/run/{}'".format(container_name, port_name),
        module_ignore_errors=False,
    )


# ---------------------------------------------------------------------------
# Recovery waits
# ---------------------------------------------------------------------------

def wait_for_macsec_container(duthost):
    """
    Wait for systemd to *auto-respawn* the macsec container(s) after a dirty
    kill.  Deliberately does NOT issue `systemctl restart`: the macsec
    service has a Restart= policy, so after SIGKILL systemd brings the
    container back on its own.  A `systemctl restart` here would graceful-
    stop the freshly auto-respawned container first, giving macsecmgrd a
    clean per-port teardown that wipes orchagent's stale SA state — which
    converts the dirty restart into a graceful one.

    Fallback: if a container hasn't come back within CONTAINER_UP_TIMEOUT
    (e.g. rapid repeated kills tripped systemd's StartLimitHit so auto-
    respawn is suppressed), clear the failure counter and `start` it — a
    start, never a restart, so a still-running container is never gracefully
    stopped.
    """
    time.sleep(KILL_SETTLE_SECONDS)

    for container_name, service_name in macsec_instances(duthost):
        if wait_until(CONTAINER_UP_TIMEOUT, 2, 0,
                      is_container_running, duthost, container_name):
            logger.info("%s container auto-respawned on %s",
                        container_name, duthost.hostname)
            continue

        logger.warning(
            "%s did not auto-respawn on %s (StartLimitHit=%s); "
            "clearing failure counter and starting",
            container_name, duthost.hostname,
            is_hitting_start_limit(duthost, service_name))
        duthost.shell("sudo systemctl reset-failed {}.service".format(service_name),
                      module_ignore_errors=True)
        duthost.shell("sudo systemctl start {}.service".format(service_name),
                      module_ignore_errors=True)
        pytest_assert(
            wait_until(CONTAINER_UP_TIMEOUT, 2, 0,
                       is_container_running, duthost, container_name),
            "{} container did not come up after dirty kill + fallback start".format(
                container_name))
        logger.info("%s container started via fallback on %s",
                    container_name, duthost.hostname)


def wait_for_mka_converged(duthost, ctrl_links, policy, cipher_suite, send_sci):
    """
    Poll APPL_DB until check_appl_db reports MKA converged on every ctrl_link.
    Returns True on success, False on timeout.
    """
    return wait_until(
        MKA_CONVERGE_TIMEOUT,
        MKA_CONVERGE_INTERVAL,
        MKA_CONVERGE_DELAY,
        check_appl_db,
        duthost, ctrl_links, policy, cipher_suite, send_sci,
    )


# ---------------------------------------------------------------------------
# APPL_DB snapshots / invariants
# ---------------------------------------------------------------------------

def _get_appl_db_sa_sak(duthost, port_name, sci, an, egress=True):
    """Return the SAK from APPL_DB for the given (port, sci, an), or None."""
    table = "MACSEC_EGRESS_SA_TABLE" if egress else "MACSEC_INGRESS_SA_TABLE"
    ns_prefix = getns_prefix(duthost, port_name)
    cmd = "sonic-db-cli {} APPL_DB HGET '{}:{}:{}:{}' sak".format(
        ns_prefix, table, port_name, sci, an)
    result = duthost.shell(cmd, module_ignore_errors=True)
    sak = result.get("stdout", "").strip()
    return sak if sak else None


def snapshot_appl_db_saks(duthost, ctrl_links):
    """
    Snapshot every (port, sci, an, direction) -> sak currently in APPL_DB
    across all macsec ctrl_links.  Useful as a before/after pivot for tests
    that need to detect SAK churn.
    """
    saks = {}
    for port_name, nbr in ctrl_links.items():
        host_sci = get_sci(duthost.get_dut_iface_mac(port_name))
        peer_sci = get_sci(nbr["host"].get_dut_iface_mac(nbr["port"]))
        for an in range(4):
            v = _get_appl_db_sa_sak(duthost, port_name, host_sci, an, egress=True)
            if v:
                saks[(port_name, host_sci, an, "egress")] = v
            v = _get_appl_db_sa_sak(duthost, port_name, peer_sci, an, egress=False)
            if v:
                saks[(port_name, peer_sci, an, "ingress")] = v
    return saks


def _asic_db_macsec_saks(duthost, ctrl_links):
    """
    Collect the set of SAKs currently programmed in ASIC_DB
    (SAI_OBJECT_TYPE_MACSEC_SA.SAI_MACSEC_SA_ATTR_SAK) across the
    namespaces that host the ctrl_link ports.

    ASIC_DB mirrors what syncd actually programmed into SAI/the chip, so
    it is the source of truth for the hardware SAK.  SAKs are returned
    upper-cased for case-insensitive comparison against APPL_DB.
    """
    ns_prefixes = set(getns_prefix(duthost, port_name) for port_name in ctrl_links)
    saks = set()
    for ns_prefix in ns_prefixes:
        keys = duthost.shell(
            "sonic-db-cli {} ASIC_DB KEYS "
            "'ASIC_STATE:SAI_OBJECT_TYPE_MACSEC_SA:*'".format(ns_prefix),
            module_ignore_errors=True,
        ).get("stdout", "").split()
        for key in keys:
            sak = duthost.shell(
                "sonic-db-cli {} ASIC_DB HGET '{}' "
                "SAI_MACSEC_SA_ATTR_SAK".format(ns_prefix, key),
                module_ignore_errors=True,
            ).get("stdout", "").strip()
            if sak:
                saks.add(sak.upper())
    return saks


def _sak_programming_gaps(duthost, ctrl_links):
    """
    Compare APPL_DB against ASIC_DB once and return
    ``(failures, asic_sak_count)``.

    ``failures`` is a list of human-readable descriptions, one per APPL_DB SA
    whose SAK is absent from ASIC_DB.  An empty list means every advertised
    SAK is programmed into SAI.  This is a single sample: callers that need a
    verdict should poll it via assert_appl_db_sak_programmed_in_asic, since
    ASIC_DB lags APPL_DB.
    """
    appl_saks = snapshot_appl_db_saks(duthost, ctrl_links)
    asic_saks = _asic_db_macsec_saks(duthost, ctrl_links)

    if not asic_saks:
        # Reported as a gap rather than raised: this runs inside a wait_until
        # predicate, which swallows exceptions, so raising here would turn a
        # real "nothing is programmed" into a silent retry with no diagnosis.
        return ["ASIC_DB has no MACSEC_SA objects at all — macsec is not "
                "programmed in hardware"], 0

    # SAI_MACSEC_SA_ATTR_SAK is always a 256-bit (64 hex chars) field in
    # ASIC_DB regardless of cipher suite.  For GCM-AES-128 the APPL_DB SAK
    # is 32 hex chars (128 bits); pad it to 64 chars before comparing so
    # AES-128 and AES-256 keys both match correctly.
    SAK_ASIC_FIELD_LEN = 64
    failures = []
    for (port_name, sci, an, direction), appl_sak in sorted(appl_saks.items()):
        normalized = appl_sak.upper().zfill(SAK_ASIC_FIELD_LEN)
        if normalized not in asic_saks:
            failures.append(
                "port={} sci={} an={} dir={}: APPL_DB sak={} is NOT present "
                "in ASIC_DB (stale-SAK bug: orchagent left the prior SAK in "
                "SAI after re-key)".format(
                    port_name, sci, an, direction, appl_sak))

    return failures, len(asic_saks)


def assert_appl_db_sak_programmed_in_asic(duthost, ctrl_links,
                                          timeout=SAK_PROGRAM_TIMEOUT,
                                          interval=SAK_PROGRAM_INTERVAL):
    """
    For every MACsec SA in APPL_DB, assert its SAK is actually present in
    ASIC_DB — i.e. the key orchagent advertises was really programmed into
    SAI/the chip.

    After a dirty restart wpa renegotiates a new SAK at the same (port,
    sci, AN), but the stale SA object survives in orchagent's
    MACsecSC::m_sa_ids, so createMACsecSA short-circuits and never
    reprograms SAI.  SAI_MACSEC_SA_ATTR_SAK is CREATE-ONLY, so the chip
    keeps the prior cycle's key while APPL_DB carries the fresh one.

    The comparison is retried until ``timeout``.  ASIC_DB is written
    asynchronously by orchagent/syncd, so it lags APPL_DB by an unbounded
    amount even after MKA reports converged; sampling it once turns that
    ordinary lag into an indistinguishable false positive.  Retrying makes
    a reported failure mean the SAK never arrived, rather than that it had
    not arrived yet.

    Raises AssertionError listing every APPL_DB SAK still absent from
    ASIC_DB once the timeout expires.
    """
    state = {}

    def _programmed():
        state["failures"], state["asic_count"] = _sak_programming_gaps(
            duthost, ctrl_links)
        if state["failures"]:
            logger.info("SAK programming incomplete: %d entry/entries still "
                        "absent from ASIC_DB; retrying", len(state["failures"]))
        return not state["failures"]

    if wait_until(timeout, interval, 0, _programmed):
        return

    failures = state.get("failures")
    if failures is None:
        raise AssertionError(
            "Could not sample APPL_DB/ASIC_DB SAK state within {}s".format(
                timeout))
    raise AssertionError(
        "APPL_DB->ASIC_DB SAK mismatch ({} entry/entries) still present after "
        "{}s; ASIC_DB holds {} distinct SAK(s):\n{}".format(
            len(failures), timeout, state.get("asic_count", 0),
            "\n".join("  * " + f for f in failures)))


# ---------------------------------------------------------------------------
# Encoding-AN (stale-AN) helpers
# ---------------------------------------------------------------------------

def get_egress_encoding_ans(duthost, ctrl_links):
    """
    Return {(port, host_sci): encoding_an} read from APPL_DB
    MACSEC_EGRESS_SC_TABLE for every ctrl_link.  encoding_an is the AN the
    egress SC is currently encrypting with.
    """
    ans = {}
    for port_name in ctrl_links:
        host_sci = get_sci(duthost.get_dut_iface_mac(port_name))
        ns_prefix = getns_prefix(duthost, port_name)
        v = duthost.shell(
            "sonic-db-cli {} APPL_DB HGET 'MACSEC_EGRESS_SC_TABLE:{}:{}' "
            "encoding_an".format(ns_prefix, port_name, host_sci),
            module_ignore_errors=True,
        ).get("stdout", "").strip()
        if v != "":
            ans[(port_name, host_sci)] = v
    return ans


def advance_egress_encoding_an(duthost, profile_name, ctrl_links,
                               policy, cipher_suite, send_sci,
                               rekey_period=20, advance_timeout=240):
    """
    Force the egress encoding AN past 0 by briefly enabling a short MKA rekey
    period, so a subsequent dirty restart crosses an AN boundary — the
    precondition for the stale-AN bug (the fix's sweep only runs when
    new_an != m_encoding_an).

    Sets rekey_period on the DUT MACSEC_PROFILE, graceful-restarts macsec to
    apply it (the session starts at AN=0), waits for MKA to converge, then
    polls until at least one egress SC's encoding_an advances to a non-zero
    value (i.e. one rekey has happened).  Leaves rekey_period set; the caller
    is responsible for restoring it (typically to 0 while macsec is killed so
    the post-restart session is stable).

    Returns the {(port, sci): encoding_an} map observed after the advance.
    """
    set_macsec_profile_fields(duthost, profile_name, rekey_period=rekey_period)
    graceful_restart_macsec(duthost)
    pytest_assert(
        wait_for_mka_converged(duthost, ctrl_links, policy, cipher_suite, send_sci),
        "MKA did not converge after enabling rekey_period={}".format(rekey_period))

    def _an_advanced():
        ans = get_egress_encoding_ans(duthost, ctrl_links)
        return ans and all(int(an) >= 1 for an in ans.values())

    pytest_assert(
        wait_until(advance_timeout, 5, 0, _an_advanced),
        "egress encoding_an did not advance to >=1 within {}s with "
        "rekey_period={} (cannot exercise stale-AN path)".format(
            advance_timeout, rekey_period))
    return get_egress_encoding_ans(duthost, ctrl_links)


def set_rekey_period(duthost, profile_name, rekey_period):
    """Set rekey_period on the DUT MACSEC_PROFILE (does not restart macsec)."""
    set_macsec_profile_fields(duthost, profile_name, rekey_period=rekey_period)


def _asic_db_egress_sa_ans_by_sc(duthost, ctrl_links):
    """
    Return {sc_oid: [an, ...]} for every EGRESS MACsec Secure Channel in
    ASIC_DB, listing the ANs of the egress SAs installed under each SC.

    A single shell loop on the DUT keeps this to one round-trip per
    namespace.  Output lines are 'EGRESS|<sc_oid>|<an>' per egress SA.
    """
    ns_prefixes = set(getns_prefix(duthost, port_name) for port_name in ctrl_links)
    sc_to_ans = {}
    for ns_prefix in ns_prefixes:
        script = (
            "for k in $(sonic-db-cli {ns} ASIC_DB KEYS "
            "'ASIC_STATE:SAI_OBJECT_TYPE_MACSEC_SA:*' 2>/dev/null); do "
            "d=$(sonic-db-cli {ns} ASIC_DB HGET \"$k\" "
            "SAI_MACSEC_SA_ATTR_MACSEC_DIRECTION); "
            "sc=$(sonic-db-cli {ns} ASIC_DB HGET \"$k\" "
            "SAI_MACSEC_SA_ATTR_SC_ID); "
            "an=$(sonic-db-cli {ns} ASIC_DB HGET \"$k\" "
            "SAI_MACSEC_SA_ATTR_AN); "
            "echo \"$d|$sc|$an\"; done"
        ).format(ns=ns_prefix)
        out = duthost.shell(script, module_ignore_errors=True).get("stdout", "")
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) != 3:
                continue
            direction, sc_oid, an = parts
            if "EGRESS" not in direction or not sc_oid:
                continue
            sc_to_ans.setdefault(sc_oid, []).append(an)
    return sc_to_ans


def assert_one_egress_sa_per_sc(duthost, ctrl_links):
    """
    After recovery, every egress Secure Channel must have exactly one SA in
    ASIC_DB.

    Stale-AN bug (SC side): a dirty restart kills wpa between
    enable_transmit_sa(new_an) and delete_transmit_sa(old_an).  The prior
    AN's SA survives in orchagent's sc.m_sa_ids and in SAI.  When the fresh
    session rekeys onto a different AN, setEncodingAN updates m_encoding_an
    but (unfixed) never sweeps the leaked old-AN SA, so the egress SC ends
    up with two installed SAs and the chip encrypts with the stale one while
    the peer's ingress SC has no SA at that AN -> IN_PKTS_NOT_USING_SA, LACP
    down.  The fix sweeps non-current ANs, restoring one-SA-per-SC.

    Raises AssertionError listing every egress SC carrying more than one SA.
    """
    sc_to_ans = _asic_db_egress_sa_ans_by_sc(duthost, ctrl_links)

    pytest_assert(
        sc_to_ans,
        "ASIC_DB has no egress MACSEC_SA objects — cannot validate the "
        "one-SA-per-SC invariant (macsec not converged in hardware?)")

    failures = []
    for sc_oid, ans in sorted(sc_to_ans.items()):
        if len(ans) != 1:
            failures.append(
                "egress SC {} has {} SAs at AN(s) {} (expected exactly 1); "
                "stale-AN bug left the pre-restart SA installed alongside the "
                "post-rekey one".format(sc_oid, len(ans), sorted(ans)))

    if failures:
        raise AssertionError(
            "egress SC one-SA invariant violated ({} SC(s)):\n{}".format(
                len(failures), "\n".join("  * " + f for f in failures)))
