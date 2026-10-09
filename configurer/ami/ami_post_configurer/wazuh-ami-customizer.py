import argparse
import logging
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from configurer.core.models import CertsManager
from configurer.core.utils import WAZUH_BASE_DIR, WAZUH_CA_DIR, ComponentCertsDirectory, CredentialKey, read_credential
from generic import exec_command, exec_command_with_status
from utils import Component, Logger

LOGFILE = Path("/var/log/wazuh-ami-customizer.log")
TEMP_DIR = Path("/etc/wazuh-ami-customizer")
CERTS_TOOL_PATH = Path(f"{TEMP_DIR}/certs-tool.sh")
CERTS_TOOL_CONFIG_PATH = Path(f"{TEMP_DIR}/config.yml")
SERVICE_PATH = "/etc/systemd/system"
SERVICE_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.service"
SERVICE_TIMER_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.timer"
WAZUH_WARNING_SCRIPT = Path("/etc/profile.d/wazuh-debug-warning.sh")

# The manager CLI that mints enrollment tokens. It is a client of the local authd socket, not a
# standalone generator, so wazuh-manager-authd has to be running before this is called.
WAZUH_MANAGER_AUTHD_BIN = "/var/wazuh-manager/bin/wazuh-manager-authd"

# Publishes the manager's CA bundle (etc/certs/root-ca.pem) to the agents (wazuh/wazuh#39319).
WAZUH_MANAGER_CERTS_BIN = "/var/wazuh-manager/bin/wazuh-manager-certs"

# Where the pre-installed agent picks the token up. w_agent_token_bootstrap() reads it once at the
# agent's first start, while still root, installs the trust anchor the token carries, enrolls, and
# unlinks the file.
WAZUH_AGENT_ENROLLMENT_TOKEN_FILE = "/var/ossec/etc/enrollment_token"

# Everything a build leaves behind that would make the freshly minted token useless or unsafe.
# The bootstrap refuses to run at all when the agent already holds a trust anchor or a key -- it
# deletes the token unused in both cases -- so anything baked into the image has to go first.
WAZUH_MANAGER_AUTHD_PASS_FILE = "/var/wazuh-manager/etc/authd.pass"
WAZUH_MANAGER_ENROLLMENT_TOKENS_FILE = "/var/wazuh-manager/etc/enrollment_tokens.json"
WAZUH_AGENT_AUTHD_PASS_FILE = "/var/ossec/etc/authd.pass"
WAZUH_AGENT_CA_FILE = "/var/ossec/etc/certs/root-ca.pem"
WAZUH_AGENT_CLIENT_KEYS_FILE = "/var/ossec/etc/client.keys"
WAZUH_AGENT_REENROLL_SECRET_FILE = "/var/ossec/etc/reenroll.secret"

# The address the token names, and the address the pre-installed agent's <manager><endpoint> already
# holds (configurer/core/static/configuration_mappings.yaml). Manager and agent are on the same
# instance, so loopback is the one address that is always reachable and never changes. It is a SAN
# entry of remoted.pem through the manager node of the cert-tool config, and a mint only refuses an
# address the listener certificate does not name -- or a certificate whose SAN is loopback AND
# NOTHING ELSE, which is why create_certificates() has to add the instance's own addresses first.
WAZUH_AGENT_ENROLLMENT_ADDRESS = "127.0.0.1"

# The indexer's own admin account, used to poll both the indexer and the dashboard (which
# authenticates against the indexer's security plugin), and the manager API account the dashboard
# uses. Their passwords are not known in advance: the packages generate them on this first boot
# (`resolve-credentials --prestart`) and publish them to /etc/wazuh/credentials.env, which stays on
# the instance as the record the user reads them from.
WAZUH_INDEXER_ADMIN_USER = "admin"
WAZUH_MANAGER_API_USER = "wazuh-internal-client"

# The token CLI talks to queue/sockets/auth.sock, which a manager reporting "active" may still be
# opening: systemctl returns as soon as the unit is active, not once every daemon inside it has
# finished initializing. Retry instead of failing the whole first boot on that race.
ENROLLMENT_TOKEN_MAX_RETRIES = 12
ENROLLMENT_TOKEN_WAIT_TIME = 5

# This instance's own root CA (key included) lives on past first boot in WAZUH_CA_DIR
# (/etc/wazuh/ca), where the packages' shared credentials library expects it, so a leaf can be
# reissued later (e.g. the instance's address changes, or a load balancer joins) without a brand new
# CA every enrolled agent would have to re-trust. Issue #957 only requires that root-ca.key never
# ship baked into the image, not that a launched instance destroy its own copy.
WAZUH_CERTS_TAR = TEMP_DIR / "wazuh-certificates.tar"

# WORKAROUND (until the indexer's --clear handles it): the indexer postinst imports its CA into the
# bundled JDK truststore as "wazuh-root-ca". The build removes the build CA from there
# (purge-build-credentials.sh), so first boot imports this instance's CA instead, as a fresh
# package install would.
INDEXER_KEYTOOL = "/usr/share/wazuh-indexer/jdk/bin/keytool"
INDEXER_JDK_CA_ALIAS = "wazuh-root-ca"
INDEXER_JDK_CACERTS_PASS = "changeit"

# A stopped unit that left processes behind keeps them in its cgroup until the last one exits.
SERVICE_CGROUP_PROCS = "/sys/fs/cgroup/system.slice/{unit}/cgroup.procs"
SERVICE_LEFTOVERS_MAX_RETRIES = 10
SERVICE_LEFTOVERS_WAIT_TIME = 2

logger = Logger("CustomCertificates")
file_handler = logging.FileHandler(LOGFILE)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(file_handler)


def run_command(command: str, error_message: str) -> str:
    """
    Runs a command and treats only a non-zero exit status as a failure.

    Tools invoked during the customization write to stderr while still doing their job: the
    dashboard keystore CLI, for one, reports an uncaught EPIPE when the password tool pipes its
    listing into `grep -q`. Aborting on any stderr output stopped the customization on that noise
    and left the instance half configured -- part of the passwords rotated, the rest still the
    defaults -- so the exit status is what decides here and stderr is only kept for the log.

    `set -e` makes a multi-command block report the first command that fails instead of the exit
    status of its last line, which is what the stderr check used to cover.

    Args:
        command (str): The command to run.
        error_message (str): Message logged and raised when the command fails.

    Returns:
        str: The command standard output.
    """

    output, error_output, returncode = exec_command_with_status(command=f"set -e\n{command}")

    if returncode != 0:
        logger.error(f"{error_message} (exit {returncode}): {error_output.strip() or output.strip()}")
        raise RuntimeError(error_message)

    if error_output.strip():
        logger.debug(f"Command succeeded but wrote to stderr: {error_output.strip()}")

    return output


def start_service(name: str) -> None:
    """
    Starts a service using systemctl.
    Args:
        name (str): The name of the service to start.

    Returns:
        None
    """

    logger.debug(f"Starting {name} service...")

    run_command(command=f"systemctl start {name}", error_message=f"Error starting {name} service")

    logger.debug(f"{name} service started")


def get_service_leftover_pids(name: str) -> list[str]:
    """
    Returns the PIDs a stopped service left running, read from the unit cgroup.

    Args:
        name (str): The name of the service to inspect.

    Returns:
        list[str]: The PIDs still in the unit cgroup. Empty once the unit is really gone.
    """

    unit = name if name.endswith(".service") else f"{name}.service"
    output, _ = exec_command(command=f"cat {SERVICE_CGROUP_PROCS.format(unit=unit)} 2>/dev/null")

    return output.split()


def kill_service_leftovers(name: str) -> None:
    """
    Terminates the processes a stopped service left running.

    systemd only runs ExecStop once a unit reached the active state: a stop issued while the unit is
    still activating skips it, and with the KillMode=process the Wazuh units use, every daemon
    already spawned survives the stop. Those orphans keep their sockets bound -- the manager API
    port among them -- and break the daemons started later in the customization, which is why
    anything the unit left behind is terminated here instead of being left to collide.

    Args:
        name (str): The name of the service whose leftovers must be terminated.

    Returns:
        None
    """

    if not get_service_leftover_pids(name):
        return

    logger.debug(f"{name} left processes running after the stop, terminating them...")

    for kill_signal in ("SIGTERM", "SIGKILL"):
        exec_command(command=f"systemctl kill --kill-whom=all --signal={kill_signal} {name}")

        for _ in range(SERVICE_LEFTOVERS_MAX_RETRIES):
            if not get_service_leftover_pids(name):
                logger.debug(f"{name} leftover processes terminated")
                return
            time.sleep(SERVICE_LEFTOVERS_WAIT_TIME)

    logger.error(f"Could not terminate the processes left running by the {name} service")
    raise RuntimeError(f"Could not terminate the processes left running by the {name} service")


def stop_service(name: str) -> None:
    """
    Stops the specified service.
    Args:
        name (str): The name of the service to stop.

    Returns:
        None
    """

    logger.debug(f"Stopping {name} service...")

    run_command(command=f"systemctl stop {name}", error_message=f"Error stopping {name} service")

    kill_service_leftovers(name)

    logger.debug(f"{name} service stopped")


def debug_ssh_message() -> None:
    exec_command(
        command="""
    mkdir -p /var/lib/wazuh
    touch /var/lib/wazuh/DEBUG_MODE
    """
    )


def http_status(url: str, user: str, password_key: str, method: str = "GET") -> str:
    """
    Sends one request authenticated with a password from /etc/wazuh/credentials.env.

    The password goes to curl through its standard input (`-K -`), never on its command line, where
    any local user could read it off the process list, and it is never logged.

    Args:
        url (str): The URL to request.
        user (str): The user to authenticate as.
        password_key (str): The credentials.env key holding that user's password.
        method (str): The HTTP method. Defaults to GET.

    Returns:
        str: The HTTP status code, or "000" if the request could not be made.
    """

    try:
        password = read_credential(password_key)
    except (OSError, KeyError) as error:
        logger.warning(f"Cannot read {password_key}: {error}")
        return "000"

    result = subprocess.run(
        [
            "curl",
            "-s",
            "-k",
            "-K",
            "-",
            "-X",
            method,
            "--max-time",
            "120",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            url,
        ],
        input=f'user = "{user}:{password}"\n',
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() or "000"


def verify_component_connection(
    component: Component, check: Callable[[], str], retries: int = 5, wait_time: int = 10
) -> None:
    """
    Verifies the component connection by sending a request to the component's endpoint.
    Args:
        component (Component): The component to verify.
        check (Callable[[], str]): Sends the request and returns its HTTP status code.
        retries (int): Number of retries if the connection fails.
        wait_time (int): Time to wait between retries.

    Returns:
        None
    """

    logger.debug(f"Verifying {component.replace('_', ' ')} connection...")

    for attempt in range(retries):
        output = check()
        if output == "200":
            logger.debug(f"{component.replace('_', ' ')} connection verified successfully")
            return

        if attempt < retries - 1:
            wait = wait_time * (attempt + 1)  # Incremental wait time
            logger.debug(f"Attempt {attempt + 1} failed (HTTP {output}), retrying in {wait} seconds...")
            time.sleep(wait)
        else:
            logger.error(f"{component.replace('_', ' ')} connection failed after {retries} attempts")
            debug_ssh_message()  # Enable debug mode
            start_ssh_service()  # Restore SSH service for debugging
            raise RuntimeError(f"{component.replace('_', ' ')} connection failed")


def enable_service(name: str) -> None:
    """
    Enables a service using systemctl.
    Args:
        name (str): The name of the service to enable.

    Returns:
        None
    """

    logger.debug(f"Enabling {name} service...")

    run_command(command=f"systemctl --quiet enable {name}", error_message=f"Error enabling {name} service")

    logger.debug(f"{name} service enabled")


def run_indexer_security_init() -> None:
    """
    Runs the indexer security initialization script.
    This function is used to initialize the indexer security settings after creating new certificates.
    It ensures that the indexer is properly configured with the new certificates.

    Returns:
        None
    """

    logger.debug("Running indexer security initialization...")

    run_command(
        command="eval /usr/share/wazuh-indexer/bin/indexer-security-init.sh",
        error_message="Error running indexer security initialization",
    )

    logger.debug("Indexer security initialization completed")


def remove_certificates() -> None:
    """
    Removes existing certificates from the components.
    This function is used to remove existing certificates before creating new ones.
    It ensures that the old certificates are deleted and do not interfere with the new ones.

    Returns:
        None
    """

    logger.debug("Removing existing certificates...")
    # The CA directory goes too: if an earlier first-boot attempt failed after installing its CA, a
    # retry would otherwise keep that CA (key and JDK truststore entry included) while issuing the
    # certificates from a new one.
    command = f"""
    rm -rf {ComponentCertsDirectory.WAZUH_MANAGER}/*
    rm -rf {ComponentCertsDirectory.WAZUH_INDEXER}/*
    rm -rf {ComponentCertsDirectory.WAZUH_DASHBOARD}/*
    rm -rf {WAZUH_CA_DIR}
    """
    run_command(command=command, error_message="Error removing existing certificates")

    logger.debug("Existing certificates removed")


def get_manager_san_ips() -> list[str]:
    """
    Collects the addresses agents may dial to reach this instance's manager, for remoted.pem's SAN.

    `hostname -I` (util-linux) already lists every configured address on every non-loopback
    interface, IPv4 and IPv6 alike (only IPv6 link-local is excluded) -- no separate handling
    needed for IPv6 there. It does NOT cover a public IPv4, though: AWS 1:1-NATs it, so it never
    appears on any local interface, only in the instance metadata service. Public IPv6 is not
    NAT'd -- AWS assigns it straight to the ENI -- but whether the OS actually configures it on an
    interface (and so whether `hostname -I` catches it) depends on the AMI's own network setup, so
    it's looked up the same way as a defensive second source, not assumed. Either metadata lookup
    reports "not available" when the instance has none, which is filtered out rather than baked
    into the SAN as a literal string.

    Fed to CertsManager.generate_certificates()'s agent_san, which passes each value straight
    through as a repeated `--agent-san <value>` flag to wazuh-certs-tool.sh -- additive on top of
    the manager node's own config.yml entry (127.0.0.1, untouched), not a replacement for it.

    DEPENDS ON wazuh-installation-assistant#1027 (Victor Ereñú, opened 2026-09-16, NOT MERGED as of
    this writing): --agent-san doesn't exist yet, and neither does that issue's other change this
    relies on -- dropping the public-IP refusal in cert_validateComponentSanValues() -- so the
    public/IPv6-metadata addresses collected here would still be rejected by the tool as it stands
    today. Written ahead of the merge so there's less to wire up once it lands; verify against the
    real tool before trusting this.

    Returns:
        list[str]: Extra addresses for remoted.pem's SAN, on top of "127.0.0.1".
    """

    logger.debug("Collecting the instance's addresses for the manager certificate SAN")
    ips: list[str] = []

    local_ips_output = run_command(
        command="hostname -I", error_message="Error listing local network interface addresses"
    )
    ips.extend(ip for ip in local_ips_output.split() if ip)

    for metadata_flag, error_message in (
        ("--public-ipv4", "Error retrieving the instance's public IPv4 address"),
        ("--ipv6", "Error retrieving the instance's IPv6 address"),
    ):
        metadata_output = run_command(
            command=f"ec2-metadata {metadata_flag} | cut -d':' -f2", error_message=error_message
        )
        metadata_ip = metadata_output.strip()
        if metadata_ip and "not available" not in metadata_ip:
            ips.append(metadata_ip)

    ips = list(dict.fromkeys(ips))  # de-dupe (hostname -I and ec2-metadata can report the same IP), keep order

    logger.debug(f"Manager certificate SAN addresses: {ips}")
    return ips


def create_certificates() -> None:
    """
    Creates new certificates using the CertsManager.

    Returns:
        None
    """

    logger.debug("Creating new certificates...")
    certs_manager = CertsManager(raw_config_path=CERTS_TOOL_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)
    try:
        certs_manager.generate_certificates(agent_san=get_manager_san_ips())
        publish_manager_ca()
        install_certificate_authority()
    finally:
        # install_certificate_authority() is the last reader of WAZUH_CERTS_TAR, so it is removed here
        # instead of waiting for clean_up(): that only runs when the whole customization succeeds, and
        # the failure path restarts sshd, which would leave every leaf private key sitting in the tar
        # for whoever logs in next. Done in `finally` so it also covers a failure while generating or
        # installing the certificates, before the error handler in main brings SSH back.
        remove_certs_tar()
    logger.debug("New certificates created")


def publish_manager_ca() -> None:
    """
    Publishes the root-ca.pem just installed for the manager with `wazuh-manager-certs stamp`.

    remoted remembers the build-time bundle; replacing it without publishing makes remoted log
    "changed outside the tool and is not published" and announce ca_generation 0 to the agents
    (wazuh-virtual-machines#1022). stamp publishes the bundle as is. It only needs the files, not a
    running manager, and checks the bundle against remoted.pem, so it runs once both are installed.

    Returns:
        None
    """

    logger.debug("Publishing the manager CA bundle")
    run_command(command=f"{WAZUH_MANAGER_CERTS_BIN} stamp", error_message="Error publishing the manager CA bundle")


def remove_certs_tar() -> None:
    """
    Deletes WAZUH_CERTS_TAR, the bundle CertsManager packs every generated certificate and leaf private
    key into. Once the certificates are in each component's own directory it is only a leftover.

    A failure to delete it is logged but never raised: this runs from a `finally`, where raising would
    replace the original error that made the customization fail.

    Returns:
        None
    """

    try:
        WAZUH_CERTS_TAR.unlink(missing_ok=True)
    except OSError as error:
        logger.error(f"Could not remove {WAZUH_CERTS_TAR}, it still holds the private keys: {error}")


def install_certificate_authority() -> None:
    """
    Leaves this instance's root CA in /etc/wazuh/ca, where the packages' shared credentials library
    expects the trust anchor: the directory root:root 0700, root-ca.pem 0644 and root-ca.key 0400.

    A wazuh-certs-tool.sh built on that library already creates the CA there and never copies its key
    into the certificates bundle. An older one creates it in its own output directory, which
    CertsManager packs into WAZUH_CERTS_TAR, so the anchor and its key are taken from the tar then.

    Returns:
        None
    """

    logger.debug(f"Installing this instance's CA in {WAZUH_CA_DIR}")

    command = f"""
    install -d -m 0700 -o root -g root {WAZUH_BASE_DIR} {WAZUH_CA_DIR}
    if [ ! -f {WAZUH_CA_DIR}/root-ca.pem ]; then
        tar -xf {WAZUH_CERTS_TAR} -C {WAZUH_CA_DIR} ./root-ca.pem
        if tar -tf {WAZUH_CERTS_TAR} ./root-ca.key > /dev/null 2>&1; then
            tar -xf {WAZUH_CERTS_TAR} -C {WAZUH_CA_DIR} ./root-ca.key
        fi
    fi
    chown root:root {WAZUH_CA_DIR}/root-ca.*
    chmod 0644 {WAZUH_CA_DIR}/root-ca.pem
    if [ -f {WAZUH_CA_DIR}/root-ca.key ]; then chmod 0400 {WAZUH_CA_DIR}/root-ca.key; fi
    """
    run_command(command=command, error_message=f"Error installing the CA in {WAZUH_CA_DIR}")

    # WORKAROUND: this instance's CA into the indexer JDK truststore, before the indexer starts.
    # -cacerts: the truststore of the keytool's own JDK, the indexer's.
    keytool_opts = f"-cacerts -storepass {INDEXER_JDK_CACERTS_PASS}"
    command = f"""
    if {INDEXER_KEYTOOL} -list {keytool_opts} -alias {INDEXER_JDK_CA_ALIAS} > /dev/null 2>&1; then
        {INDEXER_KEYTOOL} -delete {keytool_opts} -alias {INDEXER_JDK_CA_ALIAS}
    fi
    {INDEXER_KEYTOOL} -importcert {keytool_opts} -noprompt -alias {INDEXER_JDK_CA_ALIAS} -file {WAZUH_CA_DIR}/root-ca.pem
    """
    run_command(command=command, error_message="Error importing the CA into the indexer JDK truststore")

    logger.debug("CA installed")


def stop_ssh_service() -> None:
    """
    Stops the SSH service on the system.
    This function is used to stop the SSH service before configuring custom certificates.
    It ensures that the SSH service is not running during the configuration process.

    Returns:
        None
    """

    stop_service("sshd.service")


def stop_components_services() -> None:
    """
    Stops all Wazuh components services.
    This function is used to stop the Wazuh components services before configuring custom certificates.
    It ensures that all components are stopped and not running during the configuration process.

    Returns:
        None
    """

    logger.debug("Stopping Wazuh components services...")

    stop_service("wazuh-agent")
    stop_service("wazuh-indexer")
    stop_service("wazuh-manager")
    stop_service("wazuh-dashboard")

    logger.debug("Wazuh components services stopped")


def verify_indexer_connection() -> None:
    """
    Verifies the connection to the Wazuh indexer as admin, with the password the indexer package
    generated on this boot (WAZUH_INDEXER_ADMIN_PASSWORD in /etc/wazuh/credentials.env).

    Returns:
        None
    """

    verify_component_connection(
        Component.WAZUH_INDEXER,
        lambda: http_status("https://localhost:9200/", WAZUH_INDEXER_ADMIN_USER, CredentialKey.INDEXER_ADMIN),
    )


def verify_manager_connection() -> None:
    """
    Verifies the connection to the Wazuh manager API as wazuh-internal-client, the account the dashboard uses,
    with the password the manager package generated on this boot (WAZUH_MANAGER_WUI_PASSWORD).

    Returns:
        None
    """

    verify_component_connection(
        Component.WAZUH_MANAGER,
        lambda: http_status(
            "https://localhost:55000/security/user/authenticate",
            WAZUH_MANAGER_API_USER,
            CredentialKey.MANAGER_WUI,
            method="POST",
        ),
    )


def verify_dashboard_connection() -> None:
    """
    Verifies the Wazuh dashboard as admin, the account the user logs in with. The dashboard only
    answers once it has authenticated to the indexer as kibanaserver, so this also covers that pair.

    Returns:
        None
    """

    verify_component_connection(
        Component.WAZUH_DASHBOARD,
        lambda: http_status("https://localhost:443/status", WAZUH_INDEXER_ADMIN_USER, CredentialKey.INDEXER_ADMIN),
    )


def start_ssh_service() -> None:
    """
    Starts the SSH service on the system.

    This function is used to start the SSH service after the custom certificates have been configured.
    It ensures that the SSH service is running and ready to accept connections.

    Returns:
        None
    """

    start_service("sshd.service")


def reset_agent_enrollment_state() -> None:
    """
    Removes every enrollment credential and agent identity the image was built with.

    The build leaves two kinds of leftovers behind, and both have to go before a token minted on
    this instance can be used:

    * Credentials the manager generated during the build -- its Authd password and, if anything ever
      minted one there, its enrollment token store. Shipped as they are, every instance launched
      from this AMI would share them. This is what the old rotate_authd_password() did, widened
      to the artifact that replaced the password.
    * Anything on the agent side that makes the token bootstrap decline to run. It refuses whenever
      the agent already holds a trust anchor or a non-empty client.keys -- on both counts it deletes
      the token unused and returns -- so a baked anchor or a baked key would silently turn the fresh
      token into a no-op and leave every deployed instance enrolled under one identity.

    client.keys is truncated rather than deleted so the file keeps the ownership and mode the agent
    package gave it; the bootstrap only looks at its size.

    Returns:
        None
    """

    logger.debug("Removing the enrollment credentials and agent identity baked into the image")

    command = f"""
    rm -f {WAZUH_MANAGER_AUTHD_PASS_FILE} {WAZUH_MANAGER_ENROLLMENT_TOKENS_FILE}
    rm -f {WAZUH_AGENT_AUTHD_PASS_FILE} {WAZUH_AGENT_ENROLLMENT_TOKEN_FILE}
    rm -f {WAZUH_AGENT_CA_FILE} {WAZUH_AGENT_REENROLL_SECRET_FILE}
    if [ -f {WAZUH_AGENT_CLIENT_KEYS_FILE} ]; then : > {WAZUH_AGENT_CLIENT_KEYS_FILE}; fi
    """
    run_command(command=command, error_message="Error removing the baked enrollment state")

    logger.debug("Baked enrollment credentials and agent identity removed")


def mint_agent_enrollment_token() -> str:
    """
    Mints a fresh enrollment token on this instance and returns it.

    The token is minted, never baked: it is created here, on the running manager, with the CA and
    the listener certificate this instance generated for itself moments earlier in
    create_certificates(). Its 30-day TTL (the CLI default, wazuh#39068) is therefore irrelevant and
    is left alone on purpose -- a token is minted on every first boot and consumed within seconds,
    so it never gets anywhere near expiring, and shortening it would buy nothing. Do NOT "fix" this
    later by minting a long-lived token at build time and shipping it in the image: that hands every
    instance launched from this AMI the same credential, which is the whole reason this runs here.

    --embed-ca carries the CA inside the token instead of a pin of it, so the agent has its trust
    anchor without first fetching /cacerts over a connection it cannot verify yet. --max-uses 1
    because exactly one agent, the one on this instance, will ever use it.

    Returns:
        str: The token text, as the CLI prints it on stdout.

    Raises:
        RuntimeError: If no token could be minted after all retries.
    """

    logger.debug("Minting the enrollment token for the pre-installed agent")

    command = (
        f"{WAZUH_MANAGER_AUTHD_BIN} --create-enrollment-token"
        f" --address {WAZUH_AGENT_ENROLLMENT_ADDRESS}"
        " --embed-ca"
        " --max-uses 1"
        " --description 'Pre-installed agent, minted on first boot'"
    )

    for attempt in range(ENROLLMENT_TOKEN_MAX_RETRIES):
        output, error_output, returncode = exec_command_with_status(command=command)
        if returncode == 0 and output.strip():
            logger.debug("Enrollment token minted")
            return output.strip()
        logger.debug(
            f"Could not mint the enrollment token yet, retrying in {ENROLLMENT_TOKEN_WAIT_TIME} seconds "
            f"(attempt {attempt + 1}/{ENROLLMENT_TOKEN_MAX_RETRIES}): {error_output.strip()}"
        )
        time.sleep(ENROLLMENT_TOKEN_WAIT_TIME)

    logger.error("Error minting the enrollment token for the pre-installed agent")
    raise RuntimeError("Error minting the enrollment token for the pre-installed agent")


def set_agent_enrollment_token() -> None:
    """
    Leaves a freshly minted enrollment token where the pre-installed agent picks it up.

    Replaces the old authd.pass copy: the manager no longer hands the agent a shared registration
    password, it mints a credential for that one agent (wazuh#39063). The agent reads this file on
    its first start, while it is still root, installs the CA the token carries as its trust anchor,
    enrolls, and unlinks the file.

    Written the same way the agent installer writes it: created and locked down to 0600 root:root
    BEFORE the token goes into it, so the credential is never briefly readable by anyone else. The
    file never reaches a command line either, which is why it is written from here instead of being
    echoed through a shell.

    Returns:
        None

    Raises:
        RuntimeError: If the token cannot be minted or stored.
    """

    token = mint_agent_enrollment_token()

    logger.debug(f"Storing the enrollment token at {WAZUH_AGENT_ENROLLMENT_TOKEN_FILE}")

    try:
        descriptor = os.open(WAZUH_AGENT_ENROLLMENT_TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            os.write(descriptor, token.encode())
        finally:
            os.close(descriptor)
    except OSError as error:
        logger.error(f"Error storing the enrollment token: {error}")
        raise RuntimeError("Error storing the enrollment token") from error

    logger.debug("Enrollment token stored successfully")


def start_components_services() -> None:
    """
    Starts all Wazuh components services.
    This function is used to start the Wazuh components services after the custom certificates have been configured.
    It ensures that all components are running and ready to accept connections.

    Returns:
        None
    """

    logger.debug("Starting Wazuh components services...")

    # Strictly in this order, never in parallel: each package resolves its credentials when its
    # service starts (`resolve-credentials --prestart`, wazuh-virtual-machines#973). The indexer
    # generates admin, kibanaserver and wazuh-manager and publishes them to /etc/wazuh/credentials.env;
    # the manager and the dashboard read theirs from there and refuse to start (MISSING) if the indexer
    # has not published them yet. Certificates are already in place (create_certificates()): the
    # packages never issue them outside `--install`.
    enable_service("wazuh-indexer")
    start_service("wazuh-indexer")
    # Loading the security configuration stays a manual step of the indexer package: it uploads the
    # digests the indexer's --prestart just wrote into internal_users.yml.
    run_indexer_security_init()
    verify_indexer_connection()

    # Clear the enrollment credentials and the agent identity the image was built with, before the
    # manager starts, so nothing baked into the AMI is reused and the token minted below is the only
    # way this instance's agent can register.
    reset_agent_enrollment_state()

    enable_service("wazuh-manager")
    start_service("wazuh-manager")
    verify_manager_connection()

    enable_service("wazuh-dashboard")
    start_service("wazuh-dashboard")
    time.sleep(20)  # Wait for dashboard to initialize
    verify_dashboard_connection()

    # Mint the agent's enrollment token and leave it where the agent reads it on its first start.
    # It has to be done after the manager is up, since minting goes through the local authd socket,
    # and before the agent starts, which is the only moment the bootstrap looks for the file. The
    # agent installs the CA the token carries as its trust anchor, so nothing is copied by hand.
    set_agent_enrollment_token()

    enable_service("wazuh-agent")
    start_service("wazuh-agent")

    logger.debug("Wazuh components services started")


def clean_up() -> None:
    """
    Cleans up temporary files and directories created during the process.

    TEMP_DIR holds the cert-tool's own working directory, including WAZUH_CERTS_TAR -- a tar of its
    whole output, unfiltered, which with older certs-tool versions also carries the root CA's private
    key with none of the restrictive permissions applied to what gets extracted into each component's
    own directory. The CA itself is kept, secured, in WAZUH_CA_DIR (install_certificate_authority()).

    /etc/wazuh/credentials.env is deliberately left in place: it is where the user reads the
    generated passwords from, and the documentation tells them to delete it once they have.

    Returns:
        None
    """

    logger.debug("Cleaning up temporary files and directories...")

    command = f"""
    rm -rf {TEMP_DIR}
    rm -rf {LOGFILE}
    rm -rf {SERVICE_NAME}
    rm -rf {SERVICE_TIMER_NAME}
    rm -rf {WAZUH_WARNING_SCRIPT}
    """
    run_command(command=command, error_message="Error cleaning up")
    logger.debug("Clean up completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wazuh AMI Customizer")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode (skips cleanup)")
    args = parser.parse_args()

    if args.debug:
        logger.info("Debug mode enabled. Cleanup will be skipped.")

    logger.info("Starting custom certificates configuration process")

    try:
        if args.debug:
            logger.info("Wazuh customizer is running in debug mode.")
            debug_ssh_message()
        stop_ssh_service()
        stop_components_services()
        remove_certificates()
        create_certificates()
        start_components_services()
        start_ssh_service()

        if not args.debug:
            clean_up()

    except Exception as e:
        logger.error(f"An error occurred during the customization process: {e}")
        start_ssh_service()
        raise RuntimeError("An error occurred during the customization process") from e

    logger.info("Customization process finished")
