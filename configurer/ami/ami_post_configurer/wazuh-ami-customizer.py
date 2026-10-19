import argparse
import json
import logging
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from configurer.core.utils import (
    WAZUH_MANAGER_CONF_DIR,
    CredentialKey,
    read_credential,
)
from generic import exec_command, exec_command_with_status
from utils import Component, Logger

LOGFILE = Path("/var/log/wazuh-ami-customizer.log")
TEMP_DIR = Path("/etc/wazuh-ami-customizer")
SERVICE_PATH = "/etc/systemd/system"
SERVICE_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.service"
SERVICE_TIMER_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.timer"
WAZUH_WARNING_SCRIPT = Path("/etc/profile.d/wazuh-debug-warning.sh")

# The manager CLI that mints enrollment tokens. It is a client of the local authd socket, not a
# standalone generator, so wazuh-manager-authd has to be running before this is called.
WAZUH_MANAGER_AUTHD_BIN = "/var/wazuh-manager/bin/wazuh-manager-authd"

# Publishes the manager's CA bundle (certs/root-ca.pem) to the agents (wazuh/wazuh#39319).
WAZUH_MANAGER_CERTS_BIN = "/var/wazuh-manager/bin/wazuh-manager-certs"

# Where the pre-installed agent picks the token up. w_agent_token_bootstrap() reads it once at the
# agent's first start, while still root, installs the trust anchor the token carries, enrolls, and
# unlinks the file.
WAZUH_AGENT_ENROLLMENT_TOKEN_FILE = "/var/ossec/etc/enrollment_token"

# Everything a build leaves behind that would make the freshly minted token useless or unsafe.
# The bootstrap refuses to run at all when the agent already holds a trust anchor or a key -- it
# deletes the token unused in both cases -- so anything baked into the image has to go first.
WAZUH_MANAGER_AUTHD_PASS_FILE = f"{WAZUH_MANAGER_CONF_DIR}/authd.pass"
WAZUH_MANAGER_ENROLLMENT_TOKENS_FILE = f"{WAZUH_MANAGER_CONF_DIR}/enrollment_tokens.json"
WAZUH_AGENT_AUTHD_PASS_FILE = "/var/ossec/etc/authd.pass"
WAZUH_AGENT_CA_FILE = "/var/ossec/etc/certs/root-ca.pem"
# Written by the agent once it has committed to a trust anchor. With it present and the anchor gone,
# agentd refuses to start (error 4125) instead of bootstrapping a new one, so it goes with the anchor.
WAZUH_AGENT_ANCHOR_COMMITTED_FILE = "/var/ossec/etc/certs/.anchor-committed"
WAZUH_AGENT_CLIENT_KEYS_FILE = "/var/ossec/etc/client.keys"
WAZUH_AGENT_REENROLL_SECRET_FILE = "/var/ossec/etc/reenroll.secret"

# The address the token names, and the address the pre-installed agent's <manager><endpoint> already
# holds (configurer/core/static/configuration_mappings.yaml). Manager and agent are on the same
# instance, so loopback is the one address that is always reachable and never changes. The manager's
# resolver always adds it to remoted.pem's SANs, and a mint only refuses an address the listener
# certificate does not name -- or a certificate whose SAN is loopback AND NOTHING ELSE, which is why
# write_manager_local_env() hands it the instance's own addresses first.
WAZUH_AGENT_ENROLLMENT_ADDRESS = "127.0.0.1"

# The indexer's own admin account, used to poll both the indexer and the dashboard (which
# authenticates against the indexer's security plugin), and the manager API account the dashboard
# uses. Their passwords are not known in advance: the packages generate them on this first boot
# (`resolve-credentials --prestart`) and publish them to their own export/credentials.env
# (credentials_file_for), which stays on the instance as the record the user reads them from.
WAZUH_INDEXER_ADMIN_USER = "admin"
WAZUH_MANAGER_API_USER = "wazuh-internal-client"

# The token CLI talks to queue/sockets/auth.sock, which a manager reporting "active" may still be
# opening: systemctl returns as soon as the unit is active, not once every daemon inside it has
# finished initializing. Retry instead of failing the whole first boot on that race.
ENROLLMENT_TOKEN_MAX_RETRIES = 12
ENROLLMENT_TOKEN_WAIT_TIME = 5

# Each package's credential resolver. `--install` mints the package's CA and issues its pairs; it is
# the only mode that issues certificates, so first boot runs it again after the build purge cleared
# what the packages' postinst made (wazuh/internal-devel-requests#7048). In this order: the manager
# and the dashboard import the indexer's export/, the dashboard also the manager's.
CREDENTIAL_RESOLVERS = (
    "/usr/share/wazuh-indexer/bin/resolve-credentials.sh",
    "/var/wazuh-manager/bin/wazuh-manager-resolve-credentials",
    "/usr/share/wazuh-dashboard/bin/resolve-credentials",
)

# Where the manager's resolver reads the SAN lists of remoted.pem and apid.pem (root:root 0600). The
# indexer and the dashboard need none: they discover the default-route addresses themselves, and
# only the manager is reached from outside the instance by an address it cannot see, the public one.
WAZUH_MANAGER_LOCAL_ENV = f"{WAZUH_MANAGER_CONF_DIR}/local.env"

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


# Logs why a unit did not start. Each package's `resolve-credentials --prestart` (ExecStartPre)
# refuses the start with a MISSING, INVALID or UNSAFE line; without them, the last lines of the unit.
SERVICE_FAILURE_REASON_COMMAND = (
    "journalctl -u {name} -n 50 --no-pager -o cat | grep -E 'MISSING|INVALID|UNSAFE' "
    "|| journalctl -u {name} -n 50 --no-pager -o cat"
)


def start_service(name: str) -> None:
    """
    Starts a service using systemctl. If it does not start, logs the reason from its journal
    (SERVICE_FAILURE_REASON_COMMAND) before raising.

    Args:
        name (str): The name of the service to start.

    Returns:
        None
    """

    logger.debug(f"Starting {name} service...")

    try:
        run_command(command=f"systemctl start {name}", error_message=f"Error starting {name} service")
    except RuntimeError:
        reason, _, _ = exec_command_with_status(command=SERVICE_FAILURE_REASON_COMMAND.format(name=name))
        logger.error(f"{name} did not start:\n{reason.strip()}")
        raise

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
    Sends one request authenticated with a password from its owner's export/credentials.env.

    The password goes to curl through its standard input (`-K -`), never on its command line, where
    any local user could read it off the process list, and it is never logged.

    Args:
        url (str): The URL to request.
        user (str): The user to authenticate as.
        password_key (str): The CredentialKey holding that user's password.
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


def get_manager_sans() -> list[str]:
    """
    Collects the names and addresses agents may dial to reach this instance's manager, for remoted.pem's SAN.

    `hostname -I` (util-linux) already lists every configured address on every non-loopback
    interface, IPv4 and IPv6 alike (only IPv6 link-local is excluded) -- no separate handling
    needed for IPv6 there. It does NOT cover a public IPv4, though: AWS 1:1-NATs it, so it never
    appears on any local interface, only in the instance metadata service. Public IPv6 is not
    NAT'd -- AWS assigns it straight to the ENI, where `hostname -I` sees it. (The AL2023
    `ec2-metadata` has no IPv6 option at all: an earlier `--ipv6` lookup failed on every boot,
    hidden by the pipe.) A metadata lookup reports "not available" when the instance has none,
    which is filtered out rather than baked into the SAN as a literal string.

    The host name and the private and public DNS names EC2 gives the instance go in too: the AMI
    docs let users reach it by its public DNS name, and a token minted for a name the listener
    certificate does not hold is refused (ERROR 9025; wazuh-virtual-machines#1039, TC-03).

    Fed to write_manager_local_env(). A list there replaces the resolver's own discovery, so it
    carries the local addresses too; the resolver appends the loopback names. Every entry has its
    IP: or DNS: prefix, as the RC 2 packages require (wazuh/wazuh-automation#3944).

    Returns:
        list[str]: e.g. ["DNS:wazuh", "IP:172.31.5.10", "IP:203.0.113.9", "DNS:ip-172-31-5-10.ec2.internal"].
    """

    logger.debug("Collecting the instance's names and addresses for the manager certificate SAN")
    sans: list[str] = []

    hostname = run_command(command="hostname -s", error_message="Error reading the host name").strip()
    if hostname:
        sans.append(f"DNS:{hostname}")

    local_ips_output = run_command(
        command="hostname -I", error_message="Error listing local network interface addresses"
    )
    sans.extend(f"IP:{ip}" for ip in local_ips_output.split() if ip)

    for metadata_flag, prefix, error_message in (
        ("--public-ipv4", "IP", "Error retrieving the instance's public IPv4 address"),
        ("--local-hostname", "DNS", "Error retrieving the instance's private DNS name"),
        ("--public-hostname", "DNS", "Error retrieving the instance's public DNS name"),
    ):
        metadata_output = run_command(
            # -f2-: everything after the "public-ipv4:" style label.
            command=f"ec2-metadata {metadata_flag} | cut -d':' -f2-",
            error_message=error_message,
        )
        value = metadata_output.strip()
        if value and "not available" not in value:
            sans.append(f"{prefix}:{value}")

    sans = list(dict.fromkeys(sans))  # de-dupe (hostname -I and ec2-metadata can report the same IP), keep order

    logger.debug(f"Manager certificate SANs: {sans}")
    return sans


def write_manager_local_env() -> None:
    """
    Writes the instance's addresses as the SANs of the manager's remoted.pem and apid.pem.

    Without it the resolver only sees the default-route interfaces, and on AWS the public IPv4 is on
    none of them (1:1 NAT), so an agent enrolling through it would not match the listener
    certificate. apid.pem gets the same list: it does not inherit remoted's.

    Returns:
        None
    """

    sans = ",".join(get_manager_sans())
    logger.debug(f"Writing the manager certificate SANs to {WAZUH_MANAGER_LOCAL_ENV}")
    command = f"""
    install -m 0600 -o root -g root /dev/null {WAZUH_MANAGER_LOCAL_ENV}
    printf '%s\n' 'WAZUH_MANAGER_REMOTED_CERT_SANS={sans}' 'WAZUH_MANAGER_APID_CERT_SANS={sans}' > {WAZUH_MANAGER_LOCAL_ENV}
    """
    run_command(command=command, error_message=f"Error writing {WAZUH_MANAGER_LOCAL_ENV}")


def install_credentials() -> None:
    """
    Runs every package's `resolve-credentials --install`: each mints its own CA, issues its pairs
    with this instance's addresses and publishes its export/, then publishes the manager CA bundle.

    Safe to run again after a failed first boot: a resolver keeps a complete pair and a CA it finds.

    Returns:
        None
    """

    write_manager_local_env()
    for resolver in CREDENTIAL_RESOLVERS:
        logger.debug(f"Running {resolver} --install")
        run_command(command=f"{resolver} --install < /dev/null", error_message=f"Error running {resolver} --install")
    publish_manager_ca()


def publish_manager_ca() -> None:
    """
    Publishes the root-ca.pem the manager's resolver just wrote with `wazuh-manager-certs stamp`.

    remoted remembers the build-time bundle; replacing it without publishing makes remoted log
    "changed outside the tool and is not published" and announce ca_generation 0 to the agents
    (wazuh-virtual-machines#1022). stamp publishes the bundle as is. It only needs the files, not a
    running manager, and checks the bundle against remoted.pem, so it runs once both are installed.

    Returns:
        None
    """

    logger.debug("Publishing the manager CA bundle")
    run_command(command=f"{WAZUH_MANAGER_CERTS_BIN} stamp", error_message="Error publishing the manager CA bundle")


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
    generated on this boot (WAZUH_INDEXER_ADMIN_PASSWORD in /etc/wazuh-indexer/export/credentials.env).

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

    client.keys is left alone here: reset_agent_identity() empties it once the manager API is up.

    Returns:
        None
    """

    logger.debug("Removing the enrollment credentials and agent identity baked into the image")

    command = f"""
    rm -f {WAZUH_MANAGER_AUTHD_PASS_FILE} {WAZUH_MANAGER_ENROLLMENT_TOKENS_FILE}
    rm -f {WAZUH_AGENT_AUTHD_PASS_FILE} {WAZUH_AGENT_ENROLLMENT_TOKEN_FILE}
    rm -f {WAZUH_AGENT_CA_FILE} {WAZUH_AGENT_ANCHOR_COMMITTED_FILE} {WAZUH_AGENT_REENROLL_SECRET_FILE}
    """
    run_command(command=command, error_message="Error removing the baked enrollment state")

    logger.debug("Baked enrollment credentials and agent identity removed")


def reset_agent_identity() -> None:
    """
    Empties the agent's client.keys, first removing from the manager the agent it names, if any.

    The image ships client.keys empty, so an ID in it can only come from an earlier run of this
    customizer that started the agent and then failed (the service is only removed once it
    succeeds). The manager still has that agent registered under the same name and would reject the
    new enrollment as a duplicate. On a normal first boot this only truncates an empty file.

    Reading the ID, removing the agent and truncating the file happen in this one step, after the
    manager API is up, so a run that fails earlier (certificates, indexer, manager) leaves the ID on
    disk for the next one. The agent is never started before this point.

    client.keys is truncated rather than deleted so the file keeps the ownership and mode the agent
    package gave it; the bootstrap only looks at its size.

    Returns:
        None
    """

    try:
        agent_id = (Path(WAZUH_AGENT_CLIENT_KEYS_FILE).read_text().split() or [None])[0]
    except FileNotFoundError:
        return

    remove_previous_agent(agent_id)

    run_command(
        command=f": > {WAZUH_AGENT_CLIENT_KEYS_FILE}",
        error_message="Error emptying the agent's client.keys",
    )


def remove_previous_agent(agent_id: str | None) -> None:
    """
    Removes from the manager the agent an earlier, failed run of this customizer enrolled, so the
    agent can enroll again under the same name instead of being rejected as a duplicate. No-op on a
    normal first boot.

    Goes through the Server API because in 5.0.0 the manager ships no local CLI that removes agents
    (manage_agents is only installed with the agent). older_than=0s because the default (7d) skips
    an agent registered minutes ago; purge drops its key instead of keeping it as removed.

    Not fatal: if it fails, the agent's enrollment is rejected and the agent stays down, which is
    better than aborting the customization with SSH stopped. The warning says why.

    Args:
        agent_id (str | None): The ID read from the agent's client.keys by reset_agent_identity().

    Returns:
        None
    """

    if agent_id is None:
        return
    if not agent_id.isdigit():
        logger.warning(f"Ignoring an unexpected agent ID in client.keys: {agent_id}")
        return

    logger.info(f"Removing agent {agent_id}, enrolled by an earlier run of the customizer, from the manager")

    # Password and JWT reach curl through its standard input, never argv (see http_status()).
    password = read_credential(CredentialKey.MANAGER_WUI)
    jwt = subprocess.run(
        [
            "curl",
            "-s",
            "-k",
            "-K",
            "-",
            "-X",
            "POST",
            "--max-time",
            "120",
            "https://localhost:55000/security/user/authenticate?raw=true",
        ],
        input=f'user = "{WAZUH_MANAGER_API_USER}:{password}"\n',
        capture_output=True,
        text=True,
    ).stdout.strip()
    response = subprocess.run(
        [
            "curl",
            "-s",
            "-k",
            "-K",
            "-",
            "-X",
            "DELETE",
            "--max-time",
            "120",
            f"https://localhost:55000/agents?agents_list={agent_id}&status=all&older_than=0s&purge=true",
        ],
        input=f'header = "Authorization: Bearer {jwt}"\n',
        capture_output=True,
        text=True,
    ).stdout

    try:
        removed = json.loads(response)["data"]["total_affected_items"] == 1
    except (ValueError, KeyError, TypeError):
        removed = False

    if removed:
        logger.info(f"Agent {agent_id} removed")
    else:
        logger.warning(f"Could not remove agent {agent_id}; its enrollment will be rejected as a duplicate: {response}")


def mint_agent_enrollment_token() -> str:
    """
    Mints a fresh enrollment token on this instance and returns it.

    The token is minted, never baked: it is created here, on the running manager, with the CA and
    the listener certificate this instance generated for itself moments earlier in
    install_credentials(). Its 30-day TTL (the CLI default, wazuh#39068) is therefore irrelevant and
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
    # service starts (`resolve-credentials --prestart`, wazuh-virtual-machines#973), importing what
    # it needs from its peers' export/: the manager the indexer's CA, client pair and password, the
    # dashboard the indexer's and the manager's CAs and passwords. Certificates are already in place
    # (install_credentials()): the packages never issue them outside `--install`.
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
    # Only now, with the API up: removes the agent an earlier failed run enrolled, then empties
    # client.keys. Done here and not in the reset above so a run failing in between keeps the ID.
    reset_agent_identity()

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

    Each package's export/credentials.env is left in place: it is where the user reads the generated
    passwords from, and the peers import from it.

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
        install_credentials()
        start_components_services()
        start_ssh_service()

        if not args.debug:
            clean_up()

    except Exception as e:
        logger.error(f"An error occurred during the customization process: {e}")
        start_ssh_service()
        raise RuntimeError("An error occurred during the customization process") from e

    logger.info("Customization process finished")
