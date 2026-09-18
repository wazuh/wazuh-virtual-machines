import argparse
import json
import logging
import time
from pathlib import Path

from configurer.core.models import CertsManager
from configurer.core.utils import ComponentCertsDirectory
from generic import exec_command, exec_command_with_status
from utils import Component, Logger

LOGFILE = Path("/var/log/wazuh-ami-customizer.log")
TEMP_DIR = Path("/etc/wazuh-ami-customizer")
CERTS_TOOL_PATH = Path(f"{TEMP_DIR}/certs-tool.sh")
CERTS_TOOL_CONFIG_PATH = Path(f"{TEMP_DIR}/config.yml")
PASSWORDS_TOOL_PATH = Path(f"{TEMP_DIR}/passwords-tool.sh")
SERVICE_PATH = "/etc/systemd/system"
SERVICE_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.service"
SERVICE_TIMER_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.timer"
WAZUH_WARNING_SCRIPT = Path("/etc/profile.d/wazuh-debug-warning.sh")

# The Wazuh manager generates a random Authd registration password on startup and persists it in
# this file. The same password must be distributed to the agent so it can enroll against the manager.
WAZUH_MANAGER_AUTHD_PASS_FILE = "/var/wazuh-manager/etc/authd.pass"
WAZUH_AGENT_AUTHD_PASS_FILE = "/var/ossec/etc/authd.pass"
AUTHD_PASS_MAX_RETRIES = 12
AUTHD_PASS_WAIT_TIME = 5

# Path the agent's <certificate_authorities> config points at, so it trusts this instance's own
# manager now that verification_mode is enforced by default.
WAZUH_AGENT_CA_FILE = "/var/ossec/etc/certs/root-ca.pem"

# Where this instance's own root CA (key included) lives on, past first boot, so a leaf can be
# reissued later (e.g. the instance's address changes, or a load balancer joins) without having to
# start over with a brand new CA every enrolled agent would have to re-trust. See clean_up() for why
# this is kept, not deleted -- issue #957 only requires that root-ca.key never ship baked into the
# image, not that a launched instance destroy its own copy.
WAZUH_CA_DIR = Path("/etc/wazuh-certificate-authority")
WAZUH_CERTS_TAR = TEMP_DIR / "wazuh-certificates.tar"

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


def verify_component_connection(component: Component, command: str, retries: int = 5, wait_time: int = 10) -> None:
    """
    Verifies the component connection by sending a request to the component's endpoint.
    Args:
        component (Component): The component to verify.
        retries (int): Number of retries if the connection fails.
        wait_time (int): Time to wait between retries.

    Returns:
        None
    """

    logger.debug(f"Verifying {component.replace('_', ' ')} connection...")

    for attempt in range(retries):
        output, _ = exec_command(command=command)
        if output == "200":
            logger.debug(f"{component.replace('_', ' ')} connection verified successfully")
            return

        if attempt < retries - 1:
            wait = wait_time * (attempt + 1)  # Incremental wait time
            logger.debug(f"Attempt {attempt + 1} failed, retrying in {wait} seconds...")
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
    command = f"""
    rm -rf {ComponentCertsDirectory.WAZUH_MANAGER}/*
    rm -rf {ComponentCertsDirectory.WAZUH_INDEXER}/*
    rm -rf {ComponentCertsDirectory.WAZUH_DASHBOARD}/*
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
    certs_manager.generate_certificates(agent_san=get_manager_san_ips())
    logger.debug("New certificates created")


def set_agent_ssl_ca() -> None:
    """
    Provisions the local agent's trusted CA for the manager's HTTPS transport.

    Copies the manager's root CA to the path the agent's <certificate_authorities>
    configuration points at, so the pre-installed agent can verify the manager's TLS
    certificate on enrollment/connection. remoted.pem is now issued from this same CA by
    create_certificates, so pinning it is enough — no separate per-instance remoted
    generation step is needed.

    Returns:
        None
    """

    logger.debug("Setting the Wazuh agent trusted CA from the manager root CA")
    root_ca = f"{ComponentCertsDirectory.WAZUH_MANAGER}/root-ca.pem"
    command = f"""
    mkdir -p {Path(WAZUH_AGENT_CA_FILE).parent}
    cp {root_ca} {WAZUH_AGENT_CA_FILE}
    chown root:wazuh {WAZUH_AGENT_CA_FILE}
    chmod 640 {WAZUH_AGENT_CA_FILE}
    """
    run_command(command=command, error_message="Error setting the Wazuh agent trusted CA")

    logger.debug("Wazuh agent trusted CA set successfully")


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


def verify_indexer_connection(password: str = "wazuh-admin") -> None:
    """
    Verifies the connection to the Wazuh indexer.
    This function sends a request to the Wazuh indexer endpoint and checks the response.
    It ensures that the Wazuh indexer is running and accessible after the custom certificates have been configured.

    Returns:
        None
    """

    command = f'curl -XGET https://localhost:9200/ -uwazuh-admin:{password} -k --max-time 120 --silent -w "%{{http_code}}" --output /dev/null'
    verify_component_connection(Component.WAZUH_INDEXER, command)


def verify_manager_connection(password: str = "wazuh-wui") -> None:
    """
    Verifies the connection to the Wazuh manager API.
    This function sends a request to the Wazuh manager API endpoint and checks the response.
    It ensures that the Wazuh manager API is running and accessible after the custom certificates have been configured.

    Returns:
        None
    """

    command = f'curl -XPOST https://localhost:55000/security/user/authenticate -uwazuh-wui:{password} -k --max-time 120 -w "%{{http_code}}" -s -o /dev/null'
    verify_component_connection(Component.WAZUH_MANAGER, command)


def verify_dashboard_connection(password: str = "wazuh-admin") -> None:
    """
    Verifies the connection to the Wazuh dashboard.
    This function sends a request to the Wazuh dashboard endpoint and checks the response.
    It ensures that the Wazuh dashboard is running and accessible after the custom certificates have been configured.

    Returns:
        None
    """

    command = f'curl -XGET https://localhost:443/status -uwazuh-admin:{password} -k -w "%{{http_code}}" -s -o /dev/null'
    verify_component_connection(Component.WAZUH_DASHBOARD, command)


def start_ssh_service() -> None:
    """
    Starts the SSH service on the system.

    This function is used to start the SSH service after the custom certificates have been configured.
    It ensures that the SSH service is running and ready to accept connections.

    Returns:
        None
    """

    start_service("sshd.service")


def rotate_authd_password() -> None:
    """
    Removes the Authd registration password baked into the image.

    The Wazuh manager generates and persists a random Authd password when it first starts, so the
    built image ships with a fixed password. Removing it forces the manager to generate a new, unique
    password on the first boot of the deployed instance, preventing every deployed AMI from sharing
    the same registration password.

    Returns:
        None
    """

    logger.debug("Removing pre-generated Authd registration password to force a new one on first boot")

    run_command(
        command=f"rm -f {WAZUH_MANAGER_AUTHD_PASS_FILE} {WAZUH_AGENT_AUTHD_PASS_FILE}",
        error_message="Error removing Authd registration password",
    )


def set_authd_password() -> None:
    """
    Configures the Wazuh agent registration password.

    Reads the Authd password generated by the Wazuh manager on startup and writes it, with the proper
    ownership and permissions, to the Wazuh agent Authd password file so the agent can enroll against
    the manager.

    Returns:
        None
    """

    logger.debug("Setting the Wazuh agent registration password from the manager Authd password")

    for attempt in range(AUTHD_PASS_MAX_RETRIES):
        output, _ = exec_command(command=f"test -f {WAZUH_MANAGER_AUTHD_PASS_FILE} && echo found")
        if "found" in output:
            break
        logger.debug(
            f"Manager Authd password file not ready yet, retrying in {AUTHD_PASS_WAIT_TIME} seconds "
            f"(attempt {attempt + 1}/{AUTHD_PASS_MAX_RETRIES})"
        )
        time.sleep(AUTHD_PASS_WAIT_TIME)
    else:
        logger.error("Wazuh manager Authd password file not found")
        raise RuntimeError(f"Wazuh manager Authd password file not found at {WAZUH_MANAGER_AUTHD_PASS_FILE}")

    command = f"""
    cp {WAZUH_MANAGER_AUTHD_PASS_FILE} {WAZUH_AGENT_AUTHD_PASS_FILE}
    chown root:wazuh {WAZUH_AGENT_AUTHD_PASS_FILE}
    chmod 640 {WAZUH_AGENT_AUTHD_PASS_FILE}
    """
    run_command(command=command, error_message="Error setting the Wazuh agent registration password")

    logger.debug("Wazuh agent registration password set successfully")


def start_components_services() -> None:
    """
    Starts all Wazuh components services.
    This function is used to start the Wazuh components services after the custom certificates have been configured.
    It ensures that all components are running and ready to accept connections.

    Returns:
        None
    """

    logger.debug("Starting Wazuh components services...")

    enable_service("wazuh-indexer")
    start_service("wazuh-indexer")
    run_indexer_security_init()
    verify_indexer_connection()

    # Rotate the Authd registration password before the manager starts so it generates a new, unique
    # one instead of reusing the password baked into the image.
    rotate_authd_password()

    enable_service("wazuh-manager")
    start_service("wazuh-manager")
    verify_manager_connection()

    enable_service("wazuh-dashboard")
    start_service("wazuh-dashboard")
    time.sleep(20)  # Wait for dashboard to initialize
    verify_dashboard_connection()

    # Distribute the newly generated password to the agent before it starts so it can enroll.
    set_authd_password()
    # Provision the agent's trusted CA before it starts so it can verify the manager's TLS cert.
    set_agent_ssl_ca()

    enable_service("wazuh-agent")
    start_service("wazuh-agent")

    logger.debug("Wazuh components services started")


def get_instance_id() -> str:
    """
    Retrieves the instance ID of the current machine capitalized.

    Returns:
        str: The instance ID of the current machine.
    """

    logger.debug("Retrieving instance ID")

    output = run_command(
        command="ec2-metadata | grep 'instance-id' | cut -d':' -f2",
        error_message="Error retrieving instance ID",
    )

    return output.strip().capitalize()


def retrieve_users(component: str) -> list:
    """
    Retrieves a list with all Wazuh users of the selected component.

    Returns:
        List of users.
    """

    logger.debug(f"Retrieving users from Wazuh {component}")

    if component == "indexer":
        command = "curl -XGET 'https://127.0.0.1:9200/_plugins/_security/api/internalusers/' -ks -u admin:admin"
        output = run_command(command=command, error_message="Error retrieving indexer users")

        users_data = json.loads(output)
        users = list(users_data.keys())
        logger.debug(f"Indexer users retrieved: {users}")

    elif component == "manager":
        token_command = "curl -s -u wazuh:wazuh -k -X POST 'https://127.0.0.1:55000/security/user/authenticate?raw=true' --max-time 300 --retry 5 --retry-delay 5"
        token = run_command(command=token_command, error_message="Error retrieving manager token")

        command = f'curl -XGET -H "Authorization: Bearer {token}" -H "Content-Type: application/json" "https://127.0.0.1:55000/security/users" -ks -u wazuh:wazuh'
        output = run_command(command=command, error_message="Error retrieving manager users")

        users_data = json.loads(output)
        users = [user["username"] for user in users_data["data"]["affected_items"]]
        logger.debug(f"Manager users retrieved: {users}")

    else:
        raise ValueError("Invalid component specified. Use 'indexer' or 'manager'.")

    return users


def change_passwords() -> None:
    logger.name = "CustomPasswords"
    logger.debug("Changing passwords started")
    logger.debug("Getting instance ID")
    instance_id = get_instance_id()

    indexer_users = retrieve_users("indexer")
    manager_users = retrieve_users("manager")

    logger.debug("Changing passwords to instance ID")

    for user in indexer_users:
        logger.debug(f"Changing password for indexer user: {user}")
        command = f"""
        bash {PASSWORDS_TOOL_PATH} -u {user} -p {instance_id}
        """
        run_command(command=command, error_message=f"Error changing password for indexer user {user}")

    for user in manager_users:
        logger.debug(f"Changing password for manager user: {user}")
        command = f"""
        bash {PASSWORDS_TOOL_PATH} -A -au {user} -ap {user} -u {user} -p {instance_id}
        """
        run_command(command=command, error_message=f"Error changing password for manager user {user}")

    logger.debug("Passwords changed. Verifying indexer connection with new password")
    verify_indexer_connection(password=instance_id)
    logger.debug("Verifying manager API connection with new password")
    verify_manager_connection(password=instance_id)
    logger.debug("Changing passwords finished successfully")


def clean_up() -> None:
    """
    Cleans up temporary files and directories created during the process.

    TEMP_DIR holds the cert-tool's own working directory, including WAZUH_CERTS_TAR -- a tar of its
    whole output, unfiltered, so it also carries the root CA's private key with none of the 500/400
    restrictive permissions applied to what gets extracted into each component's own directory. Left
    as the tool wrote it, that's exactly the persisted, loosely-permissioned key material issue #957
    set out to remove.

    The fix is to secure root-ca.pem/root-ca.key in WAZUH_CA_DIR, NOT to destroy them: the issue only
    requires that root-ca.key never ship baked into the image (a single CA shared by every instance
    launched from it), not that a launched instance erase its own copy. Its own acceptance criteria
    assume the opposite -- "reissuing the leaf is enough and does not break enrolled agents, since
    they pin the CA rather than the leaf" only holds if that CA still exists to sign a new leaf with,
    e.g. after the instance's address changes or a load balancer joins later. An earlier revision of
    this function deleted them outright instead, which satisfied the letter of "not baked into the
    image" but broke that reissuing guarantee for every launched instance -- caught only by tracing
    the issue's exact wording, not by anything that runs. wazuh-installation-assistant, which this
    whole first-boot design otherwise mirrors, never destroys its equivalent either: it chmod 400s
    the generated root-ca.pem/key and bundles them into wazuh-install-files.tar for the operator to
    keep (install_functions/installCommon.sh).

    Returns:
        None
    """

    logger.debug("Cleaning up temporary files and directories...")

    WAZUH_CA_DIR.mkdir(parents=True, exist_ok=True)
    run_command(
        command=f"tar -xf {WAZUH_CERTS_TAR} -C {WAZUH_CA_DIR} ./root-ca.pem ./root-ca.key",
        error_message=f"Error extracting the CA into {WAZUH_CA_DIR}",
    )
    run_command(
        command=f"chown -R root:root {WAZUH_CA_DIR} && chmod 700 {WAZUH_CA_DIR} "
        f"&& chmod 400 {WAZUH_CA_DIR}/root-ca.pem {WAZUH_CA_DIR}/root-ca.key",
        error_message=f"Error securing {WAZUH_CA_DIR}",
    )

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
        stop_service("wazuh-dashboard")
        change_passwords()
        start_service("wazuh-dashboard")
        time.sleep(10)  # Wait for dashboard to initialize
        verify_dashboard_connection(get_instance_id())
        start_ssh_service()

        if not args.debug:
            clean_up()

    except Exception as e:
        logger.error(f"An error occurred during the customization process: {e}")
        start_ssh_service()
        raise RuntimeError("An error occurred during the customization process") from e

    logger.info("Customization process finished")
