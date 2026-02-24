import argparse
import json
import logging
import time
from pathlib import Path

from configurer.core.models import CertsManager
from configurer.core.utils import ComponentCertsDirectory
from generic import exec_command
from utils import Component, Logger

LOGFILE = Path("/var/log/wazuh-ami-customizer.log")
TEMP_DIR = Path("/etc/wazuh-ami-customizer")
CERTS_TOOL_PATH = Path(f"{TEMP_DIR}/certs-tool.sh")
CERTS_TOOL_CONFIG_PATH = Path(f"{TEMP_DIR}/config.yml")
PASSWORD_TOOL_PATH = Path(f"{TEMP_DIR}/password-tool.sh")
SERVICE_PATH = "/etc/systemd/system"
SERVICE_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.service"
SERVICE_TIMER_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.timer"
WAZUH_WARNING_SCRIPT = Path("/etc/profile.d/wazuh-debug-warning.sh")

logger = Logger("CustomCertificates")
file_handler = logging.FileHandler(LOGFILE)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(file_handler)


def start_service(name: str) -> None:
    """
    Starts a service using systemctl.
    Args:
        name (str): The name of the service to start.

    Returns:
        None
    """

    logger.debug(f"Starting {name} service...")

    command = f"systemctl start {name}"
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error starting {name} service: {error_output}")
        raise RuntimeError(f"Error starting {name} service")

    logger.debug(f"{name} service started")


def stop_service(name: str) -> None:
    """
    Stops the specified service.
    Args:
        name (str): The name of the service to stop.

    Returns:
        None
    """

    logger.debug(f"Stopping {name} service...")

    command = f"systemctl stop {name}"
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error stopping {name} service: {error_output}")
        raise RuntimeError(f"Error stopping {name} service")

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

    command = f"systemctl --quiet enable {name}"
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error enabling {name} service: {error_output}")
        raise RuntimeError(f"Error enabling {name} service")

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

    command = "eval /usr/share/wazuh-indexer/bin/indexer-security-init.sh"
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error running indexer security initialization: {error_output}")
        raise RuntimeError("Error running indexer security initialization")

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
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error removing existing certificates: {error_output}")
        raise RuntimeError("Error removing existing certificates")

    logger.debug("Existing certificates removed")


def create_certificates() -> None:
    """
    Creates new certificates using the CertsManager.

    Returns:
        None
    """

    logger.debug("Creating new certificates...")
    certs_manager = CertsManager(raw_config_path=CERTS_TOOL_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)
    certs_manager.generate_certificates()
    logger.debug("New certificates created")


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


def verify_indexer_connection(password: str = "admin") -> None:
    """
    Verifies the connection to the Wazuh indexer.
    This function sends a request to the Wazuh indexer endpoint and checks the response.
    It ensures that the Wazuh indexer is running and accessible after the custom certificates have been configured.

    Returns:
        None
    """

    command = f'curl -XGET https://localhost:9200/ -uadmin:{password} -k --max-time 120 --silent -w "%{{http_code}}" --output /dev/null'
    verify_component_connection(Component.WAZUH_INDEXER, command)


def verify_server_connection(password: str = "wazuh-wui") -> None:
    """
    Verifies the connection to the Wazuh server API.
    This function sends a request to the Wazuh server API endpoint and checks the response.
    It ensures that the Wazuh server API is running and accessible after the custom certificates have been configured.

    Returns:
        None
    """

    command = f'curl -XPOST https://localhost:55000/security/user/authenticate -uwazuh-wui:{password} -k --max-time 120 -w "%{{http_code}}" -s -o /dev/null'
    verify_component_connection(Component.WAZUH_MANAGER, command)


def verify_dashboard_connection() -> None:
    """
    Verifies the connection to the Wazuh dashboard.
    This function sends a request to the Wazuh dashboard endpoint and checks the response.
    It ensures that the Wazuh dashboard is running and accessible after the custom certificates have been configured.

    Returns:
        None
    """

    command = 'curl -XGET https://localhost:443/status -uadmin:admin -k -w "%{http_code}" -s -o /dev/null'
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

    enable_service("wazuh-manager")
    start_service("wazuh-manager")
    verify_server_connection()

    enable_service("wazuh-dashboard")
    start_service("wazuh-dashboard")
    time.sleep(20)  # Wait for dashboard to initialize
    verify_dashboard_connection()

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

    command = "ec2-metadata | grep 'instance-id' | cut -d':' -f2"
    output, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error retrieving instance ID: {error_output}")
        raise RuntimeError("Error retrieving instance ID")
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
        output, error_output = exec_command(command=command)
        if error_output:
            logger.error(f"Error retrieving indexer users: {error_output}")
            raise RuntimeError("Error retrieving indexer users")

        users_data = json.loads(output)
        users = list(users_data.keys())
        logger.debug(f"Indexer users retrieved: {users}")

    elif component == "server":
        token_command = "curl -s -u wazuh:wazuh -k -X POST 'https://127.0.0.1:55000/security/user/authenticate?raw=true' --max-time 300 --retry 5 --retry-delay 5"
        token, token_error = exec_command(command=token_command)
        if token_error:
            logger.error(f"Error retrieving server token: {token_error}")
            raise RuntimeError("Error retrieving server token")

        command = f'curl -XGET -H "Authorization: Bearer {token}" -H "Content-Type: application/json" "https://127.0.0.1:55000/security/users" -ks -u wazuh:wazuh'
        output, error_output = exec_command(command=command)
        if error_output:
            logger.error(f"Error retrieving server users: {error_output}")
            raise RuntimeError("Error retrieving server users")

        users_data = json.loads(output)
        users = [user["username"] for user in users_data["data"]["affected_items"]]
        logger.debug(f"Server users retrieved: {users}")

    else:
        raise ValueError("Invalid component specified. Use 'indexer' or 'server'.")

    return users


def change_passwords() -> None:
    logger.name = "CustomPasswords"
    logger.debug("Changing passwords started")
    logger.debug("Getting instance ID")
    instance_id = get_instance_id()

    indexer_users = retrieve_users("indexer")
    server_users = retrieve_users("server")

    logger.debug("Changing passwords to instance ID")

    for user in indexer_users:
        logger.debug(f"Changing password for indexer user: {user}")
        command = f"""
        bash {PASSWORD_TOOL_PATH} -u {user} -p {instance_id}
        """
        _, error_output = exec_command(command=command)
        if error_output:
            logger.error(f"Error changing password for indexer user {user}: {error_output}")
            raise RuntimeError(f"Error changing password for indexer user {user}")

    for user in server_users:
        logger.debug(f"Changing password for server user: {user}")
        command = f"""
        bash {PASSWORD_TOOL_PATH} -A -au {user} -ap {user} -u {user} -p {instance_id}
        """
        _, error_output = exec_command(command=command)
        if error_output:
            logger.error(f"Error changing password for server user {user}: {error_output}")
            raise RuntimeError(f"Error changing password for server user {user}")

    logger.debug("Passwords changed. Verifying indexer connection with new password")
    verify_indexer_connection(password=instance_id)
    logger.debug("Verifying server API connection with new password")
    verify_server_connection(password=instance_id)
    logger.debug("Changing passwords finished successfully")


def dashboard_wazuh_api_check() -> None:
    """
    Checks if the Wazuh dashboard has started successfully by looking for a specific log entry.

    Returns:
        None
    """

    logger.debug("Checking Wazuh dashboard startup...")

    command = "systemctl status wazuh-dashboard"
    retries = 5
    wait_time = 10

    for attempt in range(retries):
        output, _ = exec_command(command=command)
        # Check if error logs exist
        if 'error","healthcheck","server-api:connection-compatibility' in output:
            logger.debug("Found server API connection error in dashboard logs. Restarting wazuh-dashboard...")
            stop_service("wazuh-dashboard")
            time.sleep(10)
            start_service("wazuh-dashboard")
            logger.debug("Waiting 10 seconds after restart...")
            time.sleep(10)

            # Verify successful startup with compatibility message
            verify_retries = 5
            verify_wait = 10
            for verify_attempt in range(verify_retries):
                verify_output, _ = exec_command(command=command)
                if (
                    'info","healthcheck","server-api:connection-compatibility' in verify_output
                    and "is compatible with the dashboard version" in verify_output
                ):
                    logger.debug("Wazuh dashboard started successfully with server API compatibility confirmed")
                    return

                if verify_attempt < verify_retries - 1:
                    logger.debug(f"Compatibility message not found, retrying in {verify_wait} seconds...")
                    time.sleep(verify_wait)

            logger.error("Wazuh dashboard restart did not result in successful server API connection")
            raise RuntimeError("Wazuh dashboard failed to connect to server API after restart")

        # Check if success log already exists
        if (
            'info","healthcheck","server-api:connection-compatibility' in output
            and "is compatible with the dashboard version" in output
        ):
            logger.debug("Wazuh dashboard has started successfully")
            return

        if attempt < retries - 1:
            wait = wait_time * (attempt + 1)
            logger.debug(f"Dashboard not ready, retrying in {wait} seconds...")
            time.sleep(wait)
        else:
            logger.error("Wazuh dashboard startup check failed after all retries")
            raise RuntimeError("Wazuh dashboard startup check failed")


def clean_up() -> None:
    """
    Cleans up temporary files and directories created during the process.

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
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error cleaning up: {error_output}")
        raise RuntimeError("Error cleaning up")
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
        dashboard_wazuh_api_check()
        start_ssh_service()

        if not args.debug:
            clean_up()

    except Exception as e:
        logger.error(f"An error occurred during the customization process: {e}")
        start_ssh_service()
        raise RuntimeError("An error occurred during the customization process") from e

    logger.info("Customization process finished")
