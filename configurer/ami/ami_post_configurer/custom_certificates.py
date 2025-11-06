import logging
import time
from pathlib import Path

from configurer.core.models import CertsManager
from configurer.core.utils import ComponentCertsDirectory
from generic import exec_command
from utils import Component, Logger

LOGFILE = Path("/var/log/wazuh-ami-custom-certificates.log")
TEMP_DIR = Path("/etc/wazuh-ami-certs-customize")
CERTS_TOOL_PATH = Path(f"{TEMP_DIR}/certs-tool.sh")
CERTS_TOOL_CONFIG_PATH = Path(f"{TEMP_DIR}/config.yml")
SERVICE_PATH = "/etc/systemd/system"
SERVICE_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.service"
SERVICE_TIMER_NAME = f"{SERVICE_PATH}/wazuh-ami-customizer.timer"

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


def verify_component_connection(component: Component, command: str, retries: int = 5, wait_time: int = 5) -> None:
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
            logger.debug(f"Attempt {attempt + 1} failed, retrying in {wait_time} seconds...")
            time.sleep(wait_time)


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
    rm -rf {ComponentCertsDirectory.WAZUH_SERVER}/*
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

    stop_service("wazuh-indexer")
    stop_service("wazuh-server")
    stop_service("wazuh-dashboard")

    logger.debug("Wazuh components services stopped")


def verify_indexer_connection() -> None:
    """
    Verifies the connection to the Wazuh indexer.
    This function sends a request to the Wazuh indexer endpoint and checks the response.
    It ensures that the Wazuh indexer is running and accessible after the custom certificates have been configured.

    Returns:
        None
    """

    command = 'curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent -w "%{http_code}" --output /dev/null'
    verify_component_connection(Component.WAZUH_INDEXER, command)


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

    enable_service("wazuh-server")
    start_service("wazuh-server")

    enable_service("wazuh-dashboard")
    start_service("wazuh-dashboard")
    verify_dashboard_connection()

    logger.debug("Wazuh components services started")


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
    """
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error cleaning up: {error_output}")
        raise RuntimeError("Error cleaning up")
    logger.debug("Clean up completed")


if __name__ == "__main__":
    logger.info("Starting custom certificates configuration process")

    try:
        stop_ssh_service()
        stop_components_services()
        remove_certificates()
        create_certificates()
        start_components_services()
        start_ssh_service()
        clean_up()
    except Exception as e:
        logger.error(f"An error occurred during the custom certificates configuration process: {e}")
        start_ssh_service()
        raise RuntimeError("An error occurred during the custom certificates configuration process") from e

    logger.info("Custom certificates configuration process finished")
