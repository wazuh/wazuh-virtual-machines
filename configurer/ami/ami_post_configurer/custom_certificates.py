import logging
from pathlib import Path

from configurer.core.models import CertsManager
from configurer.core.utils import ComponentCertsDirectory
from generic import exec_command
from utils import Logger

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


def stop_ssh_service():
    """
    Stops the SSH service on the system.
    """

    logger.debug("Stopping SSH service...")
    command = "systemctl stop sshd.service"
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error("Error stopping SSH service")
        raise RuntimeError(f"Error stopping SSH service: {error_output}")
    
    logger.debug("SSH service stopped")


def stop_components_services():
    """
    Stops all Wazuh components services.
    """
    
    logger.debug("Stopping Wazuh components services...")
    command = """
    systemctl stop wazuh-indexer wazuh-server wazuh-dashboard
    sleep 5
    """
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error stopping Wazuh components services: {error_output}")
        raise RuntimeError("Error stopping Wazuh components services")
    logger.debug("Wazuh components services stopped")
    

def remove_certificates():
    """
    Removes existing certificates from the components.
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


def create_certificates():
    """
    Creates new certificates using the CertsManager.
    """
        
    logger.debug("Creating new certificates...")
    certs_manager = CertsManager(raw_config_path=CERTS_TOOL_CONFIG_PATH, certs_tool_path=CERTS_TOOL_PATH)
    certs_manager.generate_certificates()
    logger.debug("New certificates created")
    
    
def start_services():
    """
    Starts the Wazuh components services.
    """
    
    logger.debug("Starting Wazuh components services...")
    command = """
    systemctl enable wazuh-indexer wazuh-server wazuh-dashboard
    systemctl start wazuh-indexer wazuh-server wazuh-dashboard
    eval /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    """
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error starting Wazuh components services: {error_output}")
        raise RuntimeError("Error starting Wazuh components services")

    logger.debug("Wazuh components services started")


def start_ssh_service():
    """
    Starts the SSH service on the system.
    """

    logger.debug("Starting SSH service...")
    command = "systemctl start sshd.service"
    _, error_output = exec_command(command=command)
    if error_output:
        logger.error(f"Error starting SSH service: {error_output}")
        raise RuntimeError("Error starting SSH service")

    logger.debug("SSH service started")


def clean_up():
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
        start_services()
        start_ssh_service()
        clean_up()
    except Exception as e:
        logger.error(f"An error occurred during the custom certificates configuration process: {e}")
        start_ssh_service()
        raise RuntimeError("An error occurred during the custom certificates configuration process") from e

    logger.info("Custom certificates configuration process finished")
