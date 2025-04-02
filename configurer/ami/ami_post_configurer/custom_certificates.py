import logging
import os
from pathlib import Path

from configurer.core.models import CertsManager
from configurer.core.utils import ComponentCertsDirectory
from generic import exec_command
from utils import Logger

logger = Logger("CustomCertificates")
log_filename = "/var/log/wazuh-ami-custom-certificates.log"
file_handler = logging.FileHandler(log_filename)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(file_handler)

CERTS_TOOL_PATH = Path("/etc/wazuh-ami-certs-customize/certs-tool.sh")
CERTS_TOOL_CONFIG_PATH = Path("/etc/wazuh-ami-certs-customize/config.yml")


def stop_ssh_service():
    """
    Stops the SSH service on the system.
    """

    logger.debug("Stopping SSH service...")
    command = "systemctl stop sshd.service"
    output, error_output = exec_command(command=command)
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
    output, error_output = exec_command(command=command)
    if error_output:
        logger.error("Error stopping Wazuh components services")
        raise RuntimeError(f"Error stopping Wazuh components services: {error_output}")
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
    output, error_output = exec_command(command=command)
    if error_output:
        logger.error("Error removing existing certificates")
        raise RuntimeError(f"Error removing existing certificates: {error_output}")

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
    systemctl start wazuh-indexer wazuh-server wazuh-dashboard
    eval /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    """
    output, error_output = exec_command(command=command)
    if error_output:
        logger.error("Error starting Wazuh components services")
        raise RuntimeError(f"Error starting Wazuh components services: {error_output}")

    logger.debug("Wazuh components services started")
    

if __name__ == "__main__":
    logger.info("Starting custom certificates configuration process")
    print("hola")
    
    stop_ssh_service()
    stop_components_services()
    remove_certificates()
    create_certificates()
    start_services()

    logger.info("Custom certificates configuration process finished")
