from dataclasses import dataclass
from pathlib import Path

import paramiko

from configurer.core.models import CertsManager, WazuhComponentConfigManager
from generic import exec_command, remote_connection
from models import Inventory
from utils import CertificatesComponent, Component, Logger, RemoteDirectories

logger = Logger("CoreConfigurer")


@dataclass
class CoreConfigurer:
    inventory: Inventory | None
    files_configuration_path: Path

    @remote_connection
    def configure(self, client: paramiko.SSHClient | None = None):
        """
        Configures the core components and manages certificates.

        This method performs the following steps:
        1. Configures the Wazuh components (Indexer, Server, Dashboard) by replacing file entries
        using the WazuhComponentConfigManager.
        2. Generates certificates using the CertsManager and copy them to the current component certs directory.
        3. Starts the Wazuh services.

        Args:
            client (paramiko.SSHClient | None): An optional SSH client to use for remote operations. Defaults to None.
        """

        logger.debug_title("Starting core configuration process")

        logger.debug_title("Configuring components")
        config_mappings = WazuhComponentConfigManager(files_configuration_path=self.files_configuration_path)
        config_mappings.replace_file_entries(Component.WAZUH_INDEXER, client=client)
        config_mappings.replace_file_entries(Component.WAZUH_MANAGER, client=client)
        config_mappings.replace_file_entries(Component.WAZUH_DASHBOARD, client=client)
        logger.info_success("Core configuration process finished")

        logger.debug_title("Starting certificates creation and configuration process")
        certs_manager = CertsManager(
            raw_config_path=Path(RemoteDirectories.CERTS) / CertificatesComponent.CONFIG,
            certs_tool_path=Path(RemoteDirectories.CERTS) / CertificatesComponent.CERTS_TOOL,
            client=client,
        )
        certs_manager.generate_certificates(client=client)

        logger.debug_title("Starting services")
        self.start_services(client=client)

    def start_services(self, client: paramiko.SSHClient | None = None):
        command = "sudo systemctl daemon-reload"
        output, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error reloading daemon")
            raise RuntimeError(f"Error reloading daemon {error_output}")

        for component in Component:
            if component != Component.ALL:
                logger.debug(f"Starting {component.replace('_', ' ')} service...")
                command = f"""
                    sudo systemctl --quiet enable {component.replace("_", "-").lower()}
                    sudo systemctl start {component.replace("_", "-").lower()}
                    """

                if component == Component.WAZUH_INDEXER:
                    command += "sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh"

                output, error_output = exec_command(command=command, client=client)
                if error_output:
                    logger.error(f"Error starting {component} service")
                    raise RuntimeError(f"Error starting {component} service: {error_output}")

                logger.debug(f"{component.replace('_', ' ')} service started")

        logger.info_success("All services started")
