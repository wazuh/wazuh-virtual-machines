from dataclasses import dataclass
from pathlib import Path

import paramiko

from configurer.core.models import CertsManager, WazuhComponentConfigManager
from generic import remote_connection
from models import Inventory
from utils import CertificatesComponent, Component, Logger, RemoteDirectories

logger = Logger("CoreConfigurer")

@dataclass
class CoreConfigurer:
    inventory: Inventory
    files_configuration_path: Path
    
    @remote_connection
    def configure(self, client: paramiko.SSHClient | None = None):
        logger.debug_title("Starting core configuration process")
        
        logger.debug_title("Configuring components")
        config_mappings = WazuhComponentConfigManager(files_configuration_path=self.files_configuration_path)
        config_mappings.replace_file_entries(Component.WAZUH_INDEXER, client=client)
        config_mappings.replace_file_entries(Component.WAZUH_SERVER, client=client)
        config_mappings.replace_file_entries(Component.WAZUH_DASHBOARD, client=client)
        logger.info_success("Core configuration process finished")
        
        logger.debug_title("Starting certificates creation and configuration process")
        certs_manager = CertsManager(
            raw_config_path=Path(RemoteDirectories.CERTS) / CertificatesComponent.CONFIG,
            certs_tool_path=Path(RemoteDirectories.CERTS) / CertificatesComponent.CERTS_TOOL,
            client=client
        )
        
        certs_manager.generate_certificates(client=client)
