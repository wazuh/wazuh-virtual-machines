from pathlib import Path

import paramiko
import yaml

from generic import exec_command
from utils import Component, Logger

from .wazuh_config_mapping import WazuhDashboardConfigMapping, WazuhIndexerConfigMapping, WazuhServerConfigMapping

logger = Logger("ConfigManager")


class WazuhComponentConfigManager:
    def __init__(self, files_configuration_path: Path) -> None:
        with open(files_configuration_path) as f:
            self.config_mappings_file = yaml.safe_load(f)

    @property
    def indexer_mapping(self) -> WazuhIndexerConfigMapping | None:
        if self.config_mappings_file.get(Component.WAZUH_INDEXER, None):
            return WazuhIndexerConfigMapping(self.config_mappings_file[Component.WAZUH_INDEXER])

        return None

    @property
    def server_mapping(self) -> WazuhServerConfigMapping | None:
        if self.config_mappings_file.get(Component.WAZUH_SERVER, None):
            return WazuhServerConfigMapping(self.config_mappings_file[Component.WAZUH_SERVER])

        return None

    @property
    def dashboard_mapping(self) -> WazuhDashboardConfigMapping | None:
        if self.config_mappings_file.get(Component.WAZUH_DASHBOARD, None):
            return WazuhDashboardConfigMapping(self.config_mappings_file[Component.WAZUH_DASHBOARD])

        return None

    def replace_file_entries(self, component: Component, client: paramiko.SSHClient | None = None):
        if component == Component.WAZUH_INDEXER:
            replace_content = self.indexer_mapping.replace_content if self.indexer_mapping else None
        elif component == Component.WAZUH_SERVER:
            replace_content = self.server_mapping.replace_content if self.server_mapping else None
        elif component == Component.WAZUH_DASHBOARD:
            replace_content = self.dashboard_mapping.replace_content if self.dashboard_mapping else None
        else:
            raise ValueError(f"Invalid component: {component}")

        if replace_content:
            logger.debug(f"Replacing entries for {component.replace('_', ' ').capitalize()} configuration file")

            for file in replace_content:
                filepath = file["path"]
                keys = file["keys"]
                values = file["values"]

                for key, value in zip(keys, values):
                    logger.debug(f"Replacing key:{key} with value:{value} in {filepath}")
                    addon = ""
                    if '"' in value:
                        addon = f'| {key} style="double"'
                        value = value.replace('\\"', "")

                    command = f"sudo yq -i '{key} = \"{value}\" {addon}' {filepath}"
                    output, error_output = exec_command(command=command, client=client)
                    if error_output:
                        raise ValueError(
                            f"Error while replacing key:{key} with value:{value} in {filepath}: {error_output}"
                        )
        else:
            logger.debug(f"No entries to replace for {component.replace('_', ' ').capitalize()} configuration file")
