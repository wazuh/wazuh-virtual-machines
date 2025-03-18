from pathlib import Path

import paramiko
import yaml

from generic import exec_command
from utils import Component, Logger

from .wazuh_config_mapping import WazuhDashboardConfigMapping, WazuhIndexerConfigMapping, WazuhServerConfigMapping

logger = Logger("ConfigManager")


class WazuhComponentConfigManager:
    """
    Manages the configuration mappings for Wazuh components. Given a YAML file containing the configuration mappings for
    the Wazuh components, this class provides methods to replace entries in the configuration files for the specified
    Wazuh component. This is done by using the `yq` command to replace the entries in the configuration files.

    Attributes:
        config_mappings_file (dict): The configuration mappings loaded from the specified YAML file.

    Args:
        files_configuration_path (Path): The path to the YAML file containing the configuration mappings.
    """

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
        """
        Replaces entries in the configuration files for the specified Wazuh component.

        This method updates the configuration files for the given Wazuh component by replacing
        specified keys with their corresponding values. The replacement is performed using the
        `yq` command-line tool.

        Args:
            component (Component): The Wazuh component for which the configuration files need to be updated.
            client (paramiko.SSHClient | None, optional): An SSH client to execute the commands remotely. If None,
                the commands will be executed locally. Defaults to None.

        Raises:
            ValueError: If an invalid component is provided or if there is an error while replacing the keys in the files.
        """

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
