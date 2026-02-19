from pathlib import Path

import paramiko
import yaml

from generic import exec_command
from utils import Component, Logger

from .wazuh_config_mapping import (
    WazuhAgentConfigMapping,
    WazuhDashboardConfigMapping,
    WazuhIndexerConfigMapping,
    WazuhServerConfigMapping,
)

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

        # These placeholders are defined in static/configuration_mappings.yaml
        # They are necessary to obtain dynamic values according to the component, such as the node name.
        # If more placeholders are needed, add them here.
        self._indexer_placeholder = {"__indexer_node_name__": Component.WAZUH_INDEXER.lower()}
        self._manager_placeholder = {}
        self._dashboard_placeholder = {}
        self._agent_placeholder = {}

    @property
    def indexer_mapping(self) -> WazuhIndexerConfigMapping | None:
        if self.config_mappings_file.get(Component.WAZUH_INDEXER, None):
            return WazuhIndexerConfigMapping(self.config_mappings_file[Component.WAZUH_INDEXER])
        return None

    @property
    def manager_mapping(self) -> WazuhServerConfigMapping | None:
        if self.config_mappings_file.get(Component.WAZUH_MANAGER, None):
            return WazuhServerConfigMapping(self.config_mappings_file[Component.WAZUH_MANAGER])
        return None

    @property
    def dashboard_mapping(self) -> WazuhDashboardConfigMapping | None:
        if self.config_mappings_file.get(Component.WAZUH_DASHBOARD, None):
            return WazuhDashboardConfigMapping(self.config_mappings_file[Component.WAZUH_DASHBOARD])
        return None

    @property
    def agent_mapping(self) -> WazuhAgentConfigMapping | None:
        if self.config_mappings_file.get(Component.WAZUH_AGENT, None):
            return WazuhAgentConfigMapping(self.config_mappings_file[Component.WAZUH_AGENT])
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
        elif component == Component.WAZUH_MANAGER:
            replace_content = self.manager_mapping.replace_content if self.manager_mapping else None
        elif component == Component.WAZUH_DASHBOARD:
            replace_content = self.dashboard_mapping.replace_content if self.dashboard_mapping else None
        elif component == Component.WAZUH_AGENT:
            replace_content = self.agent_mapping.replace_content if self.agent_mapping else None
        else:
            raise ValueError(f"Invalid component: {component}")

        if replace_content:
            # Replace placeholders just before using the values
            self._replace_placeholders(replace_content, component)

            logger.debug(f"Replacing entries for {component.replace('_', ' ').capitalize()} configuration file")

            for file in replace_content:
                filepath = file["path"]
                keys = file["keys"]
                values = file["values"]
                yq_xml_suffix = ""

                if Path(filepath).suffix == ".conf":  # This file is XML, not YAML
                    yq_xml_suffix = "-p xml -o xml"

                for key, value in zip(keys, values, strict=False):
                    logger.debug(f"Replacing key:{key} with value:{value} in {filepath}")
                    addon = ""
                    if '"' in value:
                        addon = f'| {key} style="double"'
                        value = value.replace('\\"', "")

                    command = f"sudo yq -i {yq_xml_suffix} '{key} = \"{value}\" {addon}' {filepath}"
                    output, error_output = exec_command(command=command, client=client)
                    if error_output:
                        logger.error(f"Error while replacing key:{key} with value:{value} in {filepath}")
                        raise ValueError(
                            f"Error while replacing key:{key} with value:{value} in {filepath}: {error_output}"
                        )
        else:
            logger.debug(f"No entries to replace for {component.replace('_', ' ').capitalize()} configuration file")

    def _replace_placeholders(self, replace_content: list, component: Component) -> None:
        """
        Replace placeholders in configuration values with actual component values.

        Args:
            replace_content (list): List of file configurations with keys and values
            component (Component): The component to get values from
        """
        logger.debug(
            f"Replacing placeholders in configuration values for the {component.replace('_', ' ').capitalize()} component"
        )

        placeholders_map = (
            self._indexer_placeholder
            if component == Component.WAZUH_INDEXER
            else self._manager_placeholder
            if component == Component.WAZUH_MANAGER
            else self._dashboard_placeholder
        )

        if placeholders_map == {}:
            logger.debug("No placeholders to replace for this component")
            return

        for file_config in replace_content:
            values = file_config.get("values", [])
            for i, value in enumerate(values):
                if isinstance(value, str) and "__" in value:
                    original_value = value
                    for placeholder, replacement in placeholders_map.items():
                        if placeholder in value:
                            value = value.replace(placeholder, replacement)

                    if value != original_value:
                        values[i] = value
                        logger.debug(f"Replaced placeholders: '{original_value}' -> '{value}'")
