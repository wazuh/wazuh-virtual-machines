import ast
from pathlib import Path

import paramiko

from configurer.core.utils import ComponentCertsConfigParameter, ComponentCertsDirectory, ComponentConfigFile
from generic import exec_command
from utils import Component, Logger

logger = Logger("CertsManager")


class CertsManager:
    """
    A class to manage the generation and configuration of certificates for Wazuh components.

    Attributes:
        components_certs_default_name (dict): Default names for each certificate of each component when generated with the cert-tool.
        components_certs_config_keys (dict): Dictionary that helps determine the name of each certificate assigned to each component in its configuration file.
        certs_tool_path (Path): Path to the certificate generation tool.
    """

    def __init__(self, raw_config_path: Path, certs_tool_path: Path, client: paramiko.SSHClient | None = None) -> None:
        # Default name for each certificate of each component when generated with the cert-tool.
        self.components_certs_default_name = {
            Component.WAZUH_INDEXER: {
                "cert": f"{Component.WAZUH_INDEXER}.pem",
                "key": f"{Component.WAZUH_INDEXER}-key.pem",
                "admin-cert": "admin.pem",
                "admin-key": "admin-key.pem",
                "ca": "root-ca.pem",
            },
            Component.WAZUH_SERVER: {
                "cert": f"{Component.WAZUH_SERVER}.pem",
                "key": f"{Component.WAZUH_SERVER}-key.pem",
                "admin-cert": "admin.pem",
                "admin-key": "admin-key.pem",
                "ca": "root-ca.pem",
            },
            Component.WAZUH_DASHBOARD: {
                "cert": f"{Component.WAZUH_DASHBOARD}.pem",
                "key": f"{Component.WAZUH_DASHBOARD}-key.pem",
                "ca": "root-ca.pem",
            },
        }

        # Dictionary that helps determine the name of each certificate assigned to each component
        # in its configuration file. These variables represent the keys in each file, whose values
        # are the specific certificate paths.
        self.components_certs_config_keys = {
            Component.WAZUH_SERVER: [
                ComponentCertsConfigParameter.WAZUH_SERVER_KEY,
                ComponentCertsConfigParameter.WAZUH_SERVER_CERT,
                ComponentCertsConfigParameter.WAZUH_SERVER_CA,
            ],
            Component.WAZUH_INDEXER: [
                ComponentCertsConfigParameter.WAZUH_INDEXER_KEY,
                ComponentCertsConfigParameter.WAZUH_INDEXER_CERT,
                ComponentCertsConfigParameter.WAZUH_INDEXER_CA,
            ],
            Component.WAZUH_DASHBOARD: [
                ComponentCertsConfigParameter.WAZUH_DASHBOARD_KEY,
                ComponentCertsConfigParameter.WAZUH_DASHBOARD_CERT,
                ComponentCertsConfigParameter.WAZUH_DASHBOARD_CA,
            ],
        }
        self.certs_tool_path = certs_tool_path

        self._set_config_file_values(raw_config_path=raw_config_path, client=client)

    def _set_config_file_values(self, raw_config_path: Path, client: paramiko.SSHClient | None = None):
        """
        Sets configuration file values using the `yq` command.

        This method updates the configuration file at the specified path with predefined values for
        Wazuh components (indexer, server, and dashboard) using the `yq` command-line tool. The IP
        addresses for these components are set to "127.0.0.1".

        Args:
            raw_config_path (Path): The path to the raw configuration file to be updated.
            client (paramiko.SSHClient, optional): An SSH client for remote execution. Defaults to None.

        Raises:
            Exception: If there is an error while setting the configuration file values.
        """

        logger.debug("Setting config file values")
        yq_query = f"""
            sudo yq -i '.nodes.indexer[0].name = \"{Component.WAZUH_INDEXER}\" |
            .nodes.indexer[0].ip = "127.0.0.1" | .nodes.indexer[0].ip style="double" |
            .nodes.server[0].name = \"{Component.WAZUH_SERVER}\" |
            .nodes.server[0].ip = "127.0.0.1" | .nodes.server[0].ip style="double" |
            .nodes.dashboard[0].name = \"{Component.WAZUH_DASHBOARD}\" |
            .nodes.dashboard[0].ip = "127.0.0.1" | .nodes.dashboard[0].ip style="double"
            ' {raw_config_path}
            """
        output, error_output = exec_command(command=yq_query, client=client)

        if error_output:
            logger.error("Error while setting config file values")
            raise Exception(f"Error while setting config file values: {error_output}")

    def _get_cert_name_from_key(
        self, key: str, file: str, flattened_key: bool = True, client: paramiko.SSHClient | None = None
    ) -> str:
        """
        Retrieve the certificate name from a given key in a YAML file.

        Args:
            key (str): The key to search for in the YAML file.
            file (str): The path to the YAML file.
            flattened_key (bool, optional): Whether the key uses dot notation (e.g., "a.b.c") instead of
                hierarchical/nested YAML structure (e.g., a: b: c:). Default is True.
            client (paramiko.SSHClient, optional): An SSH client to execute the command remotely (default is None).

        Returns:
            str: The name of the certificate.

        >>> Example for server:
        >>> _get_cert_name_from_key("server.cert", "/etc/wazuh-server/wazuh-server.yml", True, client)
        >>> return: "wazuh-server.pem"
        """

        yq_xml_suffix = ""
        if Path(file).suffix == ".conf":  # This file is XML, not YAML
            yq_xml_suffix = "-p xml -o xml"

        yq_query = (
            f"sudo yq {yq_xml_suffix} '.[\"{key}\"]' {file}"
            if flattened_key
            else f"sudo yq {yq_xml_suffix} '.{key}' {file}"
        )

        output, error_output = exec_command(command=yq_query, client=client)
        if error_output:
            logger.error("Error while executing yq query")
            raise Exception(f"Error while executing yq query: {error_output}")

        if "[" in output and "]" in output:
            output = ast.literal_eval(output)[-1]  # If the result is inside a list [] return the last value

        return Path(output.strip()).name

    def _get_certs_name(
        self,
        component: Component,
        component_config_file: str,
        flattened_key: bool = True,
        client: paramiko.SSHClient | None = None,
    ) -> dict:
        """
        Retrieve the names of certificates for a given component.

        Args:
            component (Component): The component for which to retrieve certificate names.
            component_config_file (str): The path to the component's configuration file.
            flattened_key (bool, optional): Whether the key uses dot notation (e.g., "a.b.c") instead of
                hierarchical/nested YAML structure (e.g., a: b: c:). Default is True.
            client (paramiko.SSHClient | None, optional): An SSH client for remote operations. Defaults to None.

        Returns:
            dict: A dictionary mapping certificate keys to their respective names.

        >>> Example for server:
        >>> _get_certs_name(Component.WAZUH_SERVER, "/etc/wazuh-server/wazuh-server.yml", True, client)
        >>> return {
            "WAUZUH_SERVER_CERT": "wazuh-server.pem",
            "WAUZUH_SERVER_KEY": "wazuh-server-key.pem",
            "WAUZUH_SERVER_CA": "root-ca.pem"
        }
        """

        certs_name = {}
        component_keys = self.components_certs_config_keys.get(component, [])

        for key in component_keys:
            certs_name[key.name] = self._get_cert_name_from_key(
                key=key.value, file=component_config_file, flattened_key=flattened_key, client=client
            )

        return certs_name

    def generate_certificates(
        self, certs_tool_path: Path | None = None, client: paramiko.SSHClient | None = None
    ) -> None:
        """
        Main moethod of the class. It generates certificates for Wazuh components.

        This method generates certificates using the certs-tool, compresses them, and copies them to the appropriate
        directories for each Wazuh component. Also updates the name of the default certificates to the ones specified
        in the configuration files for each component.

        Args:
            certs_tool_path (Path | None): The path to the certificate generation tool. If not provided, the default path
                                           will be used.
            client (paramiko.SSHClient | None): An SSH client for executing commands on a remote server. If not provided,
                                                commands will be executed locally.

        Raises:
            Exception: If there is an error during certificate generation, compression, or copying to component directories.

        Returns:
            None
        """

        logger.debug("Generating certificates")

        if not certs_tool_path:
            certs_tool_path = self.certs_tool_path

        command = f"sudo bash {certs_tool_path} -A"
        output, error_output = exec_command(command=command, client=client)
        if error_output:
            raise Exception(f"Error while generating certificates: {error_output}")

        command = f"""
            sudo tar -cf {certs_tool_path.parent}/wazuh-certificates.tar -C {certs_tool_path.parent}/wazuh-certificates/ . && sudo rm -rf {certs_tool_path.parent}/wazuh-certificates
            """

        output, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error while compressing certificates")
            raise Exception(f"Error while compressing certificates: {error_output}")

        for component in Component:
            if component != Component.ALL:
                certs_name = self._get_certs_name(
                    component=component,
                    component_config_file=ComponentConfigFile.WAZUH_INDEXER
                    if component == Component.WAZUH_INDEXER
                    else ComponentConfigFile.WAZUH_SERVER
                    if component == Component.WAZUH_SERVER
                    else ComponentConfigFile.WAZUH_DASHBOARD,
                    flattened_key=component != Component.WAZUH_SERVER,  # Flatten key only for indexer and dashboard
                    client=client,
                )

                output, error_output = self.copy_certs_to_component_directory(
                    component=component, certs_path=certs_tool_path.parent, certs_name=certs_name, client=client
                )

                if error_output:
                    logger.error(f"Error while copying certificates to {component.replace('_', ' ')} directory")
                    raise Exception(
                        f"Error while copying certificates to {component.replace('_', ' ')} directory: {error_output}"
                    )

        logger.info_success("Certificates generated successfully")

    def copy_certs_to_component_directory(
        self, component: Component, certs_path: Path, certs_name: dict, client: paramiko.SSHClient | None = None
    ) -> tuple[str, str]:
        """
        Given a compressed folder with certificates, it extracts the certificates and copies them to the appropriate
        directories for each Wazuh component, changing the default names to the ones specified in the configuration files.

        Args:
            component (Component): The component to which the certificates will be copied.
            certs_name (dict): A dictionary containing the new names for the certificates.
            client (paramiko.SSHClient | None, optional): An SSH client for remote execution. Defaults to None.

        Returns:
            tuple[str, str]: The result of the command execution.
        """
        logger.debug(f"Copying certificates to {component.replace('_', ' ')} directory...")

        if component == Component.WAZUH_INDEXER:
            command = f"""
                sudo rm -rf {ComponentCertsDirectory.WAZUH_INDEXER}
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_INDEXER}
                sudo tar -xf {certs_path}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_INDEXER} ./{" ./".join(self.components_certs_default_name[Component.WAZUH_INDEXER].values())}
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/{self.components_certs_default_name[Component.WAZUH_INDEXER]["cert"]} {ComponentCertsDirectory.WAZUH_INDEXER}/{certs_name[ComponentCertsConfigParameter.WAZUH_INDEXER_CERT.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/{self.components_certs_default_name[Component.WAZUH_INDEXER]["key"]} {ComponentCertsDirectory.WAZUH_INDEXER}/{certs_name[ComponentCertsConfigParameter.WAZUH_INDEXER_KEY.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/{self.components_certs_default_name[Component.WAZUH_INDEXER]["ca"]} {ComponentCertsDirectory.WAZUH_INDEXER}/{certs_name[ComponentCertsConfigParameter.WAZUH_INDEXER_CA.name]}
                sudo chmod 500 {ComponentCertsDirectory.WAZUH_INDEXER}
                sudo find {ComponentCertsDirectory.WAZUH_INDEXER} -type f -exec chmod 400 {{}} \\;
                sudo chown -R wazuh-indexer:wazuh-indexer {ComponentCertsDirectory.WAZUH_INDEXER}/
                """
        elif component == Component.WAZUH_SERVER:
            command = f"""
                sudo rm -rf {ComponentCertsDirectory.WAZUH_SERVER}
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_SERVER}
                sudo tar -xf {certs_path}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_SERVER} ./{" ./".join(self.components_certs_default_name[Component.WAZUH_SERVER].values())}
                sudo mv -n {ComponentCertsDirectory.WAZUH_SERVER}/{self.components_certs_default_name[Component.WAZUH_SERVER]["cert"]} {ComponentCertsDirectory.WAZUH_SERVER}/{certs_name[ComponentCertsConfigParameter.WAZUH_SERVER_CERT.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_SERVER}/{self.components_certs_default_name[Component.WAZUH_SERVER]["key"]} {ComponentCertsDirectory.WAZUH_SERVER}/{certs_name[ComponentCertsConfigParameter.WAZUH_SERVER_KEY.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_SERVER}/{self.components_certs_default_name[Component.WAZUH_SERVER]["ca"]} {ComponentCertsDirectory.WAZUH_SERVER}/{certs_name[ComponentCertsConfigParameter.WAZUH_SERVER_CA.name]}
                sudo chmod 500 {ComponentCertsDirectory.WAZUH_SERVER}
                sudo find {ComponentCertsDirectory.WAZUH_SERVER} -type f -exec chmod 400 {{}} \\;
                sudo chown -R root:root {ComponentCertsDirectory.WAZUH_SERVER}/
                """
        elif component == Component.WAZUH_DASHBOARD:
            command = f"""
                sudo rm -rf {ComponentCertsDirectory.WAZUH_DASHBOARD}
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_DASHBOARD}
                sudo tar -xf {certs_path}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_DASHBOARD} ./{" ./".join(self.components_certs_default_name[Component.WAZUH_DASHBOARD].values())}
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/{self.components_certs_default_name[Component.WAZUH_DASHBOARD]["cert"]} {ComponentCertsDirectory.WAZUH_DASHBOARD}/{certs_name[ComponentCertsConfigParameter.WAZUH_DASHBOARD_CERT.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/{self.components_certs_default_name[Component.WAZUH_DASHBOARD]["key"]} {ComponentCertsDirectory.WAZUH_DASHBOARD}/{certs_name[ComponentCertsConfigParameter.WAZUH_DASHBOARD_KEY.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/{self.components_certs_default_name[Component.WAZUH_DASHBOARD]["ca"]} {ComponentCertsDirectory.WAZUH_DASHBOARD}/{certs_name[ComponentCertsConfigParameter.WAZUH_DASHBOARD_CA.name]}
                sudo chmod 500 {ComponentCertsDirectory.WAZUH_DASHBOARD}
                sudo find {ComponentCertsDirectory.WAZUH_DASHBOARD} -type f -exec chmod 400 {{}} \\;
                sudo chown -R wazuh-dashboard:wazuh-dashboard {ComponentCertsDirectory.WAZUH_DASHBOARD}/
                """

        return exec_command(command=command, client=client)
