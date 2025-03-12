import re
from pathlib import Path

import paramiko

from configurer.core.utils import ComponentCertsConfigParameter, ComponentCertsDirectory, ComponentConfigFile
from generic import exec_command
from utils import Component, Logger, RemoteDirectories

logger = Logger("CertsManager")


class CertsManager:
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
        yq_query = f"sudo yq '.[\"{key}\"]' {file}" if flattened_key else f"sudo yq '.{key}' {file}"

        output, error_output = exec_command(command=yq_query, client=client)
        if error_output:
            raise Exception(f"Error while executing yq query: {error_output}")

        cleaned_output = re.sub(r'^\["(.*)"\]$', r"\1", output)

        return Path(cleaned_output.strip()).name

    def _get_certs_name(
        self,
        component: Component,
        component_config_file: str,
        flattened_key: bool = True,
        client: paramiko.SSHClient | None = None,
    ):
        certs_name = {}
        component_keys = self.components_certs_config_keys.get(component, [])

        for key in component_keys:
            certs_name[key.name] = self._get_cert_name_from_key(
                key=key.value, file=component_config_file, flattened_key=flattened_key, client=client
            )

        return certs_name

    def generate_certificates(self, certs_tool_path: Path | None = None, client: paramiko.SSHClient | None = None):
        logger.debug("Generating certificates")

        if not certs_tool_path:
            certs_tool_path = self.certs_tool_path

        command = f"sudo bash {certs_tool_path} -A"
        output, error_output = exec_command(command=command, client=client)
        if error_output:
            raise Exception(f"Error while generating certificates: {error_output}")

        command = f"""
            sudo tar -cf {RemoteDirectories.CERTS}/wazuh-certificates.tar -C {RemoteDirectories.CERTS}/wazuh-certificates/ . && sudo rm -rf {RemoteDirectories.CERTS}/wazuh-certificates
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
                    flattened_key=component != Component.WAZUH_SERVER,
                    client=client,
                )

                output, error_output = self.copy_certs_to_component_directory(
                    component=component, certs_name=certs_name, client=client
                )

                if error_output:
                    logger.error(f"Error while copying certificates to {component.replace('_', ' ')} directory")
                    raise Exception(
                        f"Error while copying certificates to {component.replace('_', ' ')} directory: {error_output}"
                    )

        logger.info_success("Certificates generated successfully")

    def copy_certs_to_component_directory(
        self, component: Component, certs_name: dict, client: paramiko.SSHClient | None = None
    ) -> tuple[str, str]:
        logger.debug(f"Copying certificates to {component.replace('_', ' ')} directory...")

        if component == Component.WAZUH_INDEXER:
            command = f"""
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_INDEXER}
                sudo tar -xf {RemoteDirectories.CERTS}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_INDEXER} ./{" ./".join(self.components_certs_default_name[Component.WAZUH_INDEXER].values())}
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/{self.components_certs_default_name[Component.WAZUH_INDEXER]["cert"]} {ComponentCertsDirectory.WAZUH_INDEXER}/{certs_name[ComponentCertsConfigParameter.WAZUH_INDEXER_CERT.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/{self.components_certs_default_name[Component.WAZUH_INDEXER]["key"]} {ComponentCertsDirectory.WAZUH_INDEXER}/{certs_name[ComponentCertsConfigParameter.WAZUH_INDEXER_KEY.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_INDEXER}/{self.components_certs_default_name[Component.WAZUH_INDEXER]["ca"]} {ComponentCertsDirectory.WAZUH_INDEXER}/{certs_name[ComponentCertsConfigParameter.WAZUH_INDEXER_CA.name]}
                sudo chown -R wazuh-indexer:wazuh-indexer {ComponentCertsDirectory.WAZUH_INDEXER}/
                """
        elif component == Component.WAZUH_SERVER:
            command = f"""
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_SERVER}
                sudo tar -xf {RemoteDirectories.CERTS}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_SERVER} ./{" ./".join(self.components_certs_default_name[Component.WAZUH_SERVER].values())}
                sudo mv -n {ComponentCertsDirectory.WAZUH_SERVER}/{self.components_certs_default_name[Component.WAZUH_SERVER]["cert"]} {ComponentCertsDirectory.WAZUH_SERVER}/{certs_name[ComponentCertsConfigParameter.WAZUH_SERVER_CERT.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_SERVER}/{self.components_certs_default_name[Component.WAZUH_SERVER]["key"]} {ComponentCertsDirectory.WAZUH_SERVER}/{certs_name[ComponentCertsConfigParameter.WAZUH_SERVER_KEY.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_SERVER}/{self.components_certs_default_name[Component.WAZUH_SERVER]["ca"]} {ComponentCertsDirectory.WAZUH_SERVER}/{certs_name[ComponentCertsConfigParameter.WAZUH_SERVER_CA.name]}
                sudo chown -R wazuh-server:wazuh-server {ComponentCertsDirectory.WAZUH_SERVER}/
                """
        elif component == Component.WAZUH_DASHBOARD:
            command = f"""
                sudo mkdir -p {ComponentCertsDirectory.WAZUH_DASHBOARD}
                sudo tar -xf {RemoteDirectories.CERTS}/wazuh-certificates.tar -C {ComponentCertsDirectory.WAZUH_DASHBOARD} ./{" ./".join(self.components_certs_default_name[Component.WAZUH_DASHBOARD].values())}
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/{self.components_certs_default_name[Component.WAZUH_DASHBOARD]["cert"]} {ComponentCertsDirectory.WAZUH_DASHBOARD}/{certs_name[ComponentCertsConfigParameter.WAZUH_DASHBOARD_CERT.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/{self.components_certs_default_name[Component.WAZUH_DASHBOARD]["key"]} {ComponentCertsDirectory.WAZUH_DASHBOARD}/{certs_name[ComponentCertsConfigParameter.WAZUH_DASHBOARD_KEY.name]}
                sudo mv -n {ComponentCertsDirectory.WAZUH_DASHBOARD}/{self.components_certs_default_name[Component.WAZUH_DASHBOARD]["ca"]} {ComponentCertsDirectory.WAZUH_DASHBOARD}/{certs_name[ComponentCertsConfigParameter.WAZUH_DASHBOARD_CA.name]}
                sudo chown -R wazuh-dashboard:wazuh-dashboard {ComponentCertsDirectory.WAZUH_DASHBOARD}/
                """

        return exec_command(command=command, client=client)
