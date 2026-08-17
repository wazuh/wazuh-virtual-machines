import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from configurer.core.models import CertsManager, WazuhComponentConfigManager
from generic import exec_command, remote_connection
from models import Inventory
from utils import CertificatesComponent, Component, Logger, RemoteDirectories

logger = Logger("CoreConfigurer")

# The Wazuh manager automatically generates a random Authd registration password on startup
# and persists it in this file. The Wazuh agent needs that same password to enroll against
# the manager, so it is copied to the agent Authd password file.
WAZUH_MANAGER_AUTHD_PASS_FILE = "/var/wazuh-manager/etc/authd.pass"
WAZUH_AGENT_AUTHD_PASS_FILE = "/var/ossec/etc/authd.pass"
# The manager generates its Authd password on startup, so wait for the file to appear.
AUTHD_PASS_MAX_RETRIES = 24
AUTHD_PASS_WAIT_TIME = 5
# `systemctl start` returns as soon as the manager process is launched, not once it has finished
# initializing, so wait for its API to actually respond before relying on anything it sets up.
MANAGER_READY_MAX_RETRIES = 12
MANAGER_READY_WAIT_TIME = 10


@dataclass
class CoreConfigurer:
    inventory: Inventory | None
    files_configuration_path: Path

    @remote_connection
    def configure(self, client: paramiko.SSHClient | None = None):
        """
        Configures the core components and manages certificates.

        This method performs the following steps:
        1. Configures the Wazuh components (Indexer, Manager, Dashboard) by replacing file entries
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
        config_mappings.replace_file_entries(Component.WAZUH_AGENT, client=client)
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

                # The manager (started in a previous iteration) has already generated its Authd
                # password, so copy it to the agent before enrolling it against the manager.
                if component == Component.WAZUH_AGENT:
                    self.set_authd_password(client=client)

                command = f"""
                    sudo systemctl --quiet enable {component.replace("_", "-").lower()}
                    sudo systemctl start {component.replace("_", "-").lower()}
                    """

                if component == Component.WAZUH_INDEXER:
                    command += "sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh"

                if component == Component.WAZUH_MANAGER:
                    command += """
                    sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username -v wazuh-manager
                    sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password -v wazuh-manager
                    """

                output, error_output = exec_command(command=command, client=client)
                if error_output:
                    logger.error(f"Error starting {component} service")
                    raise RuntimeError(f"Error starting {component} service: {error_output}")

                logger.debug(f"{component.replace('_', ' ')} service started")

                if component == Component.WAZUH_MANAGER:
                    self.wait_for_manager_ready(client=client)

        logger.info_success("All services started")

    def wait_for_manager_ready(self, client: paramiko.SSHClient | None = None):
        """
        Waits for the Wazuh manager API to respond, confirming the manager has finished starting up.

        Args:
            client (paramiko.SSHClient | None, optional): An SSH client to execute the commands
                remotely. If None, the commands are executed locally. Defaults to None.

        Raises:
            RuntimeError: If the manager API does not respond within the retry budget.
        """

        logger.debug("Waiting for the Wazuh manager API to be ready")

        command = (
            'sudo curl -XPOST https://localhost:55000/security/user/authenticate '
            '-uwazuh-wui:wazuh-wui -k --max-time 10 -w "%{http_code}" -s -o /dev/null'
        )
        for attempt in range(MANAGER_READY_MAX_RETRIES):
            output, _ = exec_command(command=command, client=client)
            if output == "200":
                break
            logger.debug(
                f"Wazuh manager API not ready yet, retrying in {MANAGER_READY_WAIT_TIME} seconds "
                f"(attempt {attempt + 1}/{MANAGER_READY_MAX_RETRIES})"
            )
            time.sleep(MANAGER_READY_WAIT_TIME)
        else:
            logger.error("Wazuh manager API did not become ready in time")
            raise RuntimeError("Wazuh manager API did not become ready in time")

        logger.debug("Wazuh manager API is ready")

    def set_authd_password(self, client: paramiko.SSHClient | None = None):
        """
        Configures the Wazuh agent registration password.

        Reads the Authd password automatically generated and stored by the Wazuh manager in its
        ``authd.pass`` file and writes it, with the proper ownership and permissions, to the Wazuh
        agent ``authd.pass`` file. This lets the agent enroll against the manager and reproduces the
        behavior of the ``WAZUH_REGISTRATION_PASSWORD`` installation parameter for the pre-installed
        agent shipped in the OVA and AMI.

        Args:
            client (paramiko.SSHClient | None, optional): An SSH client to execute the commands
                remotely. If None, the commands are executed locally. Defaults to None.

        Raises:
            RuntimeError: If the manager Authd password file is not found or the agent registration
                password cannot be set.
        """

        logger.debug("Setting the Wazuh agent registration password from the manager Authd password")

        for attempt in range(AUTHD_PASS_MAX_RETRIES):
            output, _ = exec_command(
                command=f"sudo test -f {WAZUH_MANAGER_AUTHD_PASS_FILE} && echo found", client=client
            )
            if "found" in output:
                break
            logger.debug(
                f"Manager Authd password file not ready yet, retrying in {AUTHD_PASS_WAIT_TIME} seconds "
                f"(attempt {attempt + 1}/{AUTHD_PASS_MAX_RETRIES})"
            )
            time.sleep(AUTHD_PASS_WAIT_TIME)
        else:
            logger.error("Wazuh manager Authd password file not found")
            raise RuntimeError(f"Wazuh manager Authd password file not found at {WAZUH_MANAGER_AUTHD_PASS_FILE}")

        command = f"""
            sudo cp {WAZUH_MANAGER_AUTHD_PASS_FILE} {WAZUH_AGENT_AUTHD_PASS_FILE}
            sudo chown root:wazuh {WAZUH_AGENT_AUTHD_PASS_FILE}
            sudo chmod 640 {WAZUH_AGENT_AUTHD_PASS_FILE}
            """
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error("Error setting the Wazuh agent registration password")
            raise RuntimeError(f"Error setting the Wazuh agent registration password: {error_output}")

        logger.debug("Wazuh agent registration password set successfully")
