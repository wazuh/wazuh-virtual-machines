import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from configurer.core.models import CertsManager, WazuhComponentConfigManager
from generic import exec_command, exec_command_with_status, remote_connection
from models import Inventory
from utils import CertificatesComponent, Component, Logger, RemoteDirectories

logger = Logger("CoreConfigurer")

# The pre-installed agent is NOT enrolled here, and that is deliberate. wazuh/wazuh#39063 replaced
# the shared Authd password with a per-agent WAZUH_ENROLLMENT_TOKEN, which the manager mints locally
# with `wazuh-manager-authd --create-enrollment-token`. Two things make the image the wrong place to
# do that:
#
#   * A mint is refused when the agent listener certificate names loopback only
#     (enrollment_token_mint.c: "certificate only names loopback"), and at build time it does --
#     the instance's real addresses only reach remoted.pem's SAN on the first boot of the deployed
#     instance, through CertsManager.generate_certificates()'s agent_san (issue #957).
#   * Anything minted here would be baked into the published image, so every instance launched from
#     it would share one enrollment credential and one agent key. That is the exact problem the
#     Authd password rotation existed to avoid, and a token is no better baked than a password was.
#
# So the image ships an agent that is installed, configured and disabled, with no key, no trust
# anchor and no token. The first-boot hooks mint the token and let the agent enroll for real, each
# deployed instance with its own credential and its own identity:
# configurer/ova/ova_post_configurer/scripts/wazuh-starter/wazuh-starter.sh (OVA) and
# configurer/ami/ami_post_configurer/wazuh-ami-customizer.py (AMI).

# `wazuh-manager-keystore` stores its values in a RocksDB-backed file (queue/keystore) that a
# just-started manager daemon may still be opening -- `systemctl start` returns as soon as the
# unit is "active", not once every daemon inside it has finished initializing -- so the keystore
# CLI can lose the exclusive-lock race immediately after start. Retry instead of failing outright.
MANAGER_KEYSTORE_MAX_RETRIES = 6
MANAGER_KEYSTORE_WAIT_TIME = 5


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

        # The agent is started with nothing to enroll with: no token is minted at build time (see
        # the note at the top of this file). It stays unenrolled until the first boot of the
        # deployed instance, where the token is minted and the agent enrolls for real. The manager
        # ships with <auth><use_password>yes</use_password>, so an agent carrying no credential
        # cannot register by accident in the meantime.
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

                if component == Component.WAZUH_MANAGER:
                    self.set_manager_keystore(client=client)

                logger.debug(f"{component.replace('_', ' ')} service started")

        logger.info_success("All services started")

    def set_manager_keystore(self, client: paramiko.SSHClient | None = None):
        """
        Sets the manager's indexer credentials in its keystore, retrying on lock contention.

        `wazuh-manager-keystore` needs exclusive access to a RocksDB-backed file that a manager
        daemon started moments earlier may still be opening, since a systemd unit reporting
        "active" doesn't mean every daemon inside it has finished initializing. That race makes
        the CLI fail intermittently right after the manager starts, so each key is retried by exit
        status instead of failing on the first attempt.

        Args:
            client (paramiko.SSHClient | None, optional): An SSH client to execute the commands
                remotely. If None, the commands are executed locally. Defaults to None.

        Raises:
            RuntimeError: If a keystore value could not be set after all retries.
        """

        for key in ("username", "password"):
            command = f"sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k {key} -v wazuh-manager"

            for attempt in range(MANAGER_KEYSTORE_MAX_RETRIES):
                _, error_output, returncode = exec_command_with_status(command=command, client=client)
                if returncode == 0:
                    break
                logger.debug(
                    f"Manager keystore {key} not set yet, retrying in {MANAGER_KEYSTORE_WAIT_TIME} seconds "
                    f"(attempt {attempt + 1}/{MANAGER_KEYSTORE_MAX_RETRIES})"
                )
                time.sleep(MANAGER_KEYSTORE_WAIT_TIME)
            else:
                logger.error(f"Error setting manager keystore {key}")
                raise RuntimeError(f"Error setting manager keystore {key}: {error_output}")
