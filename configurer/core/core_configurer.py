from dataclasses import dataclass
from pathlib import Path

import paramiko

from configurer.core.models import WazuhComponentConfigManager
from generic import exec_command, remote_connection
from models import Inventory
from utils import Component, Logger

logger = Logger("CoreConfigurer")

# The pre-installed agent is NOT enrolled here, and that is deliberate. wazuh/wazuh#39063 replaced
# the shared Authd password with a per-agent WAZUH_ENROLLMENT_TOKEN, which the manager mints locally
# with `wazuh-manager-authd --create-enrollment-token`. Two things make the image the wrong place to
# do that:
#
#   * A mint is refused when the agent listener certificate names loopback only
#     (enrollment_token_mint.c: "certificate only names loopback"), and at build time it does --
#     the instance's real addresses only reach remoted.pem's SAN on the first boot of the deployed
#     instance, when the first-boot hook runs the manager's `resolve-credentials --install`.
#   * Anything minted here would be baked into the published image, so every instance launched from
#     it would share one enrollment credential and one agent key. That is the exact problem the
#     Authd password rotation existed to avoid, and a token is no better baked than a password was.
#
# So the image ships an agent that is installed, configured and disabled, with no key, no trust
# anchor and no token. The first-boot hooks mint the token and let the agent enroll for real, each
# deployed instance with its own credential and its own identity:
# configurer/ova/ova_post_configurer/scripts/wazuh-starter/wazuh-starter.sh (OVA) and
# configurer/ami/ami_post_configurer/wazuh-ami-customizer.py (AMI).

# The manager's indexer credential is NOT set here any more. The manager package resolves it itself
# (wazuh/wazuh-indexer#1928): its postinst reads WAZUH_INDEXER_MANAGER_PASSWORD from
# /etc/wazuh-indexer/export/credentials.env, which the indexer package published with a generated value, and
# stores it in the manager keystore. Writing the old wazuh-manager/wazuh-manager pair over it would
# leave the manager unable to authenticate to the indexer.

# No certificate is generated here either. Since 5.0.0 RC 2 every package mints its own CA and issues
# its own pairs in its postinst (`resolve-credentials --install`), and on a single host each imports
# its peers' CAs from their export/. A pair issued from any other CA is refused at the next start.
# The build purge clears all of it, and first boot runs `--install` again on the instance.


@dataclass
class CoreConfigurer:
    inventory: Inventory | None
    files_configuration_path: Path

    @remote_connection
    def configure(self, client: paramiko.SSHClient | None = None):
        """
        Configures the core components and starts their services.

        This method performs the following steps:
        1. Configures the Wazuh components (Indexer, Manager, Dashboard) by replacing file entries
        using the WazuhComponentConfigManager.
        2. Starts the Wazuh services.

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

                logger.debug(f"{component.replace('_', ' ')} service started")

        logger.info_success("All services started")
