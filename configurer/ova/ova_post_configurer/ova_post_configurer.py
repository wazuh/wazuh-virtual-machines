import json
import os
import shutil
from pathlib import Path

from configurer.utils import run_command
from generic.helpers import modify_file
from utils import Logger

logger = Logger("OVA PostConfigurer - Main module")

STATIC_PATH = "configurer/ova/ova_post_configurer/static"
SCRIPTS_PATH = "configurer/ova/ova_post_configurer/scripts"
WAZUH_STARTER_PATH = f"{SCRIPTS_PATH}/wazuh-starter"
UTILS_PATH = "utils"


def set_hostname() -> None:
    """
    Sets the hostname of the VM to 'wazuh-server'.

    Returns:
        None
    """
    logger.debug("Setting hostname to 'wazuh-server'.")
    run_command("sudo hostnamectl set-hostname wazuh-server", check=True)


def config_grub() -> None:
    """
    Configures the GRUB bootloader by performing the following steps:
    1. Copies the Wazuh GRUB image file from the static path to the GRUB directory.
    2. Copies the GRUB configuration file from the static path to the default configuration directory.
    3. Regenerates the GRUB configuration file using the `grub2-mkconfig` command.

    Returns:
        None
    """
    logger.debug("Configuring GRUB bootloader.")
    files_to_move = {
        f"{STATIC_PATH}/grub/wazuh.png": "/boot/grub2/wazuh.png",
        f"{STATIC_PATH}/grub/grub": "/etc/default/grub",
    }
    for src, dst in files_to_move.items():
        if os.path.exists(dst):
            os.remove(dst)
        shutil.copy(src, dst)
    run_command("grub2-mkconfig -o /boot/grub2/grub.cfg")


def enable_fips() -> None:
    """
    Enables FIPS (Federal Information Processing Standards) mode on the system.

    This is done by performing the following steps:
    1. Updating the system packages.
    2. Installing the `dracut-fips` package.
    3. Rebuilding the initial RAM disk with FIPS support.
    4. Updating the kernel boot parameters to enable FIPS mode.

    Returns:
        None
    """
    logger.debug("Enabling FIPS mode.")
    commands = [
        "yum update -y",
        "yum install -y dracut-fips",
        "dracut -f",
        "/sbin/grubby --update-kernel=ALL --args='fips=1'",
    ]
    run_command(commands)


def update_jvm_heap() -> None:
    """
    Updates the JVM heap configuration. This is done through the automatic_set_ram.sh script.
    This script sets the WAzuh Indexer heap to the half of the total VM RAM memory.

    Steps performed:
    1. Copies the `automatic_set_ram.sh` script from the static path to `/etc/automatic_set_ram.sh`.
    2. Sets execution permissions (755) for the script.
    3. Copies the `updateIndexerHeap.service` systemd service file to `/etc/systemd/system/updateIndexerHeap.service`.
    4. Reloads the systemd daemon and enables the `updateIndexerHeap.service` to run at startup.

    Returns:
        None
    """
    logger.debug("Updating JVM heap configuration.")
    files_to_move = {
        f"{UTILS_PATH}/scripts/automatic_set_ram.sh": "/etc/automatic_set_ram.sh",
        f"{UTILS_PATH}/scripts/updateIndexerHeap.service": "/etc/systemd/system/updateIndexerHeap.service",
    }

    for src, dst in files_to_move.items():
        if os.path.exists(dst):
            os.remove(dst)
        shutil.copy(src, dst)
        if "automatic_set_ram.sh" in src:
            os.chmod(dst, 0o755)

    run_command(["systemctl daemon-reload", "systemctl enable updateIndexerHeap.service"])


def add_wazuh_starter_service() -> None:
    """
    This function copies the Wazuh starter service, timer, and script files to the system locations.
    It also sets the necessary permissions for the script file and enables the systemd service and timer.

    This results in the Wazuh services started one by one in the correct order.

    Steps performed:
    1. Copies the Wazuh starter service file to `/etc/systemd/system/wazuh-starter.service`.
    2. Copies the Wazuh starter timer file to `/etc/systemd/system/wazuh-starter.timer`.
    3. Copies the Wazuh starter script file to `/etc/.wazuh-starter.sh`.
    4. Sets executable permissions (755) on the script file.
    5. Reloads the systemd daemon and enables the Wazuh starter service and timer.

    Returns:
        None
    """
    logger.debug("Adding Wazuh starter service.")
    files_to_move = {
        f"{WAZUH_STARTER_PATH}/wazuh-starter.service": "/etc/systemd/system/wazuh-starter.service",
        f"{WAZUH_STARTER_PATH}/wazuh-starter.timer": "/etc/systemd/system/wazuh-starter.timer",
        f"{WAZUH_STARTER_PATH}/wazuh-starter.sh": "/etc/.wazuh-starter.sh",
    }

    for src, dst in files_to_move.items():
        if os.path.exists(dst):
            os.remove(dst)
        shutil.copy(src, dst)
        if "wazuh-starter.sh" in src:
            os.chmod(dst, 0o755)

    commands = [
        "systemctl daemon-reload",
        "systemctl enable wazuh-starter.timer",
        "systemctl enable wazuh-starter.service",
    ]
    run_command(commands)


def steps_system_config() -> None:
    """
    This function is the migration of the older systemConfig located in steps.sh.
    It performs some previous configuration to the VM:

    1. Upgrading the system packages using `yum upgrade`.
    2. Configuring the GRUB bootloader.
    3. Enabling FIPS (Federal Information Processing Standards) mode.
    4. Updating the JVM heap size.
    5. Adding the Wazuh starter service.
    6. Changing the root password to 'wazuh'.
    7. Setting the system hostname.
    8. Modifying the SSH configuration to:
        - Comment out the `PermitRootLogin yes` directive.
        - Enable password authentication by replacing `PasswordAuthentication no` with `PasswordAuthentication yes`.
        - Append `PermitRootLogin no` to the SSH configuration file.
    9. Retrieving the Wazuh version and stage from the `VERSION.json` file.
    10. Running a script to display messages with the Wazuh version and user information.

    Returns:
        None
    """
    run_command("yum upgrade -y")

    config_grub()

    enable_fips()

    update_jvm_heap()

    add_wazuh_starter_service()

    run_command("echo 'root:wazuh' | chpasswd")

    set_hostname()

    modify_file(
        filepath=Path("/etc/ssh/sshd_config"),
        replacements=[("PermitRootLogin yes", "#PermitRootLogin yes")],
        client=None,
    )

    modify_file(
        filepath=Path("/etc/ssh/sshd_config"),
        replacements=[("PasswordAuthentication no", "PasswordAuthentication yes")],
        client=None,
    )

    with open("/etc/ssh/sshd_config", "a") as file:
        file.write("\nPermitRootLogin no\n")

    # Retrieve Wazuh Version from Version.json
    with open("VERSION.json") as file:
        data = json.load(file)
    version = data.get("version")
    stage = data.get("stage")
    wazuh_version = version + "-" + stage

    logger.debug("Adding Wazuh welcome messages.")
    run_command(f"sudo bash {SCRIPTS_PATH}/messages.sh no {wazuh_version} wazuh-user")


def steps_clean() -> None:
    """
    Cleans up the system by executing a series of commands.

    This function performs the following cleanup steps:
    1. Removes the file `/securityadmin_demo.sh`.
    2. Cleans all cached data for the `yum` package manager.
    3. Reloads the systemd manager configuration.
    4. Clears the current user's bash history.

    Returns:
        None
    """
    commands = [
        "rm -f /securityadmin_demo.sh",
        "yum clean all",
        "systemctl daemon-reload",
        "cat /dev/null > ~/.bash_history && history -c",
    ]
    run_command(commands)


def post_conf_create_network_config(config_path: str = "/etc/systemd/network/20-eth1.network") -> None:
    """
    Creates a network configuration file for a specified network interface and restarts
    the systemd-networkd service to apply the changes.

    Args:
        config_path (str): The file path where the network configuration will be created.
                           Defaults to "/etc/systemd/network/20-eth1.network".

    Returns:
        None
    """
    logger.debug("Creating network configuration.")
    config_content = """[Match]
Name=eth1
[Network]
DHCP=ipv4
"""

    with open(config_path, "w") as config_file:
        config_file.write(config_content)
        run_command("systemctl restart systemd-networkd")


def post_conf_change_ssh_crypto_policies(config_path: str = "/etc/crypto-policies/back-ends/opensshserver.config"):
    """
    Updates the SSH cryptographic policies in the specified configuration file and restarts the SSH service.
    This function modifies the OpenSSH server configuration file to update cryptographic settings such as
    ciphers, MACs, GSSAPI key exchange algorithms, and key exchange algorithms. It replaces the existing
    values for these settings with predefined secure values in order to be able to connect via SSH with FIPS enabled.

    Args:
        config_path (str): The path to the OpenSSH server configuration file. Defaults to
                           "/etc/crypto-policies/back-ends/opensshserver.config".

    Returns:
        None
    """
    logger.debug("Changing SSH cryptographic policies.")
    new_values = {
        "Ciphers": "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "MACs": "MACs hmac-sha2-256,hmac-sha2-512",
        "GSSAPIKexAlgorithms": "GSSAPIKexAlgorithms gss-nistp256-sha256-,gss-group14-sha256-,gss-group16-sha512-",
        "KexAlgorithms": "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521",
    }

    with open(config_path) as file:
        lines = file.readlines()

    with open(config_path, "w") as file:
        for line in lines:
            key = line.split()[0] if line.strip() else ""
            if key in new_values:
                file.write(new_values[key] + "\n")
            else:
                file.write(line)

    run_command("systemctl restart sshd")


def post_conf_clean() -> None:
    """
    Cleans up system logs, clears command history, removes cached package data, and updates SSH configuration.

    This function performs the following actions:
    1. Clears the contents of various log files and removes specific log files.
    2. Clears the bash command history for the current user.
    3. Cleans up cached package data using `yum clean all` and removes the yum cache directory.
    4. Modifies the SSH daemon configuration to remove specific settings related to `AuthorizedKeysCommand`.
    5. Restarts the SSH daemon to apply the configuration changes.

    Returns:
        None
    """
    logger.debug("Cleaning up system logs and command history.")
    log_clean_commands = [
        "find /var/log/ -type f -exec bash -c 'cat /dev/null > {}' \\;",
        r"find /var/log/wazuh-indexer -type f -execdir sh -c 'cat /dev/null > \"$1\"' _ {} \;",
        "rm -rf /var/log/wazuh-install.log",
    ]
    run_command(log_clean_commands)

    run_command("cat /dev/null > ~/.bash_history && history -c")

    yum_clean_commands = ["sudo yum clean all", "sudo rm -rf /var/cache/yum/*"]
    run_command(yum_clean_commands)

    sshd_config_changes = [
        (r"^#?AuthorizedKeysCommand.*", ""),
        (r"^#?AuthorizedKeysCommandUser.*", ""),
    ]
    sshd_config_path = Path("/etc/ssh/sshd_config")
    modify_file(filepath=sshd_config_path, replacements=sshd_config_changes, client=None)
    run_command("sudo systemctl restart sshd")


def main() -> None:
    """
    Main function to run the OVA PostConfigurer process.
    This function performs the following tasks:
    1. Configures the system using the `steps_system_config` function.
    2. Stops the Wazuh Manager service.
    3. Deletes specific Wazuh indexes.
    4. Re-runs the security-init.
    5. Stops and disable Wazuh services.
    6. Cleans up the system by calling `steps_clean`.
    7. Applies post-configuration changes, including:
        - Creating network configuration.
        - Changing SSH cryptographic policies.
        - Performing additional cleanup tasks.

    Returns:
        None
    """
    logger.debug_title("Starting OVA PostConfigurer")
    logger.debug("Running system configuration.")
    steps_system_config()

    run_command("systemctl stop wazuh-server")
    indexes = [
        "wazuh-alerts-*",
        "wazuh-archives-*",
        "wazuh-states-vulnerabilities-*",
        "wazuh-statistics-*",
        "wazuh-monitoring-*",
    ]
    for index in indexes:
        run_command(f"curl -u admin:admin -XDELETE 'https://127.0.0.1:9200/{index}' -k")

    std_out, _,_ = run_command("bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1", output=True)
    logger.debug(std_out)

    commands = [
        "systemctl stop wazuh-indexer wazuh-dashboard",
        "systemctl disable wazuh-server",
        "systemctl disable wazuh-dashboard",
    ]
    run_command(commands)

    steps_clean()

    logger.debug("Applying post-configuration changes.")
    post_conf_create_network_config()
    post_conf_change_ssh_crypto_policies()
    post_conf_clean()
    logger.info_success("OVA PostConfigurer completed.")


if __name__ == "__main__":
    main()
