import json
import os
import shutil
from pathlib import Path

from configurer.core.utils import indexer_request_command, purge_build_credentials_command
from configurer.utils import run_command
from generic.helpers import add_content_to_file, modify_file
from utils import Logger, RemoteDirectories, CertificatesComponent

logger = Logger("OVA PostConfigurer - Main module")

STATIC_PATH = "configurer/ova/ova_post_configurer/static"
SCRIPTS_PATH = "configurer/ova/ova_post_configurer/scripts"
WAZUH_STARTER_PATH = f"{SCRIPTS_PATH}/wazuh-starter"
UTILS_PATH = "utils"

# wazuh-starter regenerates the CA and every component certificate on first boot (see steps_clean),
# so it needs its own persistent copy of the certs-tool and its config -- the ones core_configurer
# downloads under RemoteDirectories.CERTS only exist for the build, wazuh-starter runs long after
# that directory is gone.
#
# Both files must keep their default names and live side by side: wazuh-certs-tool.sh resolves its
# own config as "$(dirname "$0")/config.yml" with no flag to override it (verified against the real
# tool on a booted OVA -- it failed with "No configuration file found" when the config was persisted
# under a different name), so CertificatesComponent.CONFIG ("config.yml") is not just a default, it's
# a hard requirement.
WAZUH_STARTER_CERTS_DIR = "/etc/.wazuh-starter-certs"
WAZUH_STARTER_CERTS_TOOL_PATH = f"{WAZUH_STARTER_CERTS_DIR}/{CertificatesComponent.CERTS_TOOL}"
WAZUH_STARTER_CERTS_CONFIG_PATH = f"{WAZUH_STARTER_CERTS_DIR}/{CertificatesComponent.CONFIG}"


def set_hostname() -> None:
    """
    Sets the hostname of the VM to 'wazuh'.

    Returns:
        None
    """
    logger.debug("Setting hostname to 'wazuh'.")
    run_command("sudo hostnamectl set-hostname wazuh", check=True)


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
    This script sets the Wazuh Indexer heap to a quarter of the final host's total RAM memory.

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


def add_wazuh_starter_certs_tool() -> None:
    """
    Persists the certs-tool and its config for wazuh-starter's first-boot use.

    core_configurer's build-time run already downloaded these under RemoteDirectories.CERTS to
    generate the certificates baked into the image (later discarded per instance, see steps_clean).
    wazuh-starter needs the same tool at first boot, long after that build-time directory is gone,
    so this copies both files to a location that survives packaging.

    Returns:
        None

    Raises:
        FileNotFoundError: If the certs-tool or its config are not present under RemoteDirectories.CERTS
            at the point this runs -- steps_system_config must call this after core_configurer's certs
            generation step, not before.
    """

    logger.debug("Persisting the certs-tool for wazuh-starter.")
    certs_dir = os.path.expanduser(str(RemoteDirectories.CERTS))
    src_certs_tool = f"{certs_dir}/{CertificatesComponent.CERTS_TOOL}"
    src_config = f"{certs_dir}/{CertificatesComponent.CONFIG}"

    os.makedirs(WAZUH_STARTER_CERTS_DIR, exist_ok=True)
    for src, dst in {
        src_certs_tool: WAZUH_STARTER_CERTS_TOOL_PATH,
        src_config: WAZUH_STARTER_CERTS_CONFIG_PATH,
    }.items():
        if not os.path.exists(src):
            raise FileNotFoundError(f"{src} not found -- expected core_configurer's certs generation to have run first")
        shutil.copy(src, dst)

    logger.info_success("Certs-tool persisted for wazuh-starter.")


def configure_sshd(ssh_config_file: Path | str = Path("/etc/ssh/sshd_config")) -> None:
    """
    Configures the SSH daemon to disable root login, enable password authentication,
    and disable AuthorizedKeysCommand, in an idempotent and robust way.
    """
    logger.debug("Applying robust SSH configuration.")

    if not isinstance(ssh_config_file, Path):
        ssh_config_file = Path(ssh_config_file)

    # Remove any existing PasswordAuthentication, PermitRootLogin, AuthorizedKeysCommand directives
    replace_content = [
        (r"^[ \t]*#?[ \t]*PasswordAuthentication.*$", "PasswordAuthentication yes"),
        (r"^[ \t]*#?[ \t]*PermitRootLogin.*$", "PermitRootLogin no"),
        (r"^[ \t]*#?[ \t]*AuthorizedKeysCommand.*$", ""),
    ]
    modify_file(ssh_config_file, replace_content)


def grow_root_filesystem() -> None:
    """
    Extends the root partition and its XFS file system to the end of the disk. The base box grows
    the AL2023 disk (25 GiB) to its final size, but the partition and file system keep the original
    size until they are extended here. growpart exits non-zero when there is nothing to grow (for
    example, if cloud-init already did it at boot), so its result is not checked; xfs_growfs is.

    Returns:
        None
    """
    logger.debug("Growing the root partition and file system.")
    root_part = "$(findmnt -no SOURCE /)"
    run_command(
        f'growpart "/dev/$(lsblk -no PKNAME {root_part})" "$(cat /sys/class/block/$(basename {root_part})/partition)"'
    )
    run_command("xfs_growfs /", check=True)
    stdout, _, _ = run_command("df -h /", output=True)
    logger.info(f"Root file system after growing:\n{stdout[0]}")


def steps_system_config() -> None:
    """
    This function is the migration of the older systemConfig located in steps.sh.
    It performs some previous configuration to the VM:

    1. Upgrading the system packages using `yum upgrade`.
    2. Configuring the GRUB bootloader.
    3. Enabling FIPS (Federal Information Processing Standards) mode.
    4. Updating the JVM heap size.
    5. Adding the Wazuh starter service.
    6. Setting the system hostname.
    7. Retrieving the Wazuh version from the `VERSION.json` file.
    8. Running a script to display messages with the Wazuh version and user information.

    Returns:
        None
    """
    run_command("yum upgrade -y")

    grow_root_filesystem()

    config_grub()

    enable_fips()

    update_jvm_heap()

    add_wazuh_starter_service()
    add_wazuh_starter_certs_tool()

    set_hostname()

    # Retrieve Wazuh Version from Version.json. The stage is not used, as the stage OVA is copied unchanged to production
    with open("VERSION.json") as file:
        data = json.load(file)
    wazuh_version = data.get("version")

    logger.debug("Adding Wazuh welcome messages.")
    run_command(f"sudo bash {SCRIPTS_PATH}/messages.sh no {wazuh_version} wazuh-user")


def steps_clean() -> None:
    """
    Cleans up the system by executing a series of commands.

    This function performs the following cleanup steps:
    1. Removes the file `/securityadmin_demo.sh`.
    2. Removes the CA and every component certificate baked in at image build time (indexer,
       manager/indexer-connector, dashboard, admin, and the manager's remoted pair), regenerated
       per instance by wazuh-starter on first boot.
    3. Cleans all cached data for the `yum` package manager.
    4. Reloads the systemd manager configuration.
    5. Clears the current user's bash history.

    Returns:
        None
    """
    commands = [
        "rm -f /securityadmin_demo.sh",
        # Every certificate here, root-ca.pem included, was generated once at image build time.
        # Shipping any of them -- root-ca.pem's private key above all -- would make every VM
        # deployed from this OVA share the same CA, letting anyone who downloaded a copy forge a
        # valid certificate for any other instance's manager. Removed here, regenerated per
        # instance by wazuh-starter on first boot.
        "rm -f /var/wazuh-manager/etc/certs/*.pem",
        "rm -rf /etc/wazuh-indexer/certs/* /etc/wazuh-dashboard/certs/*",
        "yum clean all",
        "systemctl daemon-reload",
        "cat /dev/null > ~/.bash_history && history -c",
    ]
    run_command(commands)


def post_conf_create_network_config(config_path: str = "/etc/systemd/network/20-eth0.network") -> None:
    """
    Creates a network configuration file for a specified network interface and restarts
    the systemd-networkd service to apply the changes.

    Args:
        config_path (str): The file path where the network configuration will be created.
                           Defaults to "/etc/systemd/network/20-eth0.network".

    Returns:
        None
    """
    logger.debug("Creating network configuration.")
    config_content = """[Match]
Type=ether
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


def post_conf_deactivate_cloud_init() -> None:
    """
    Cleans the cloud-init logs and artifacts.
    Deactivates cloud-init by creating a configuration file that disables its modules.
    Creates a YAML configuration file at `/etc/cloud/cloud.cfg.d/99-disable-cloud-init.cfg`
    to disable all cloud-init modules. This prevents cloud-init from running during system boot.
    It also deletes the /var/lib/cloud directory and its content.

    Returns:
        None
    """
    logger.debug("Deactivating cloud-init.")
    run_command("sudo cloud-init clean --logs")
    shutil.rmtree("/var/lib/cloud", ignore_errors=True)
    Path("/etc/cloud/cloud-init.disabled").touch()
    cloud_init_content = """
network:
  config: disabled
"""

    config_file_path = Path("/etc/cloud/cloud.cfg.d/99-amazon-override.cfg")
    config_file_path.write_text(cloud_init_content)


def post_conf_delete_generated_network_files() -> None:
    """
    Deletes generated network configuration files to ensure proper network setup on next boot.

    This function removes specific network configuration files that may have been
    automatically generated by the system. Deleting these files allows the system
    to use the custom network configuration.

    Returns:
        None
    """
    logger.debug("Deleting generated network configuration files.")
    network_dir = Path("/etc/systemd/network/")
    for file in network_dir.glob("10-cloud-init-*.network"):
        file.unlink(missing_ok=True)
    for file in network_dir.glob("*vagrant*.network"):
        file.unlink(missing_ok=True)


def clean_generated_logs(
    log_directory_path: Path = Path("/var/log"),
    wazuh_indexer_log_path: Path = Path("/var/log/wazuh-indexer"),
    wazuh_manager_log_path: Path = Path("/var/wazuh-manager/logs"),
    wazuh_agent_log_path: Path = Path("/var/ossec/logs"),
    wazuh_dashboard_log_path: Path = Path("/var/log/wazuh-dashboard"),
) -> None:
    """
    Cleans up generated log files during the configuration in specified directories by truncating their contents.

    Checks if the specified log directories exist and contain files. If so, it
    truncates the contents of all files within those directories to free up space while
    retaining the file structure.

    Args:
        log_directory_path (Path): Path to the general log directory. Defaults to /var/log.
        wazuh_indexer_log_path (Path): Path to the Wazuh indexer log directory.
        wazuh_manager_log_path (Path): Path to the Wazuh manager log directory.
        wazuh_agent_log_path (Path): Path to the Wazuh agent log directory.
        wazuh_dashboard_log_path (Path): Path to the Wazuh dashboard log directory.

    Returns:
        None
    """
    logger.debug(f'Cleaning up generated logs in "{log_directory_path}"')

    log_dirs = [
        log_directory_path,
        wazuh_indexer_log_path,
        wazuh_manager_log_path,
        wazuh_agent_log_path,
        wazuh_dashboard_log_path,
    ]

    for log_dir in log_dirs:
        if log_dir.is_dir():
            files = list(log_dir.rglob("*"))
            for f in files:
                if f.is_file():
                    with open(f, "w") as fh:
                        fh.truncate(0)

    logger.info_success("Generated logs cleaned up successfully")


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

    post_conf_deactivate_cloud_init()
    post_conf_delete_generated_network_files()

    clean_generated_logs()

    run_command("cat /dev/null > ~/.bash_history && history -c")

    yum_clean_commands = ["sudo yum clean all", "sudo rm -rf /var/cache/yum/*"]
    run_command(yum_clean_commands)


def configure_ssh() -> None:
    """Apply SSH hardening and restart the SSH daemon.

    This routine updates SSH crypto policies, modifies the main
    ``/etc/ssh/sshd_config`` file, and, if present, iterates over all
    ``*.conf`` files in ``/etc/ssh/sshd_config.d`` to apply the same
    configuration updates and append explicit directives to disable root
    login and enable password authentication.

    Finally, it restarts the ``sshd`` service so all changes take effect.

    Returns:
        None
    """
    post_conf_change_ssh_crypto_policies()
    configure_sshd(Path("/etc/ssh/sshd_config"))

    sshd_config_d = Path("/etc/ssh/sshd_config.d")
    if sshd_config_d.is_dir():
        for conf_file in sshd_config_d.glob("*.conf"):
            configure_sshd(conf_file)
            add_content_to_file(conf_file, "\nPermitRootLogin no\nPasswordAuthentication yes\n")

    run_command("systemctl restart sshd")


def delete_wazuh_indexes() -> None:
    """
    Deletes Wazuh indexer indexes and data streams.

    This function removes all Wazuh-related indexes, data streams, and configuration
    from the Wazuh indexer (OpenSearch) to ensure a clean state.

    Returns:
        None
    """
    logger.debug("Deleting Wazuh indexer indexes.")

    indexes_to_delete = [
        "wazuh-*",
        "_data_stream/*",
        ".wazuh-cti-consumers",
        ".wazuh-threatintel-vulnerabilities-*",
        ".wazuh-settings",
        ".wazuh-content-manager-jobs",
    ]

    # There is no admin:admin any more: the indexer package generated the admin password at install
    # time and published it to /etc/wazuh/credentials.env. It reaches curl through its standard input,
    # never argv, and is never logged.
    for index in indexes_to_delete:
        result = run_command(indexer_request_command(method="DELETE", path=index), output=True)
        http_code = result[0][0] if result else ""
        if http_code == "401":
            raise RuntimeError(f"Error removing index {index} (HTTP 401): the admin password was not accepted")
        if http_code not in ("200", "404"):
            logger.warning(f"Removing index {index} returned HTTP {http_code}")


def purge_build_credentials() -> None:
    """
    Removes every credential, certificate and CA the build resolved, with every service stopped.

    Runs each package's `resolve-credentials --clear`, restores the indexer's password placeholders
    (workaround, see purge-build-credentials.sh) and removes /etc/wazuh. wazuh-starter then has each
    VM resolve its own passwords (`--prestart`) and issue its own certificates on first boot.

    Raises:
        RuntimeError: If any step fails or anything resolved at build time is left in the image.
    """
    logger.debug("Removing the credentials, certificates and CA resolved at build time.")
    result = run_command(purge_build_credentials_command(), output=True)
    stdout, stderr, returncode = result[0][0], result[1][0], result[2][0]
    if returncode != 0:
        raise RuntimeError(f"Error removing the build-time credentials: {stderr or stdout}")
    logger.info_success("Build-time credentials, certificates and CA removed.")


def generalize_image(root: Path = Path("/")) -> None:
    """
    Removes everything that would be shared by every VM deployed from this OVA and locks the build-time access.

    Must be the last step of the build: once the password of wazuh-user expires, the build can no longer log in.
    The result is verified afterwards, as some of the commands report warnings on stderr even when they succeed.

    1. Removes the SSH authorized_keys of every user (the Vagrant insecure public key, whose private key is public).
    2. Removes the SSH host keys (sshd-keygen.target regenerates them on first boot, DSA no longer).
    3. Empties /etc/machine-id, so each VM generates its own on first boot.
    4. Removes the cloud-init ec2-user, its sudoers file and the ifcfg-eth0 left by the base image.
    5. Locks the root password and expires the one of wazuh-user, which must be changed on the first login.

    Args:
        root (Path): Root of the file system that is verified. Only changed by the tests.

    Raises:
        RuntimeError: If anything shared or any build-time access is left in the image.
    """
    logger.debug("Generalizing the image and locking the build-time access.")
    commands = [
        "rm -f /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys",
        "rm -f /etc/ssh/ssh_host_*",
        # Emptied, not removed: an empty machine-id makes systemd generate and commit a new one on first boot,
        # while a missing (or "uninitialized") one triggers the first-boot semantics, `systemctl preset-all`
        # included, which would undo the services left disabled on purpose for wazuh-starter.
        "truncate -s 0 /etc/machine-id",
        "[ -L /var/lib/dbus/machine-id ] || rm -f /var/lib/dbus/machine-id",
        "! id ec2-user >/dev/null 2>&1 || userdel -r ec2-user",
        "grep -rlw ec2-user /etc/sudoers.d | xargs -r rm -f",
        "rm -f /etc/sysconfig/network-scripts/ifcfg-eth0",
        # The password of wazuh-user stays documented in the banner, but must be changed on the first login. A random
        # password per VM was ruled out, as the images never change passwords automatically on boot. sudo stays
        # NOPASSWD, as it was.
        "passwd -l root",
        "chage -d 0 wazuh-user",
    ]
    run_command(commands)

    errors = []
    if leftovers := [*root.glob("home/*/.ssh/authorized_keys"), *root.glob("root/.ssh/authorized_keys")]:
        errors.append(f"authorized_keys left: {leftovers}")
    if leftovers := [*root.glob("etc/ssh/ssh_host_*")]:
        errors.append(f"SSH host keys left: {leftovers}")
    if (root / "etc/machine-id").stat().st_size:
        errors.append("/etc/machine-id is not empty")
    if any(line.startswith("ec2-user:") for line in (root / "etc/passwd").read_text().splitlines()):
        errors.append("ec2-user still exists")
    if any("ec2-user" in f.read_text() for f in (root / "etc/sudoers.d").glob("*")):
        errors.append("ec2-user is still in /etc/sudoers.d")
    shadow = {line.split(":")[0]: line.split(":") for line in (root / "etc/shadow").read_text().splitlines()}
    if not shadow["root"][1].startswith("!"):
        errors.append("the root password is not locked")
    if shadow["wazuh-user"][2] != "0":
        errors.append("the wazuh-user password is not expired")
    if errors:
        raise RuntimeError(f"Error generalizing the image: {'; '.join(errors)}")
    logger.info_success("Image generalized and build-time access locked.")


def main() -> None:
    """
    Main function to run the OVA PostConfigurer process.
    This function performs the following tasks:
    1. Configures the system using the `steps_system_config` function.
    2. Stops the Wazuh Manager service.
    3. Deletes specific Wazuh indexes.
    4. Re-runs the security-init.
    5. Stops and disable Wazuh services.
    6. Removes the credentials, certificates and CA resolved at build time (`purge_build_credentials`).
    7. Cleans up the system by calling `steps_clean`.
    7. Applies post-configuration changes, including:
        - Creating network configuration.
        - Changing SSH cryptographic policies.
        - Modifying the SSH configuration to:
            - Comment out the `PermitRootLogin yes` directive.
            - Enable password authentication by replacing `PasswordAuthentication no` with `PasswordAuthentication yes`.
            - Append `PermitRootLogin no` to the SSH configuration file.
        - Performing additional cleanup tasks.
    8. Generalizes the image (`generalize_image`). This must be the last step.

    Returns:
        None
    """
    logger.debug_title("Starting OVA PostConfigurer")
    logger.debug("Running system configuration.")
    steps_system_config()

    run_command("systemctl stop wazuh-manager")
    run_command("systemctl stop wazuh-agent")
    delete_wazuh_indexes()

    run_command("bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1")

    # Every Wazuh service is left disabled, the indexer included: wazuh-starter starts them one by one
    # on first boot, once this VM's certificates are in place, and enables them afterwards. An indexer
    # started by systemd at boot would run its `--prestart` before any certificate exists and race
    # wazuh-starter, and its unit gives up after three failed starts in a minute.
    commands = [
        "systemctl stop wazuh-indexer wazuh-dashboard",
        "systemctl disable wazuh-indexer",
        "systemctl disable wazuh-manager",
        "systemctl disable wazuh-agent",
        "systemctl disable wazuh-dashboard",
    ]
    run_command(commands)

    purge_build_credentials()

    steps_clean()

    logger.debug("Applying post-configuration changes.")
    post_conf_create_network_config()
    configure_ssh()
    post_conf_clean()
    generalize_image()
    logger.info_success("OVA PostConfigurer completed.")


if __name__ == "__main__":
    main()
