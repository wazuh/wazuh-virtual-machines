import os
import shutil

from configurer.utils.helpers import run_command

VAGRANT_KEY_URL = "https://raw.githubusercontent.com/hashicorp/vagrant/main/keys/vagrant.pub"


def configure_dns() -> None:
    """
    This function removes the existing /etc/resolv.conf file if it exists,
    and then creates a new one with a single nameserver entry pointing to
    Google's public DNS server (8.8.8.8).

    Returns:
        None
    """
    resolv_conf = "/etc/resolv.conf"
    if os.path.exists(resolv_conf):
        os.remove(resolv_conf)
    with open(resolv_conf, "w") as f:
        f.write("nameserver 8.8.8.8\n")


def setup_user() -> None:
    """
    This function performs the following steps:
    1. Creates a new user 'wazuh-user' with a home directory and bash shell.
    2. Sets the password for 'wazuh-user' to 'wazuh'.
    3. Creates the .ssh directory in the user's home directory.
    4. Downloads the Vagrant public key and saves it as the authorized_keys file.
    5. Sets appropriate permissions for the .ssh directory and authorized_keys file.
    6. Changes ownership of the user's home directory to 'wazuh-user'.
    7. Grants 'wazuh-user' passwordless sudo privileges by creating a sudoers file.

    Returns:
        None
    """
    commands = ["useradd -m -s /bin/bash wazuh-user", "echo 'wazuh-user:wazuh' | chpasswd"]
    run_command(commands)
    os.makedirs("/home/wazuh-user/.ssh", exist_ok=True)

    run_command(f"wget -nv {VAGRANT_KEY_URL} -O /home/wazuh-user/.ssh/authorized_keys")

    os.chmod("/home/wazuh-user/.ssh/authorized_keys", 0o600)
    os.chmod("/home/wazuh-user/.ssh", 0o700)

    run_command("chown -R wazuh-user:wazuh-user /home/wazuh-user")

    with open("/etc/sudoers.d/wazuh-user", "w") as f:
        f.write("wazuh-user ALL=(ALL) NOPASSWD: ALL\n")
    os.chmod("/etc/sudoers.d/wazuh-user", 0o440)


def install_dependencies() -> None:
    """
    This function runs a command to install the 'network-scripts' and 'git' packages.

    Returns:
        None
    """
    run_command("yum install -y network-scripts git")


def install_guest_additions() -> None:
    """
    This function performs the following steps:
    1. Installs necessary dependencies using yum and dnf package managers.
    2. Downloads the latest version of VirtualBox Guest Additions ISO.
    3. Mounts the downloaded ISO file.
    4. Runs the VBoxLinuxAdditions script to install the Guest Additions.
    5. Unmounts the ISO file and removes it from the system.
    6. Updates the kernel modules for VirtualBox Guest Additions.

    Returns:
        None
    """
    commands = [
        "yum install -y gcc elfutils-libelf-devel kernel-devel libX11 libXt libXext libXmu",
        "dnf remove $(dnf repoquery --installonly --latest-limit=-1)",
    ]
    run_command(commands)

    kernel_version = os.listdir("/lib/modules")[0]
    vbox_version, _, _ = run_command("wget -q http://download.virtualbox.org/virtualbox/LATEST.TXT -O -", output=True)

    commands = [
        f"wget -nv https://download.virtualbox.org/virtualbox/{vbox_version[0]}/VBoxGuestAdditions_{vbox_version[0]}.iso -O /root/VBoxGuestAdditions.iso",
        "mount -o ro,loop /root/VBoxGuestAdditions.iso /mnt",
    ]
    run_command(commands)

    run_command("sh /mnt/VBoxLinuxAdditions.run")

    run_command("umount /mnt")
    os.remove("/root/VBoxGuestAdditions.iso")

    commands = [f"/etc/kernel/postinst.d/vboxadd {kernel_version}", f"/sbin/depmod {kernel_version}"]
    run_command(commands)


def configure_ssh() -> None:
    """
    Configures the SSH daemon to allow password authentication.
    It then restarts the SSH service to apply the changes.

    Returns:
        None
    """
    sshd_config = "/etc/ssh/sshd_config"
    with open(sshd_config) as file:
        lines = file.readlines()
    with open(sshd_config, "w") as file:
        for line in lines:
            if line.strip() == "#PasswordAuthentication yes" or line.strip() == "PasswordAuthentication no":
                file.write("PasswordAuthentication yes\n")
            else:
                file.write(line)
    run_command("systemctl restart sshd")


def cleanup() -> None:
    """
    This function performs the following cleanup tasks:
    1. Cleans all yum caches.
    2. Removes the yum cache directory.
    3. Deletes the /etc/resolv.conf file if it exists.
    4. Deletes the /setup.py file if it exists.
    5. Fills and removes zero-filled files to free up space.

    Returns:
        None.
    """
    run_command("yum clean all")
    shutil.rmtree("/var/cache/yum", ignore_errors=True)
    if os.path.exists("/etc/resolv.conf"):
        os.remove("/etc/resolv.conf")
    if os.path.exists("/setup.py"):
        os.remove("/setup.py")
    for i in range(1, 3):
        run_command(f"dd if=/dev/zero of=/zero{i} bs=1M")
        run_command(f"rm -f /zero{i}")


def main() -> None:
    """
    Main function to set up the environment.

    This function performs the following steps:
    1. Configures DNS settings.
    2. Sets up the users configuration.
    3. Installs necessary dependencies.
    4. Installs guest additions.
    5. Configures SSH.
    6. Cleans up temporary files and settings.

    Returns:
        None
    """
    configure_dns()
    setup_user()
    install_dependencies()
    install_guest_additions()
    configure_ssh()
    cleanup()


if __name__ == "__main__":
    main()
