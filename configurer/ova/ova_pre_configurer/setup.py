import os
import shutil
import sys

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

    commands = [
        "/sbin/modprobe vboxguest",
        "/sbin/modprobe vboxsf",
        "/sbin/modprobe vboxvideo",
    ]
    run_command(commands)

    stdout, stderr, return_code = run_command("lsmod | grep -q vboxguest", check=False, output=True)
    if return_code[0] != 0:
        vboxguest_path = f"/lib/modules/{kernel_version}/misc/vboxguest.ko"
        if not os.path.isfile(vboxguest_path):
            sys.exit(1)
        has_vboxadd_service = os.path.isfile("/etc/init.d/vboxadd") or os.path.isfile(
            "/usr/lib/systemd/system/vboxadd.service"
        )
        if not has_vboxadd_service:
            sys.exit(1)

    if os.path.isfile("/usr/lib/systemd/system/vboxadd.service"):
        commands = [
            "mkdir -p /etc/systemd/system/multi-user.target.wants",
            "ln -sf /usr/lib/systemd/system/vboxadd.service /etc/systemd/system/multi-user.target.wants/vboxadd.service",
            "ln -sf /usr/lib/systemd/system/vboxadd-service.service /etc/systemd/system/multi-user.target.wants/vboxadd-service.service",
        ]
        run_command(commands)

    if not os.path.isfile("/etc/rc.d/rc.local"):
        commands = [
            "touch /etc/rc.d/rc.local",
            "chmod +x /etc/rc.d/rc.local",
        ]
        run_command(commands)

    rc_local_block = (
        "# VirtualBox Guest Additions - ensure modules are loaded\n"
        "if [ -f /etc/init.d/vboxadd ]; then\n"
        "    /etc/init.d/vboxadd start || true\n"
        "fi\n"
    )
    with open("/etc/rc.d/rc.local", "a+", encoding="utf-8") as rc_file:
        rc_file.seek(0)
        content = rc_file.read()
        if "# VirtualBox Guest Additions - ensure modules are loaded" not in content:
            rc_file.write(rc_local_block)
    run_command("chmod +x /etc/rc.d/rc.local")

    if os.path.isfile("/usr/lib/systemd/system/rc-local.service"):
        run_command(
            "ln -sf /usr/lib/systemd/system/rc-local.service /etc/systemd/system/multi-user.target.wants/rc-local.service"
        )


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

    sshd_override_dir = "/etc/ssh/sshd_config.d"
    sshd_override_file = os.path.join(sshd_override_dir, "50-vagrant-password-auth.conf")
    if not os.path.isdir(sshd_override_dir):
        run_command(f"mkdir -p {sshd_override_dir}")
    override_content = "PasswordAuthentication yes\nPubkeyAuthentication yes\nChallengeResponseAuthentication no\n"
    with open(sshd_override_file, "w", encoding="utf-8") as f:
        f.write(override_content)
    run_command(f"chmod 600 {sshd_override_file}")
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
