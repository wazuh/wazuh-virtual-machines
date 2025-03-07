import os
import shutil
import subprocess

from configurer.utils import run_command
from utils import Logger

logger = Logger("log")

def configure_dns():
    resolv_conf = "/etc/resolv.conf"
    if os.path.exists(resolv_conf):
        os.remove(resolv_conf)
    with open(resolv_conf, "w") as f:
        f.write("nameserver 8.8.8.8\n")
        
def setup_user():
    commands = [
        ["useradd", "-m", "-s", "/bin/bash", "wazuh-user"],
        ["echo", "wazuh-user:wazuh" "|", "chpasswd"]
    ]
    run_command(commands)
    os.makedirs("/home/wazuh-user/.ssh", exist_ok=True)
    
    vagrant_key_url = "https://raw.githubusercontent.com/hashicorp/vagrant/main/keys/vagrant.pub"
    commands = [
        ["wget", "-nv", vagrant_key_url, "-O", "/home/wazuh-user/.ssh/authorized_keys"],
    ]
    run_command(commands)
    
    os.chmod("/home/wazuh-user/.ssh/authorized_keys", 0o600)
    os.chmod("/home/wazuh-user/.ssh", 0o700)
    
    commands = [
        ["chown", "-R", "wazuh-user:wazuh-user", "/home/wazuh-user"]
    ]
    run_command(commands)
    
    with open("/etc/sudoers.d/wazuh-user", "w") as f:
        f.write("wazuh-user ALL=(ALL) NOPASSWD: ALL\n")
    os.chmod("/etc/sudoers.d/wazuh-user", 0o440)
    
def install_dependencies():
    commands = [
        ["yum", "install", "-y", "network-scripts","git"]
    ]
    run_command(commands)
    
def install_guest_additions():
    commands = [
        ["yum", "install", "-y", "gcc", "elfutils-libelf-devel", "kernel-devel", "libX11", "libXt", "libXext", "libXmu"],
        ["dnf", "remove", "$(dnf", "repoquery", "--installonly", "--latest-limit=-1)"]
    ]
    run_command(commands)
    
    kernel_version = os.listdir("/lib/modules")[0]
    vbox_version = subprocess.getoutput("wget -q http://download.virtualbox.org/virtualbox/LATEST.TXT -O -")
    
    commands = [
        ["wget", "-nv", f"https://download.virtualbox.org/virtualbox/{vbox_version}/VBoxGuestAdditions_{vbox_version}.iso", "-O", "/root/VBoxGuestAdditions.iso"],
        ["mount", "-o", "ro,loop", "/root/VBoxGuestAdditions.iso", "/mnt"]
    ]
    run_command(commands)
    
    commands = [
        ["sh", "/mnt/VBoxLinuxAdditions.run"],
    ]
    run_command("sh /mnt/VBoxLinuxAdditions.run", check=False)
    
    commands = [
        ["umount", "/mnt"],
    ]
    run_command(commands)
    os.remove("/root/VBoxGuestAdditions.iso")
    
    commands = [
        ["/etc/kernel/postinst.d/vboxadd", kernel_version],
        ["/sbin/depmod", kernel_version]
    ]
    run_command(commands)

def configure_ssh():
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

def cleanup():
    run_command("yum clean all")
    shutil.rmtree("/var/cache/yum", ignore_errors=True)
    if os.path.exists("/etc/resolv.conf"):
        os.remove("/etc/resolv.conf")
    if os.path.exists("/setup.sh"):
        os.remove("/setup.sh")
    for i in range(1, 3):
        run_command(f"dd if=/dev/zero of=/zero{i} bs=1M", check=False)
        run_command(f"rm -f /zero{i}")

def main():
    configure_dns()
    setup_user()
    install_dependencies()
    install_guest_additions()
    configure_ssh()
    cleanup()

if __name__ == "__main__":
    main()
