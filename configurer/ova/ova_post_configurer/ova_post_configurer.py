import json
import os
import shutil
from pathlib import Path

from configurer.utils import run_command
from generic.helpers import modify_file
from utils import Logger

logger = Logger("OVA PostConfigurer - Main module")

STATIC_PATH = "configurer/ova/ova_post_configurer/static"


def set_hostname() -> None:
    """
    Sets the hostname of the VM to 'wazuh-server'.
    """
    run_command("sudo hostnamectl set-hostname wazuh-server", check=True)


def config_grub() -> None:
    shutil.move(f"{STATIC_PATH}/grub/wazuh.png", "/boot/grub2/")
    shutil.move(f"{STATIC_PATH}/grub/grub", "/etc/default/")
    run_command("grub2-mkconfig -o /boot/grub2/grub.cfg")


def enable_fips() -> None:
    commands = [
        "yum update -y",
        "yum install -y dracut-fips",
        "dracut -f",
        "/sbin/grubby --update-kernel=ALL --args='fips=1'",
    ]
    run_command(commands)


def update_jvm_heap() -> None:
    script_src = f"{STATIC_PATH}/automatic_set_ram.sh"
    script_dest = "/etc/automatic_set_ram.sh"
    service_src = f"{STATIC_PATH}/updateIndexerHeap.service"
    service_dest = "/etc/systemd/system/updateIndexerHeap.service"

    shutil.move(script_src, script_dest)
    os.chmod(script_dest, 0o755)
    shutil.move(service_src, service_dest)
    run_command(["systemctl daemon-reload", "systemctl enable updateIndexerHeap.service"])


def add_wazuh_starter_service() -> None:
    service_src = f"{STATIC_PATH}/wazuh-starter/wazuh-starter.service"
    service_dest = "/etc/systemd/system/wazuh-starter.service"

    timer_src = f"{STATIC_PATH}/wazuh-starter/wazuh-starter.timer"
    timer_dest = "/etc/systemd/system/wazuh-starter.timer"

    script_src = f"{STATIC_PATH}/wazuh-starter/wazuh-starter.sh"
    script_dest = "/etc/.wazuh-starter.sh"

    shutil.move(service_src, service_dest)
    shutil.move(timer_src, timer_dest)
    shutil.move(script_src, script_dest)

    os.chmod(script_dest, 0o755)

    commands = [
        "systemctl daemon-reload",
        "systemctl enable wazuh-starter.timer",
        "systemctl enable wazuh-starter.service",
    ]
    run_command(commands)


def steps_system_config() -> None:
    run_command("yum upgrade -y")

    config_grub()

    enable_fips()

    update_jvm_heap()

    # Not confirmed
    add_wazuh_starter_service()

    # Before it was: sed -i "s/root:.*:/root:\$1\$pNjjEA7K\$USjdNwjfh7A\.vHCf8suK41::0:99999:7:::/g" /etc/shadow
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
    wazuh_version = version + stage
    run_command(f"{STATIC_PATH}/messages.sh no {wazuh_version} wazuh-user")


def steps_clean() -> None:
    commands = [
        "rm -f /securityadmin_demo.sh",
        "yum clean all",
        "systemctl daemon-reload",
        "cat /dev/null > ~/.bash_history && history -c",
    ]
    run_command(commands)


def main() -> None:
    steps_system_config()

    run_command("systemctl stop wazuh-manager")
    indexes = [
        "wazuh-alerts-*",
        "wazuh-archives-*",
        "wazuh-states-vulnerabilities-*",
        "wazuh-statistics-*",
        "wazuh-monitoring-*",
    ]
    for index in indexes:
        run_command(f"curl -u admin:admin -XDELETE 'https://127.0.0.1:9200/{index}' -k")

    run_command("bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1")

    commands = [
        "systemctl stop wazuh-indexer wazuh-dashboard",
        "systemctl disable wazuh-manager",
        "systemctl disable wazuh-dashboard",
    ]
    run_command(commands)

    steps_clean()


if __name__ == "__main__":
    main()
