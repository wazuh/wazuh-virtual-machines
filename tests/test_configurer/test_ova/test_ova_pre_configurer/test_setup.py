from unittest.mock import call, mock_open, patch

import pytest

from configurer.ova.ova_pre_configurer.setup import (
    VAGRANT_KEY_URL,
    cleanup,
    configure_dns,
    configure_ssh,
    install_dependencies,
    install_guest_additions,
    main,
    setup_user,
)


@pytest.fixture
def mock_run_command():
    with patch("configurer.ova.ova_pre_configurer.setup.run_command") as mock_setup_run_command:
        yield mock_setup_run_command


@pytest.fixture
def mock_open_file():
    with patch("builtins.open", new_callable=mock_open) as mock_open_file:
        yield mock_open_file


@patch("os.path.exists")
@patch("os.remove")
def test_configure_dns_file_exists(mock_remove, mock_exists, mock_open_file):
    mock_exists.return_value = True

    configure_dns()

    mock_remove.assert_called_once_with("/etc/resolv.conf")

    mock_open_file.assert_called_once_with("/etc/resolv.conf", "w")

    mock_open_file().write.assert_called_once_with("nameserver 8.8.8.8\n")


@patch("os.path.exists")
def test_configure_dns_file_does_not_exist(mock_exists, mock_open_file):
    mock_exists.return_value = False

    configure_dns()

    mock_open_file.assert_called_once_with("/etc/resolv.conf", "w")

    mock_open_file().write.assert_called_once_with("nameserver 8.8.8.8\n")


@patch("os.makedirs")
@patch("os.chmod")
def test_setup_user(mock_chmod, mock_makedirs, mock_run_command, mock_open_file):
    setup_user()

    mock_run_command.assert_any_call(["useradd -m -s /bin/bash wazuh-user", "echo 'wazuh-user:wazuh' | chpasswd"])

    mock_makedirs.assert_called_once_with("/home/wazuh-user/.ssh", exist_ok=True)

    mock_run_command.assert_any_call(f"wget -nv {VAGRANT_KEY_URL} -O /home/wazuh-user/.ssh/authorized_keys")

    mock_chmod.assert_has_calls(
        [
            call("/home/wazuh-user/.ssh/authorized_keys", 0o600),
            call("/home/wazuh-user/.ssh", 0o700),
        ]
    )

    mock_run_command.assert_any_call("chown -R wazuh-user:wazuh-user /home/wazuh-user")

    mock_open_file.assert_called_once_with("/etc/sudoers.d/wazuh-user", "w")
    mock_open_file().write.assert_called_once_with("wazuh-user ALL=(ALL) NOPASSWD: ALL\n")

    mock_chmod.assert_called_with("/etc/sudoers.d/wazuh-user", 0o440)


def test_install_dependencies(mock_run_command):
    install_dependencies()

    mock_run_command.assert_called_once_with("yum install -y network-scripts git")


@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions(mock_remove, mock_listdir, mock_run_command):
    mock_listdir.return_value = ["5.10.0"]

    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
    ]

    install_guest_additions()

    mock_run_command.assert_any_call(
        [
            "yum install -y gcc elfutils-libelf-devel kernel-devel libX11 libXt libXext libXmu",
            "dnf remove $(dnf repoquery --installonly --latest-limit=-1)",
        ]
    )

    mock_listdir.assert_called_once_with("/lib/modules")

    mock_run_command.assert_any_call("wget -q http://download.virtualbox.org/virtualbox/LATEST.TXT -O -", output=True)

    mock_run_command.assert_any_call(
        [
            "wget -nv https://download.virtualbox.org/virtualbox/7.1.6/VBoxGuestAdditions_7.1.6.iso -O /root/VBoxGuestAdditions.iso",
            "mount -o ro,loop /root/VBoxGuestAdditions.iso /mnt",
        ]
    )

    mock_run_command.assert_any_call("sh /mnt/VBoxLinuxAdditions.run")

    mock_run_command.assert_any_call("umount /mnt")
    mock_remove.assert_called_once_with("/root/VBoxGuestAdditions.iso")

    mock_run_command.assert_any_call(["/etc/kernel/postinst.d/vboxadd 5.10.0", "/sbin/depmod 5.10.0"])


@patch("builtins.open", new_callable=mock_open, read_data="PasswordAuthentication no\n")
def test_configure_ssh_update_password_authentication(mock_open_file, mock_run_command):
    configure_ssh()

    mock_open_file.assert_any_call("/etc/ssh/sshd_config")
    mock_open_file().write.assert_called_once_with("PasswordAuthentication yes\n")

    mock_run_command.assert_called_once_with("systemctl restart sshd")


@patch("builtins.open", new_callable=mock_open, read_data="#PasswordAuthentication yes\n")
def test_configure_ssh_uncomment_password_authentication(mock_open_file, mock_run_command):
    configure_ssh()

    mock_open_file.assert_any_call("/etc/ssh/sshd_config")
    mock_open_file().write.assert_called_once_with("PasswordAuthentication yes\n")

    mock_run_command.assert_called_once_with("systemctl restart sshd")


@patch("builtins.open", new_callable=mock_open, read_data="OtherConfiguration yes\n")
def test_configure_ssh_no_password_authentication(mock_open_file, mock_run_command):
    configure_ssh()

    mock_open_file.assert_any_call("/etc/ssh/sshd_config")
    mock_open_file().write.assert_called_once_with("OtherConfiguration yes\n")

    mock_run_command.assert_called_once_with("systemctl restart sshd")


@patch("os.path.exists")
@patch("os.remove")
@patch("shutil.rmtree")
def test_cleanup(mock_rmtree, mock_remove, mock_exists, mock_run_command):
    mock_exists.side_effect = lambda path: path in ["/etc/resolv.conf", "/setup.py"]

    cleanup()

    mock_run_command.assert_any_call("yum clean all")

    mock_rmtree.assert_called_once_with("/var/cache/yum", ignore_errors=True)

    mock_remove.assert_any_call("/etc/resolv.conf")

    mock_remove.assert_any_call("/setup.py")

    mock_run_command.assert_any_call("dd if=/dev/zero of=/zero1 bs=1M")
    mock_run_command.assert_any_call("rm -f /zero1")
    mock_run_command.assert_any_call("dd if=/dev/zero of=/zero2 bs=1M")
    mock_run_command.assert_any_call("rm -f /zero2")


@patch("configurer.ova.ova_pre_configurer.setup.cleanup")
@patch("configurer.ova.ova_pre_configurer.setup.configure_ssh")
@patch("configurer.ova.ova_pre_configurer.setup.install_guest_additions")
@patch("configurer.ova.ova_pre_configurer.setup.install_dependencies")
@patch("configurer.ova.ova_pre_configurer.setup.setup_user")
@patch("configurer.ova.ova_pre_configurer.setup.configure_dns")
def test_main(
    mock_configure_dns,
    mock_setup_user,
    mock_install_dependencies,
    mock_install_guest_additions,
    mock_configure_ssh,
    mock_cleanup,
):
    main()

    mock_configure_dns.assert_called_once()
    mock_setup_user.assert_called_once()
    mock_install_dependencies.assert_called_once()
    mock_install_guest_additions.assert_called_once()
    mock_configure_ssh.assert_called_once()
    mock_cleanup.assert_called_once()
