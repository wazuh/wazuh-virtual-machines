from unittest.mock import call, mock_open, patch

import pytest

from configurer.ova.ova_pre_configurer.setup import (
    VAGRANT_KEY_URL,
    configure_dns,
    configure_ssh,
    install_dependencies,
    install_guest_additions,
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
    # Mock the file existence check to return True
    mock_exists.return_value = True

    # Call the function
    configure_dns()

    # Assert that the file was removed
    mock_remove.assert_called_once_with("/etc/resolv.conf")

    # Assert that the file was opened for writing
    mock_open_file.assert_called_once_with("/etc/resolv.conf", "w")

    # Assert that the correct content was written to the file
    mock_open_file().write.assert_called_once_with("nameserver 8.8.8.8\n")


@patch("os.path.exists")
def test_configure_dns_file_does_not_exist(mock_exists, mock_open_file):
    # Mock the file existence check to return False
    mock_exists.return_value = False

    # Call the function
    configure_dns()

    # Assert that the file was not removed
    mock_open_file.assert_called_once_with("/etc/resolv.conf", "w")

    # Assert that the correct content was written to the file
    mock_open_file().write.assert_called_once_with("nameserver 8.8.8.8\n")


@patch("os.makedirs")
@patch("os.chmod")
def test_setup_user(mock_chmod, mock_makedirs, mock_run_command, mock_open_file):
    # Call the function
    setup_user()

    # Assert that the useradd and password commands were executed
    mock_run_command.assert_any_call(["useradd -m -s /bin/bash wazuh-user", "echo 'wazuh-user:wazuh' | chpasswd"])

    # Assert that the .ssh directory was created
    mock_makedirs.assert_called_once_with("/home/wazuh-user/.ssh", exist_ok=True)

    # Assert that the Vagrant public key was downloaded
    mock_run_command.assert_any_call(f"wget -nv {VAGRANT_KEY_URL} -O /home/wazuh-user/.ssh/authorized_keys")

    # Assert that the permissions for the .ssh directory and authorized_keys file were set
    mock_chmod.assert_has_calls(
        [
            call("/home/wazuh-user/.ssh/authorized_keys", 0o600),
            call("/home/wazuh-user/.ssh", 0o700),
        ]
    )

    # Assert that ownership of the home directory was changed
    mock_run_command.assert_any_call("chown -R wazuh-user:wazuh-user /home/wazuh-user")

    # Assert that the sudoers file was created with the correct content
    mock_open_file.assert_called_once_with("/etc/sudoers.d/wazuh-user", "w")
    mock_open_file().write.assert_called_once_with("wazuh-user ALL=(ALL) NOPASSWD: ALL\n")

    # Assert that the permissions for the sudoers file were set
    mock_chmod.assert_called_with("/etc/sudoers.d/wazuh-user", 0o440)


def test_install_dependencies(mock_run_command):
    # Call the function
    install_dependencies()

    # Assert that the correct command was executed
    mock_run_command.assert_called_once_with("yum install -y network-scripts git")


@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions(mock_remove, mock_listdir, mock_run_command):
    # Mock the kernel version directory
    mock_listdir.return_value = ["5.10.0"]

    # Mock the output of the wget command to fetch the latest VirtualBox version
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
    ]

    # Call the function
    install_guest_additions()

    # Assert that the necessary dependencies were installed
    mock_run_command.assert_any_call(
        [
            "yum install -y gcc elfutils-libelf-devel kernel-devel libX11 libXt libXext libXmu",
            "dnf remove $(dnf repoquery --installonly --latest-limit=-1)",
        ]
    )

    # Assert that the kernel version was retrieved
    mock_listdir.assert_called_once_with("/lib/modules")

    # Assert that the VirtualBox version was fetched
    mock_run_command.assert_any_call("wget -q http://download.virtualbox.org/virtualbox/LATEST.TXT -O -", output=True)

    # Assert that the VBoxGuestAdditions ISO was downloaded
    mock_run_command.assert_any_call(
        [
            "wget -nv https://download.virtualbox.org/virtualbox/7.1.6/VBoxGuestAdditions_7.1.6.iso -O /root/VBoxGuestAdditions.iso",
            "mount -o ro,loop /root/VBoxGuestAdditions.iso /mnt",
        ]
    )

    # Assert that the VBoxLinuxAdditions script was executed
    mock_run_command.assert_any_call("sh /mnt/VBoxLinuxAdditions.run")

    # Assert that the ISO was unmounted and removed
    mock_run_command.assert_any_call("umount /mnt")
    mock_remove.assert_called_once_with("/root/VBoxGuestAdditions.iso")

    # Assert that the kernel modules were updated
    mock_run_command.assert_any_call(["/etc/kernel/postinst.d/vboxadd 5.10.0", "/sbin/depmod 5.10.0"])


@patch("builtins.open", new_callable=mock_open, read_data="PasswordAuthentication no\n")
@patch("configurer.ova.ova_pre_configurer.setup.run_command")
def test_configure_ssh_update_password_authentication(mock_run_command, mock_open_file):
    # Call the function
    configure_ssh()

    # Assert that the sshd_config file was opened for reading and writing
    mock_open_file.assert_any_call("/etc/ssh/sshd_config")
    mock_open_file().write.assert_called_once_with("PasswordAuthentication yes\n")

    # Assert that the SSH service was restarted
    mock_run_command.assert_called_once_with("systemctl restart sshd")


@patch("builtins.open", new_callable=mock_open, read_data="#PasswordAuthentication yes\n")
@patch("configurer.ova.ova_pre_configurer.setup.run_command")
def test_configure_ssh_uncomment_password_authentication(mock_run_command, mock_open_file):
    # Call the function
    configure_ssh()

    # Assert that the sshd_config file was opened for reading and writing
    mock_open_file.assert_any_call("/etc/ssh/sshd_config")
    mock_open_file().write.assert_called_once_with("PasswordAuthentication yes\n")

    # Assert that the SSH service was restarted
    mock_run_command.assert_called_once_with("systemctl restart sshd")


@patch("builtins.open", new_callable=mock_open, read_data="SomeOtherConfig yes\n")
@patch("configurer.ova.ova_pre_configurer.setup.run_command")
def test_configure_ssh_no_changes_needed(mock_run_command, mock_open_file):
    # Call the function
    configure_ssh()

    # Assert that the sshd_config file was opened for reading and writing
    mock_open_file.assert_any_call("/etc/ssh/sshd_config")

    # Assert that no changes were made to the file
    mock_open_file().write.assert_not_called()

    # Assert that the SSH service was restarted
    mock_run_command.assert_called_once_with("systemctl restart sshd")
