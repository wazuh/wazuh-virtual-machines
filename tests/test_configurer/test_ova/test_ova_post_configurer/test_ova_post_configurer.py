from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from configurer.ova.ova_post_configurer.ova_post_configurer import (
    SCRIPTS_PATH,
    STATIC_PATH,
    UTILS_PATH,
    WAZUH_STARTER_PATH,
    add_wazuh_starter_service,
    clean_generated_logs,
    config_grub,
    configure_sshd,
    enable_fips,
    main,
    post_conf_change_ssh_crypto_policies,
    post_conf_clean,
    post_conf_create_network_config,
    post_conf_deactivate_cloud_init,
    post_conf_delete_generated_network_files,
    set_hostname,
    steps_clean,
    steps_system_config,
    update_jvm_heap,
)


@pytest.fixture
def mock_run_command():
    with patch(
        "configurer.ova.ova_post_configurer.ova_post_configurer.run_command"
    ) as mock_ova_post_configurer_run_command:
        yield mock_ova_post_configurer_run_command


@pytest.fixture
def mock_os_path_exists():
    with patch("os.path.exists") as mock_exists:
        yield mock_exists


@pytest.fixture
def mock_os_remove():
    with patch("os.remove") as mock_remove:
        yield mock_remove


@pytest.fixture
def mock_shutil_copy():
    with patch("shutil.copy") as mock_copy:
        yield mock_copy


def test_set_hostname(mock_run_command):
    set_hostname()
    mock_run_command.assert_called_once_with("sudo hostnamectl set-hostname wazuh", check=True)


def test_config_grub(mock_run_command, mock_os_path_exists, mock_os_remove, mock_shutil_copy):
    mock_os_path_exists.side_effect = lambda path: path in [
        "/boot/grub2/wazuh.png",
        "/etc/default/grub",
    ]

    config_grub()

    mock_os_remove.assert_has_calls([call("/boot/grub2/wazuh.png"), call("/etc/default/grub")], any_order=True)

    mock_shutil_copy.assert_has_calls(
        [
            call(f"{STATIC_PATH}/grub/wazuh.png", "/boot/grub2/wazuh.png"),
            call(f"{STATIC_PATH}/grub/grub", "/etc/default/grub"),
        ],
        any_order=True,
    )

    mock_run_command.assert_called_once_with("grub2-mkconfig -o /boot/grub2/grub.cfg")


def test_enable_fips(mock_run_command):
    enable_fips()
    mock_run_command.assert_called_once_with(
        [
            "yum update -y",
            "yum install -y dracut-fips",
            "dracut -f",
            "/sbin/grubby --update-kernel=ALL --args='fips=1'",
        ]
    )


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.os.chmod")
def test_update_jvm_heap(mock_chmod, mock_run_command, mock_os_path_exists, mock_os_remove, mock_shutil_copy):
    mock_os_path_exists.side_effect = lambda path: path in [
        "/etc/automatic_set_ram.sh",
        "/etc/systemd/system/updateIndexerHeap.service",
    ]

    update_jvm_heap()

    mock_os_remove.assert_has_calls(
        [
            call("/etc/automatic_set_ram.sh"),
            call("/etc/systemd/system/updateIndexerHeap.service"),
        ],
        any_order=True,
    )

    mock_shutil_copy.assert_has_calls(
        [
            call(f"{UTILS_PATH}/scripts/automatic_set_ram.sh", "/etc/automatic_set_ram.sh"),
            call(f"{UTILS_PATH}/scripts/updateIndexerHeap.service", "/etc/systemd/system/updateIndexerHeap.service"),
        ],
        any_order=True,
    )

    mock_chmod.assert_called_once_with("/etc/automatic_set_ram.sh", 0o755)

    mock_run_command.assert_called_once_with(["systemctl daemon-reload", "systemctl enable updateIndexerHeap.service"])


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.os.chmod")
def test_add_wazuh_starter_service(mock_chmod, mock_run_command, mock_os_path_exists, mock_os_remove, mock_shutil_copy):
    mock_os_path_exists.side_effect = lambda path: path in [
        "/etc/systemd/system/wazuh-starter.service",
        "/etc/systemd/system/wazuh-starter.timer",
        "/etc/.wazuh-starter.sh",
    ]

    add_wazuh_starter_service()

    mock_os_remove.assert_has_calls(
        [
            call("/etc/systemd/system/wazuh-starter.service"),
            call("/etc/systemd/system/wazuh-starter.timer"),
            call("/etc/.wazuh-starter.sh"),
        ],
        any_order=True,
    )

    mock_shutil_copy.assert_has_calls(
        [
            call(
                f"{WAZUH_STARTER_PATH}/wazuh-starter.service",
                "/etc/systemd/system/wazuh-starter.service",
            ),
            call(
                f"{WAZUH_STARTER_PATH}/wazuh-starter.timer",
                "/etc/systemd/system/wazuh-starter.timer",
            ),
            call(f"{WAZUH_STARTER_PATH}/wazuh-starter.sh", "/etc/.wazuh-starter.sh"),
        ],
        any_order=True,
    )

    mock_chmod.assert_called_once_with("/etc/.wazuh-starter.sh", 0o755)

    mock_run_command.assert_called_once_with(
        [
            "systemctl daemon-reload",
            "systemctl enable wazuh-starter.timer",
            "systemctl enable wazuh-starter.service",
        ]
    )


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.Path")
def test_configure_sshd(mock_path_class):
    # Mock main sshd_config file
    mock_main_config = MagicMock()
    mock_main_config.exists.return_value = True
    mock_main_config.read_text.return_value = (
        "# Some comment\n"
        "PasswordAuthentication no\n"
        "PermitRootLogin yes\n"
        "AuthorizedKeysCommand /usr/bin/some-command\n"
        "OtherSetting value\n"
    )

    # Mock sshd_config.d directory and files
    mock_config_d = MagicMock()
    mock_config_d.is_dir.return_value = True

    mock_conf_file = MagicMock()
    mock_conf_file.exists.return_value = True
    mock_conf_file.read_text.return_value = (
        "PasswordAuthentication no\n"
        "# PermitRootLogin yes\n"
    )

    mock_config_d.glob.return_value = [mock_conf_file]

    # Setup Path mock to return different objects for different calls
    def path_side_effect(arg):
        if arg == "/etc/ssh/sshd_config":
            return mock_main_config
        elif arg == "/etc/ssh/sshd_config.d":
            return mock_config_d
        return MagicMock()

    mock_path_class.side_effect = path_side_effect

    configure_sshd()

    # Verify main config was processed
    mock_main_config.exists.assert_called_once()
    mock_main_config.read_text.assert_called_once()
    assert mock_main_config.write_text.call_count == 1

    # Check the content written to main config
    written_content = mock_main_config.write_text.call_args[0][0]
    assert "PasswordAuthentication yes" in written_content
    assert "PermitRootLogin no" in written_content
    assert "PasswordAuthentication no" not in written_content
    assert "PermitRootLogin yes" not in written_content
    assert "AuthorizedKeysCommand" not in written_content
    assert "OtherSetting value" in written_content

    # Verify sshd_config.d directory was checked
    mock_config_d.is_dir.assert_called_once()
    mock_config_d.glob.assert_called_once_with("*.conf")

    # Verify conf file was processed
    mock_conf_file.exists.assert_called_once()
    mock_conf_file.read_text.assert_called_once()
    assert mock_conf_file.write_text.call_count == 1


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.set_hostname")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.add_wazuh_starter_service")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.update_jvm_heap")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.enable_fips")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.config_grub")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.configure_sshd")
@patch("builtins.open", new_callable=mock_open)
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.json.load")
def test_steps_system_config(
    mock_json_load,
    mock_open_file,
    mock_configure_sshd,
    mock_config_grub,
    mock_enable_fips,
    mock_update_jvm_heap,
    mock_add_wazuh_starter_service,
    mock_set_hostname,
    mock_run_command,
):
    mock_json_load.return_value = {"version": "5.0.0", "stage": "alpha0"}

    steps_system_config()

    mock_run_command.assert_any_call("yum upgrade -y")

    mock_config_grub.assert_called_once()

    mock_enable_fips.assert_called_once()

    mock_update_jvm_heap.assert_called_once()

    mock_add_wazuh_starter_service.assert_called_once()

    mock_run_command.assert_any_call("echo 'root:wazuh' | chpasswd")

    mock_set_hostname.assert_called_once()

    mock_configure_sshd.assert_called_once()

    mock_open_file.assert_any_call("VERSION.json")
    mock_run_command.assert_any_call(f"sudo bash {SCRIPTS_PATH}/messages.sh no 5.0.0-alpha0 wazuh-user")



def test_steps_clean(mock_run_command):
    steps_clean()
    mock_run_command.assert_called_once_with(
        [
            "rm -f /securityadmin_demo.sh",
            "yum clean all",
            "systemctl daemon-reload",
            "cat /dev/null > ~/.bash_history && history -c",
        ]
    )


@patch("builtins.open", new_callable=mock_open)
def test_post_conf_create_network_config(mock_open, mock_run_command):
    config_path = "/etc/systemd/network/20-eth0.network"
    expected_content = """[Match]
Type=ether
[Network]
DHCP=ipv4
"""

    post_conf_create_network_config(config_path=config_path)

    mock_open.assert_called_once_with(config_path, "w")

    mock_open.return_value.__enter__().write.assert_called_once_with(expected_content)

    mock_run_command.assert_called_once_with("systemctl restart systemd-networkd")


def test_post_conf_change_ssh_crypto_policies(mock_run_command):
    config_path = "/etc/crypto-policies/back-ends/opensshserver.config"
    existing_content = (
        "Ciphers old-cipher\n"
        "MACs old-mac\n"
        "GSSAPIKexAlgorithms old-gss\n"
        "KexAlgorithms old-kex\n"
        "OtherSetting some-value\n"
    )
    expected_content = (
        "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com\n"
        "MACs hmac-sha2-256,hmac-sha2-512\n"
        "GSSAPIKexAlgorithms gss-nistp256-sha256-,gss-group14-sha256-,gss-group16-sha512-\n"
        "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521\n"
        "OtherSetting some-value\n"
    )

    m = mock_open(read_data=existing_content)

    with patch("builtins.open", m):
        post_conf_change_ssh_crypto_policies(config_path=config_path)

    m.assert_any_call(config_path)
    m.assert_any_call(config_path, "w")

    handle = m()
    written_content = "".join(call.args[0] for call in handle.write.call_args_list)
    assert written_content == expected_content

    mock_run_command.assert_called_once_with("systemctl restart sshd")


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.Path")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.shutil.rmtree")
def test_post_conf_deactivate_cloud_init(mock_rmtree, mock_path, mock_run_command):
    mock_cloud_init_disabled = mock_path.return_value
    mock_config_file_path = mock_path.return_value

    post_conf_deactivate_cloud_init()

    mock_run_command.assert_called_once_with("sudo cloud-init clean --logs")

    mock_rmtree.assert_called_once_with("/var/lib/cloud", ignore_errors=True)

    assert mock_path.call_count == 2
    mock_path.assert_any_call("/etc/cloud/cloud-init.disabled")
    mock_path.assert_any_call("/etc/cloud/cloud.cfg.d/99-amazon-override.cfg")

    mock_cloud_init_disabled.touch.assert_called_once()

    expected_content = """
network:
  config: disabled
"""
    mock_config_file_path.write_text.assert_called_once_with(expected_content)


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.Path")
def test_post_conf_delete_generated_network_files(mock_path):
    mock_network_dir = MagicMock()
    mock_path.return_value = mock_network_dir

    mock_cloud_init_file1 = MagicMock()
    mock_cloud_init_file2 = MagicMock()
    mock_vagrant_file = MagicMock()

    mock_network_dir.glob.side_effect = [
        [mock_cloud_init_file1, mock_cloud_init_file2],
        [mock_vagrant_file],
    ]

    post_conf_delete_generated_network_files()

    mock_path.assert_called_once_with("/etc/systemd/network/")

    assert mock_network_dir.glob.call_count == 2
    mock_network_dir.glob.assert_any_call("10-cloud-init-*.network")
    mock_network_dir.glob.assert_any_call("*vagrant*.network")

    mock_cloud_init_file1.unlink.assert_called_once_with(missing_ok=True)
    mock_cloud_init_file2.unlink.assert_called_once_with(missing_ok=True)
    mock_vagrant_file.unlink.assert_called_once_with(missing_ok=True)


@patch("builtins.open", new_callable=mock_open)
def test_clean_generated_logs(mock_file_open):
    # Mock directories
    mock_log_dir = MagicMock()
    mock_log_dir.is_dir.return_value = True

    mock_indexer_dir = MagicMock()
    mock_indexer_dir.is_dir.return_value = True

    mock_manager_dir = MagicMock()
    mock_manager_dir.is_dir.return_value = False

    mock_agent_dir = MagicMock()
    mock_agent_dir.is_dir.return_value = True

    mock_dashboard_dir = MagicMock()
    mock_dashboard_dir.is_dir.return_value = False

    # Mock files in directories
    mock_file1 = MagicMock()
    mock_file1.is_file.return_value = True

    mock_file2 = MagicMock()
    mock_file2.is_file.return_value = True

    mock_subdir = MagicMock()
    mock_subdir.is_file.return_value = False

    mock_log_dir.rglob.return_value = [mock_file1, mock_subdir]
    mock_indexer_dir.rglob.return_value = [mock_file2]
    mock_agent_dir.rglob.return_value = []

    clean_generated_logs(
        log_directory_path=mock_log_dir,
        wazuh_indexer_log_path=mock_indexer_dir,
        wazuh_manager_log_path=mock_manager_dir,
        wazuh_agent_log_path=mock_agent_dir,
        wazuh_dashboard_log_path=mock_dashboard_dir,
    )

    # Verify directories were checked
    mock_log_dir.is_dir.assert_called()
    mock_indexer_dir.is_dir.assert_called()
    mock_manager_dir.is_dir.assert_called()
    mock_agent_dir.is_dir.assert_called()
    mock_dashboard_dir.is_dir.assert_called()

    # Verify rglob was called on existing directories
    mock_log_dir.rglob.assert_called_once_with("*")
    mock_indexer_dir.rglob.assert_called_once_with("*")
    mock_agent_dir.rglob.assert_called_once_with("*")

    # Verify files were opened and truncated
    assert mock_file_open.call_count == 2  # Only for files, not subdirs
    mock_file_open.assert_any_call(mock_file1, "w")
    mock_file_open.assert_any_call(mock_file2, "w")

    # Verify truncate was called
    mock_file_handle = mock_file_open.return_value.__enter__.return_value
    assert mock_file_handle.truncate.call_count == 2


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.configure_sshd")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.clean_generated_logs")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.post_conf_deactivate_cloud_init")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.post_conf_delete_generated_network_files")
def test_post_conf_clean(
    mock_post_conf_delete_generated_network_files,
    mock_post_conf_deactivate_cloud_init,
    mock_clean_generated_logs,
    mock_configure_sshd,
    mock_run_command,
):
    post_conf_clean()

    mock_post_conf_deactivate_cloud_init.assert_called_once()
    mock_post_conf_delete_generated_network_files.assert_called_once()
    mock_clean_generated_logs.assert_called_once()

    mock_run_command.assert_any_call("cat /dev/null > ~/.bash_history && history -c")

    mock_run_command.assert_any_call(
        [
            "sudo yum clean all",
            "sudo rm -rf /var/cache/yum/*",
        ]
    )

    mock_configure_sshd.assert_called_once()

    mock_run_command.assert_any_call("sudo systemctl restart sshd")


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.steps_system_config")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.steps_clean")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.post_conf_create_network_config")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.post_conf_change_ssh_crypto_policies")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.post_conf_clean")
def test_main(
    mock_post_conf_clean,
    mock_post_conf_change_ssh_crypto_policies,
    mock_post_conf_create_network_config,
    mock_steps_clean,
    mock_steps_system_config,
    mock_run_command,
):
    main()

    mock_steps_system_config.assert_called_once()

    mock_run_command.assert_any_call("systemctl stop wazuh-manager")
    mock_run_command.assert_any_call("systemctl stop wazuh-agent")

    mock_run_command.assert_any_call("curl -u admin:admin -XDELETE 'https://127.0.0.1:9200/wazuh-*' -k")

    mock_run_command.assert_any_call("bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1")

    mock_run_command.assert_any_call(
        [
            "systemctl stop wazuh-indexer wazuh-dashboard",
            "systemctl disable wazuh-manager",
            "systemctl disable wazuh-agent",
            "systemctl disable wazuh-dashboard",
        ]
    )

    mock_steps_clean.assert_called_once()

    mock_post_conf_create_network_config.assert_called_once()
    mock_post_conf_change_ssh_crypto_policies.assert_called_once()
    mock_post_conf_clean.assert_called_once()
