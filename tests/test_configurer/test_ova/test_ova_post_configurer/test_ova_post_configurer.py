from pathlib import Path
from unittest.mock import call, mock_open, patch

import pytest

from configurer.ova.ova_post_configurer.ova_post_configurer import (
    SCRIPTS_PATH,
    STATIC_PATH,
    UTILS_PATH,
    WAZUH_STARTER_PATH,
    add_wazuh_starter_service,
    config_grub,
    enable_fips,
    main,
    post_conf_change_ssh_crypto_policies,
    post_conf_clean,
    post_conf_create_network_config,
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
    mock_run_command.assert_called_once_with("sudo hostnamectl set-hostname wazuh-server", check=True)


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


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.set_hostname")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.add_wazuh_starter_service")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.update_jvm_heap")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.enable_fips")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.config_grub")
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.modify_file")
@patch("builtins.open", new_callable=mock_open)
@patch("configurer.ova.ova_post_configurer.ova_post_configurer.json.load")
def test_steps_system_config(
    mock_json_load,
    mock_open,
    mock_modify_file,
    mock_config_grub,
    mock_enable_fips,
    mock_update_jvm_heap,
    mock_add_wazuh_starter_service,
    mock_set_hostname,
    mock_run_command,
):
    mock_json_load.return_value = {"version": "6.0.0", "stage": "alpha0"}

    steps_system_config()

    mock_run_command.assert_any_call("yum upgrade -y")

    mock_config_grub.assert_called_once()

    mock_enable_fips.assert_called_once()

    mock_update_jvm_heap.assert_called_once()

    mock_add_wazuh_starter_service.assert_called_once()

    mock_run_command.assert_any_call("echo 'root:wazuh' | chpasswd")

    mock_set_hostname.assert_called_once()

    mock_modify_file.assert_any_call(
        filepath=Path("/etc/ssh/sshd_config"),
        replacements=[("PermitRootLogin yes", "#PermitRootLogin yes")],
        client=None,
    )
    mock_modify_file.assert_any_call(
        filepath=Path("/etc/ssh/sshd_config"),
        replacements=[("PasswordAuthentication no", "PasswordAuthentication yes")],
        client=None,
    )

    mock_open.assert_any_call("/etc/ssh/sshd_config", "a")
    mock_open.return_value.__enter__().write.assert_called_once_with("\nPermitRootLogin no\n")

    mock_open.assert_any_call("VERSION.json")
    mock_run_command.assert_any_call(f"sudo bash {SCRIPTS_PATH}/messages.sh no 6.0.0-alpha0 wazuh-user")


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
    config_path = "/etc/systemd/network/20-eth1.network"
    expected_content = """[Match]
Name=eth1
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


@patch("configurer.ova.ova_post_configurer.ova_post_configurer.modify_file")
def test_post_conf_clean(mock_modify_file, mock_run_command):
    post_conf_clean()

    mock_run_command.assert_any_call(
        [
            "find /var/log/ -type f -exec bash -c 'cat /dev/null > {}' \\;",
            r"find /var/log/wazuh-indexer -type f -execdir sh -c 'cat /dev/null > \"$1\"' _ {} \;",
            "rm -rf /var/log/wazuh-install.log",
        ]
    )

    mock_run_command.assert_any_call("cat /dev/null > ~/.bash_history && history -c")

    mock_run_command.assert_any_call(
        [
            "sudo yum clean all",
            "sudo rm -rf /var/cache/yum/*",
        ]
    )

    mock_modify_file.assert_called_once_with(
        filepath=Path("/etc/ssh/sshd_config"),
        replacements=[
            (r"^#?AuthorizedKeysCommand.*", ""),
            (r"^#?AuthorizedKeysCommandUser.*", ""),
        ],
        client=None,
    )

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

    mock_run_command.assert_any_call("systemctl stop wazuh-server")

    expected_indexes = [
        "wazuh-alerts-*",
        "wazuh-archives-*",
        "wazuh-states-vulnerabilities-*",
        "wazuh-statistics-*",
        "wazuh-monitoring-*",
    ]
    for index in expected_indexes:
        mock_run_command.assert_any_call(f"curl -u admin:admin -XDELETE 'https://127.0.0.1:9200/{index}' -k")

    mock_run_command.assert_any_call("bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh -ho 127.0.0.1")

    mock_run_command.assert_any_call(
        [
            "systemctl stop wazuh-indexer wazuh-dashboard",
            "systemctl disable wazuh-server",
            "systemctl disable wazuh-dashboard",
        ]
    )

    mock_steps_clean.assert_called_once()

    mock_post_conf_create_network_config.assert_called_once()
    mock_post_conf_change_ssh_crypto_policies.assert_called_once()
    mock_post_conf_clean.assert_called_once()
