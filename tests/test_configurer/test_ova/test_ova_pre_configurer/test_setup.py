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


@patch("os.path.isfile")
@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions_success_vboxguest_loaded(mock_remove, mock_listdir, mock_isfile, mock_run_command, mock_open_file):
    mock_listdir.return_value = ["5.10.0"]
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, [0]),
        (None, None, None),
        (None, None, None),
    ]
    
    def isfile_side_effect(path):
        if path == "/etc/rc.d/rc.local" or path == "/usr/lib/systemd/system/rc-local.service":
            return False
        return False
    
    mock_isfile.side_effect = isfile_side_effect
    mock_open_file.return_value.read.return_value = ""
    
    install_guest_additions()
    
    mock_run_command.assert_any_call([
        "yum install -y gcc elfutils-libelf-devel kernel-devel libX11 libXt libXext libXmu",
        "dnf remove $(dnf repoquery --installonly --latest-limit=-1)",
    ])
    mock_run_command.assert_any_call("wget -q http://download.virtualbox.org/virtualbox/LATEST.TXT -O -", output=True)
    mock_run_command.assert_any_call("lsmod | grep -q vboxguest", check=False, output=True)
    mock_remove.assert_called_once_with("/root/VBoxGuestAdditions.iso")


@patch("os.path.isfile")
@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions_vboxguest_check_failure_missing_ko_file(mock_remove, mock_listdir, mock_isfile, mock_run_command):
    mock_listdir.return_value = ["5.10.0"]
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, [1]),
    ]
    mock_isfile.return_value = False

    with patch("sys.exit", side_effect=lambda code: (_ for _ in ()).throw(SystemExit(code))) as mock_exit:
        with pytest.raises(SystemExit) as exc:
            install_guest_additions()
        assert exc.value.code == 1
        mock_isfile.assert_any_call("/lib/modules/5.10.0/misc/vboxguest.ko")
        mock_exit.assert_called_once_with(1)


@patch("os.path.isfile")
@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions_vboxguest_check_failure_missing_service(mock_remove, mock_listdir, mock_isfile, mock_run_command):
    mock_listdir.return_value = ["5.10.0"]
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, [1]),
    ]

    def isfile_side_effect(path):
        if path == "/lib/modules/5.10.0/misc/vboxguest.ko":
            return True
        if path in ("/etc/init.d/vboxadd", "/usr/lib/systemd/system/vboxadd.service"):
            return False
        return False
    mock_isfile.side_effect = isfile_side_effect

    with patch("sys.exit", side_effect=lambda code: (_ for _ in ()).throw(SystemExit(code))) as mock_exit:
        with pytest.raises(SystemExit) as exc:
            install_guest_additions()
        assert exc.value.code == 1
        mock_isfile.assert_any_call("/lib/modules/5.10.0/misc/vboxguest.ko")
        mock_isfile.assert_any_call("/etc/init.d/vboxadd")
        mock_isfile.assert_any_call("/usr/lib/systemd/system/vboxadd.service")
        mock_exit.assert_called_once_with(1)

@patch("os.path.isfile")
@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions_vboxguest_check_passes_with_init_service(mock_remove, mock_listdir, mock_isfile, mock_run_command, mock_open_file):
    mock_listdir.return_value = ["5.10.0"]
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, [1]),
        (None, None, None),
        (None, None, None),
    ]
    
    def isfile_side_effect(path):
        if path == "/lib/modules/5.10.0/misc/vboxguest.ko" or path == "/etc/init.d/vboxadd":
            return True
        elif path == "/usr/lib/systemd/system/vboxadd.service" or path == "/etc/rc.d/rc.local" or path == "/usr/lib/systemd/system/rc-local.service":
            return False
        return False
    
    mock_isfile.side_effect = isfile_side_effect
    mock_open_file.return_value.read.return_value = ""
    
    install_guest_additions()
    
    mock_isfile.assert_any_call("/lib/modules/5.10.0/misc/vboxguest.ko")
    mock_isfile.assert_any_call("/etc/init.d/vboxadd")

@patch("os.path.isfile")
@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions_vboxguest_check_passes_with_systemd_service(mock_remove, mock_listdir, mock_isfile, mock_run_command, mock_open_file):
    mock_listdir.return_value = ["5.10.0"]
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, [1]),
        (None, None, None),
        (None, None, None),
        (None, None, None),
    ]
    
    def isfile_side_effect(path):
        if path == "/lib/modules/5.10.0/misc/vboxguest.ko":
            return True
        elif path == "/etc/init.d/vboxadd":
            return False
        elif path == "/usr/lib/systemd/system/vboxadd.service":
            return True
        elif path == "/etc/rc.d/rc.local" or path == "/usr/lib/systemd/system/rc-local.service":
            return False
        return False
    
    mock_isfile.side_effect = isfile_side_effect
    mock_open_file.return_value.read.return_value = ""
    
    install_guest_additions()
    
    mock_isfile.assert_any_call("/lib/modules/5.10.0/misc/vboxguest.ko")
    mock_isfile.assert_any_call("/usr/lib/systemd/system/vboxadd.service")
    mock_run_command.assert_any_call([
        "mkdir -p /etc/systemd/system/multi-user.target.wants",
        "ln -sf /usr/lib/systemd/system/vboxadd.service /etc/systemd/system/multi-user.target.wants/vboxadd.service",
        "ln -sf /usr/lib/systemd/system/vboxadd-service.service /etc/systemd/system/multi-user.target.wants/vboxadd-service.service",
    ])

@patch("os.path.isfile")
@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions_rc_local_exists_with_content(mock_remove, mock_listdir, mock_isfile, mock_run_command, mock_open_file):
    mock_listdir.return_value = ["5.10.0"]
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, [0]),
        (None, None, None),
    ]
    
    def isfile_side_effect(path):
        if path == "/etc/rc.d/rc.local":
            return True
        elif path == "/usr/lib/systemd/system/rc-local.service":
            return False
        return False
    
    mock_isfile.side_effect = isfile_side_effect
    mock_open_file.return_value.read.return_value = "# VirtualBox Guest Additions - ensure modules are loaded\n"
    
    install_guest_additions()
    
    mock_run_command.assert_any_call("chmod +x /etc/rc.d/rc.local")

@patch("os.path.isfile")
@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions_with_rc_local_service(mock_remove, mock_listdir, mock_isfile, mock_run_command, mock_open_file):
    mock_listdir.return_value = ["5.10.0"]
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, [0]),
        (None, None, None),
        (None, None, None),
        (None, None, None),
    ]
    
    def isfile_side_effect(path):
        if path == "/etc/rc.d/rc.local":
            return False
        elif path == "/usr/lib/systemd/system/rc-local.service":
            return True
        return False
    
    mock_isfile.side_effect = isfile_side_effect
    mock_open_file.return_value.read.return_value = ""
    
    install_guest_additions()
    
    mock_run_command.assert_any_call("ln -sf /usr/lib/systemd/system/rc-local.service /etc/systemd/system/multi-user.target.wants/rc-local.service")

@patch("os.path.isfile")
@patch("os.listdir")
@patch("os.remove")
def test_install_guest_additions_complete_systemd_scenario(mock_remove, mock_listdir, mock_isfile, mock_run_command, mock_open_file):
    mock_listdir.return_value = ["5.10.0"]
    mock_run_command.side_effect = [
        (None, None, None),
        (["7.1.6"], None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, [1]),
        (None, None, None),
        (None, None, None),
        (None, None, None),
        (None, None, None),
    ]
    
    def isfile_side_effect(path):
        mapping = {
            "/lib/modules/5.10.0/misc/vboxguest.ko": True,
            "/etc/init.d/vboxadd": False,
            "/usr/lib/systemd/system/vboxadd.service": True,
            "/etc/rc.d/rc.local": False,
            "/usr/lib/systemd/system/rc-local.service": True
        }
        return mapping.get(path, False)
    
    mock_isfile.side_effect = isfile_side_effect
    mock_open_file.return_value.read.return_value = ""
    
    install_guest_additions()
    
    mock_run_command.assert_any_call([
        "mkdir -p /etc/systemd/system/multi-user.target.wants",
        "ln -sf /usr/lib/systemd/system/vboxadd.service /etc/systemd/system/multi-user.target.wants/vboxadd.service",
        "ln -sf /usr/lib/systemd/system/vboxadd-service.service /etc/systemd/system/multi-user.target.wants/vboxadd-service.service",
    ])
    
    mock_run_command.assert_any_call("ln -sf /usr/lib/systemd/system/rc-local.service /etc/systemd/system/multi-user.target.wants/rc-local.service")
    
    mock_open_file.assert_any_call("/etc/rc.d/rc.local", "a+", encoding="utf-8")    


@patch("os.path.isdir")
@patch("os.path.join")
@patch("builtins.open", new_callable=mock_open, read_data="PasswordAuthentication no\n")
def test_configure_ssh_update_password_authentication(mock_open_file, mock_join, mock_isdir, mock_run_command):
    mock_isdir.return_value = True
    mock_join.return_value = "/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf"
    
    mock_sshd_config = mock_open(read_data="PasswordAuthentication no\n")
    mock_override_file = mock_open()
    
    def open_side_effect(filename, *args, **kwargs):
        if filename == "/etc/ssh/sshd_config":
            return mock_sshd_config.return_value
        elif filename == "/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf":
            return mock_override_file.return_value
        else:
            return mock_open_file.return_value
    
    mock_open_file.side_effect = open_side_effect
    
    configure_ssh()

    mock_open_file.assert_any_call("/etc/ssh/sshd_config")
    
    mock_sshd_config().write.assert_any_call("PasswordAuthentication yes\n")
    
    mock_open_file.assert_any_call("/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf", "w", encoding="utf-8")
    
    expected_override_content = (
        "PasswordAuthentication yes\n"
        "PubkeyAuthentication yes\n"
        "ChallengeResponseAuthentication no\n"
    )
    mock_override_file().write.assert_called_once_with(expected_override_content)
    
    mock_run_command.assert_any_call("chmod 600 /etc/ssh/sshd_config.d/50-vagrant-password-auth.conf")
    mock_run_command.assert_any_call("systemctl restart sshd")


@patch("os.path.isdir")
@patch("os.path.join")
@patch("builtins.open", new_callable=mock_open, read_data="#PasswordAuthentication yes\n")
def test_configure_ssh_uncomment_password_authentication(mock_open_file, mock_join, mock_isdir, mock_run_command):
    mock_isdir.return_value = True
    mock_join.return_value = "/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf"
    
    mock_sshd_config = mock_open(read_data="#PasswordAuthentication yes\n")
    mock_override_file = mock_open()
    
    def open_side_effect(filename, *args, **kwargs):
        if filename == "/etc/ssh/sshd_config":
            return mock_sshd_config.return_value
        elif filename == "/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf":
            return mock_override_file.return_value
        else:
            return mock_open_file.return_value
    
    mock_open_file.side_effect = open_side_effect
    
    configure_ssh()

    mock_open_file.assert_any_call("/etc/ssh/sshd_config")
    mock_sshd_config().write.assert_any_call("PasswordAuthentication yes\n")
    
    mock_open_file.assert_any_call("/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf", "w", encoding="utf-8")
    
    expected_override_content = (
        "PasswordAuthentication yes\n"
        "PubkeyAuthentication yes\n"
        "ChallengeResponseAuthentication no\n"
    )
    mock_override_file().write.assert_called_once_with(expected_override_content)
    
    mock_run_command.assert_any_call("chmod 600 /etc/ssh/sshd_config.d/50-vagrant-password-auth.conf")
    mock_run_command.assert_any_call("systemctl restart sshd")


@patch("os.path.isdir")
@patch("os.path.join")
@patch("builtins.open", new_callable=mock_open, read_data="OtherConfiguration yes\n")
def test_configure_ssh_no_password_authentication(mock_open_file, mock_join, mock_isdir, mock_run_command):
    mock_isdir.return_value = True
    mock_join.return_value = "/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf"
    
    mock_sshd_config = mock_open(read_data="OtherConfiguration yes\n")
    mock_override_file = mock_open()
    
    def open_side_effect(filename, *args, **kwargs):
        if filename == "/etc/ssh/sshd_config":
            return mock_sshd_config.return_value
        elif filename == "/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf":
            return mock_override_file.return_value
        else:
            return mock_open_file.return_value
    
    mock_open_file.side_effect = open_side_effect
    
    configure_ssh()

    mock_open_file.assert_any_call("/etc/ssh/sshd_config")
    mock_sshd_config().write.assert_any_call("OtherConfiguration yes\n")
    
    mock_open_file.assert_any_call("/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf", "w", encoding="utf-8")
    
    expected_override_content = (
        "PasswordAuthentication yes\n"
        "PubkeyAuthentication yes\n"
        "ChallengeResponseAuthentication no\n"
    )
    mock_override_file().write.assert_called_once_with(expected_override_content)
    
    mock_run_command.assert_any_call("chmod 600 /etc/ssh/sshd_config.d/50-vagrant-password-auth.conf")
    mock_run_command.assert_any_call("systemctl restart sshd")


@patch("os.path.isdir")
@patch("os.path.join")
@patch("builtins.open", new_callable=mock_open, read_data="PasswordAuthentication no\n")
def test_configure_ssh_creates_sshd_config_dir(mock_open_file, mock_join, mock_isdir, mock_run_command):
    mock_isdir.return_value = False
    mock_join.return_value = "/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf"
    
    mock_sshd_config = mock_open(read_data="PasswordAuthentication no\n")
    mock_override_file = mock_open()
    
    def open_side_effect(filename, *args, **kwargs):
        if filename == "/etc/ssh/sshd_config":
            return mock_sshd_config.return_value
        elif filename == "/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf":
            return mock_override_file.return_value
        else:
            return mock_open_file.return_value
    
    mock_open_file.side_effect = open_side_effect
    
    configure_ssh()

    mock_run_command.assert_any_call("mkdir -p /etc/ssh/sshd_config.d")
    
    mock_open_file.assert_any_call("/etc/ssh/sshd_config.d/50-vagrant-password-auth.conf", "w", encoding="utf-8")
    
    expected_override_content = (
        "PasswordAuthentication yes\n"
        "PubkeyAuthentication yes\n"
        "ChallengeResponseAuthentication no\n"
    )
    mock_override_file().write.assert_called_once_with(expected_override_content)
    
    mock_run_command.assert_any_call("chmod 600 /etc/ssh/sshd_config.d/50-vagrant-password-auth.conf")
    mock_run_command.assert_any_call("systemctl restart sshd")


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
