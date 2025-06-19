from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from configurer.ami.ami_pre_configurer import AmiPreConfigurer


@pytest.fixture()
def mock_ami_customizer(valid_inventory) -> AmiPreConfigurer:
    return AmiPreConfigurer(
        inventory=valid_inventory,
        wazuh_banner_path=Path("/path/to/wazuh_banner"),
        local_set_ram_script_path=Path("/path/to/set_ram_script"),
        local_update_indexer_heap_service_path=Path("/path/to/update_indexer_heap_service"),
        local_customize_certs_service_path=Path("/path/to/customize_certs_service"),
        local_customize_certs_timer_path=Path("/path/to/customize_certs_timer"),
    )


@pytest.fixture
def mock_exec_command(autouse=True):
    mock_exec_command = MagicMock()
    with patch("configurer.ami.ami_pre_configurer.ami_pre_configurer.exec_command", mock_exec_command):
        mock_exec_command.return_value = "", ""
        yield mock_exec_command


@pytest.fixture(autouse=True)
def mock_modify_file():
    with patch("configurer.ami.ami_pre_configurer.ami_pre_configurer.modify_file") as mock_modify:
        mock_modify.return_value = None
        yield mock_modify


def test_customize_without_wazuh_user(mock_ami_customizer, mock_logger):
    with pytest.raises(
        Exception,
        match=f'Before customizing the AMI, the Wazuh user  "{mock_ami_customizer.wazuh_user}" must be created',
    ):
        mock_ami_customizer.customize()


def test_customize_success(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko, mock_modify_file):
    mock_ami_customizer.inventory.ansible_user = mock_ami_customizer.wazuh_user
    mock_ami_customizer.customize()

    commands = [
        f"""
        sudo pkill -u {mock_ami_customizer.instance_username}
        sudo userdel -r {mock_ami_customizer.instance_username}
        """,
        """
        sudo cloud-init clean
        sudo cloud-init init
        """,
        f"""
        sudo hostnamectl set-hostname {mock_ami_customizer.wazuh_hostname}
        """,
        f"""
        sudo cat {mock_ami_customizer.instance_update_logo_path}
        """,
        f"""
        sudo mv /tmp/{mock_ami_customizer.wazuh_banner_path.name} {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo chmod 755 {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo chown root:root {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo rm -f {mock_ami_customizer.default_motd_file_path}
        """,
        """
        sudo systemctl restart systemd-journald
        sudo journalctl --flush
        """,
        f"""
        sudo mv /tmp/{mock_ami_customizer.local_set_ram_script_path.name} {mock_ami_customizer.ram_service_script_destination_path}/{mock_ami_customizer.local_set_ram_script_path.name}
        sudo chmod 755 {mock_ami_customizer.ram_service_script_destination_path}/{mock_ami_customizer.local_set_ram_script_path.name}
        """,
        f"""
        sudo mv /tmp/{mock_ami_customizer.local_update_indexer_heap_service_path.name} {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_update_indexer_heap_service_path.name}
        sudo chmod 755 {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_update_indexer_heap_service_path.name}
        sudo chown root:root {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_update_indexer_heap_service_path.name}
        sudo systemctl --quiet enable {mock_ami_customizer.local_update_indexer_heap_service_path.name}
        """,
        f"""
        sudo mv /tmp/{mock_ami_customizer.local_customize_certs_service_path.name} {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_service_path.name}
        sudo chmod 755 {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_service_path.name}
        sudo chown root:root {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_service_path.name}
        sudo systemctl --quiet enable {mock_ami_customizer.local_customize_certs_service_path.name}
        """,
        f"""
        sudo mv /tmp/{mock_ami_customizer.local_customize_certs_timer_path.name} {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_timer_path.name}
        sudo chmod 755 {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_timer_path.name}
        sudo chown root:root {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_timer_path.name}
        sudo systemctl --quiet enable {mock_ami_customizer.local_customize_certs_timer_path.name}
        """,
    ]
    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    for command in commands:
        command = command.replace("\n", "").replace(" ", "")
        mock_exec_command.assert_any_call(command=command, client=mock_paramiko.return_value)


def test_customize_without_client(mock_ami_customizer, mock_logger):
    mock_ami_customizer.inventory = None
    with pytest.raises(Exception, match="SSH client is not connected"):
        mock_ami_customizer.customize()


def test_create_user_success(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko, mock_modify_file):
    new_user = mock_ami_customizer.create_wazuh_user()

    command = f"""
        sudo adduser {mock_ami_customizer.wazuh_user}
        sudo mkdir -p /home/{mock_ami_customizer.wazuh_user}/.ssh
        sudo chown -R {mock_ami_customizer.wazuh_user}:{mock_ami_customizer.wazuh_user} /home/{mock_ami_customizer.wazuh_user}/.ssh
        sudo chmod 700 /home/{mock_ami_customizer.wazuh_user}/.ssh
        sudo touch /home/{mock_ami_customizer.wazuh_user}/.ssh/authorized_keys
        sudo chmod 600 /home/{mock_ami_customizer.wazuh_user}/.ssh/authorized_keys
        sudo cp /home/{mock_ami_customizer.instance_username}/.ssh/authorized_keys /home/{mock_ami_customizer.wazuh_user}/.ssh/authorized_keys
        sudo chown {mock_ami_customizer.wazuh_user}:{mock_ami_customizer.wazuh_user} /home/{mock_ami_customizer.wazuh_user}/.ssh/authorized_keys
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    assert new_user == mock_ami_customizer.wazuh_user
    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    mock_modify_file.assert_called_once_with(
        filepath=Path("/etc/sudoers.d/90-cloud-init-users"),
        replacements=[(r"ec2-user", mock_ami_customizer.wazuh_user)],
        client=mock_paramiko.return_value,
    )

    mock_logger.debug_title.assert_any_call("Starting AMI customization process")
    mock_logger.debug.assert_any_call(f"Creating Wazuh user: {mock_ami_customizer.wazuh_user}")
    mock_logger.debug.assert_any_call(f"Changing inventory user to {mock_ami_customizer.wazuh_user}")
    mock_logger.info_success.assert_any_call(f'Wazuh user "{mock_ami_customizer.wazuh_user}" created successfully')


def test_create_user_failure(mock_ami_customizer, mock_logger, mock_exec_command, mock_modify_file):
    mock_exec_command.return_value = ("", "useradd: user already exists")
    with pytest.raises(
        Exception,
        match=f'Failed to create Wazuh user "{mock_ami_customizer.wazuh_user}": useradd: user already exists',
    ):
        mock_ami_customizer.create_wazuh_user()

    mock_logger.debug_title.assert_any_call("Starting AMI customization process")
    mock_logger.debug.assert_any_call(f"Creating Wazuh user: {mock_ami_customizer.wazuh_user}")
    mock_modify_file.assert_not_called()


def test_remove_default_instance_user_success(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_ami_customizer.remove_default_instance_user(mock_paramiko.return_value)

    command = f"""
        sudo pkill -u {mock_ami_customizer.instance_username}
        sudo userdel -r {mock_ami_customizer.instance_username}
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    mock_logger.debug.assert_any_call(f"Removing default instance user: {mock_ami_customizer.instance_username}")
    mock_logger.info_success.assert_any_call(
        f'Default instance user "{mock_ami_customizer.instance_username}" removed successfully'
    )


def test_remove_default_instance_user_failure(mock_ami_customizer, mock_logger, mock_exec_command):
    mock_exec_command.return_value = ("", "userdel: user not found")
    with pytest.raises(
        RuntimeError,
        match=f'Failed to remove default instance user "{mock_ami_customizer.instance_username}": userdel: user not found',
    ):
        mock_ami_customizer.remove_default_instance_user(None)

    mock_logger.debug.assert_any_call(f"Removing default instance user: {mock_ami_customizer.instance_username}")
    mock_logger.error.assert_any_call(
        f'Failed to remove default instance user "{mock_ami_customizer.instance_username}"'
    )


def test_configure_cloud_cfg_success(
    mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko, mock_modify_file
):
    mock_ami_customizer.configure_cloud_cfg(mock_paramiko.return_value)

    command = """
        sudo cloud-init clean
        sudo cloud-init init
        """.replace("\n", "").replace(" ", "")

    replacements = [
        (r"gecos: .*", "gecos: Wazuh AMI User"),
        (r"^[ \t]*name:\s*.*$", f"     name: {mock_ami_customizer.wazuh_user}"),
        (r"- set_hostname\n", ""),
        (r"\s*- update_hostname", ""),
        (r"preserve_hostname: false", "preserve_hostname: true"),
    ]

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    mock_modify_file.assert_called_once_with(
        filepath=mock_ami_customizer.cloud_config_path,
        replacements=replacements,
        client=mock_paramiko.return_value,
    )
    mock_logger.debug.assert_any_call(f"Configuring cloud config file: {mock_ami_customizer.cloud_config_path}")
    mock_logger.debug.assert_any_call("Executing cloud-init commands")
    mock_logger.info_success.assert_any_call("Cloud config file configured successfully")


def test_configure_cloud_cfg_failure(mock_ami_customizer, mock_logger, mock_exec_command, mock_modify_file):
    mock_exec_command.return_value = ("", "cloud-init: command not found")
    with pytest.raises(
        RuntimeError,
        match="Error configuring cloud config: cloud-init: command not found",
    ):
        mock_ami_customizer.configure_cloud_cfg(None)

    mock_modify_file.assert_called_once()
    mock_logger.debug.assert_any_call(f"Configuring cloud config file: {mock_ami_customizer.cloud_config_path}")
    mock_logger.error.assert_any_call("Error configuring cloud config")


def test_update_hostname_success(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_ami_customizer.update_hostname(mock_paramiko.return_value)

    command = f"""
        sudo hostnamectl set-hostname {mock_ami_customizer.wazuh_hostname}
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    mock_logger.debug.assert_any_call("Updating hostname")
    mock_logger.info_success.assert_any_call(f'Hostname updated successfully to "{mock_ami_customizer.wazuh_hostname}"')


def test_update_hostname_failure(mock_ami_customizer, mock_logger, mock_exec_command):
    mock_exec_command.return_value = ("", "hostnamectl: command not found")
    with pytest.raises(
        RuntimeError,
        match="Error updating hostname: hostnamectl: command not found",
    ):
        mock_ami_customizer.update_hostname(None)

    mock_logger.debug.assert_any_call("Updating hostname")
    mock_logger.error.assert_any_call("Error updating hostname")


def test_check_instance_updates_with(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_exec_command.return_value = ("testing updates", "")
    updates = mock_ami_customizer.check_instance_updates(mock_paramiko.return_value)

    command = f"sudo cat {mock_ami_customizer.instance_update_logo_path}"

    assert updates
    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.warning.assert_any_call("Instance has updates available")
    mock_logger.debug.assert_any_call("Checking for instance updates")


def test_check_instance_updates_without(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_exec_command.return_value = ("", "")
    updates = mock_ami_customizer.check_instance_updates(mock_paramiko.return_value)

    command = f"sudo cat {mock_ami_customizer.instance_update_logo_path}"

    assert not updates
    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call("Checking for instance updates")
    mock_logger.info.assert_any_call("Instance is up to date")


def test_check_instance_updates_error(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_exec_command.return_value = ("", "No such file or directory")
    with pytest.raises(
        RuntimeError,
        match="Error checking instance updates: No such file or directory",
    ):
        mock_ami_customizer.check_instance_updates(mock_paramiko.return_value)

    command = f"sudo cat {mock_ami_customizer.instance_update_logo_path}"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    mock_logger.debug.assert_any_call("Checking for instance updates")
    mock_logger.error.assert_any_call("Error checking instance updates")


def test_update_instance_success(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_ami_customizer.update_instance(mock_paramiko.return_value)

    command = """
        sudo yum update -y
        sudo dnf upgrade --assumeyes --releasever=latest
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    mock_logger.debug.assert_any_call("Updating instance")
    mock_logger.info_success.assert_any_call("Instance updated successfully")


def test_update_instance_failure(mock_ami_customizer, mock_logger, mock_exec_command):
    mock_exec_command.return_value = ("", "yum: command not found")

    with pytest.raises(
        RuntimeError,
        match="Error updating instance: yum: command not found",
    ):
        mock_ami_customizer.update_instance(None)

    mock_logger.debug.assert_any_call("Updating instance")


def test_update_instance_with_warning(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_exec_command.return_value = ("", "WARNING: This is not an error message")
    mock_ami_customizer.update_instance(mock_paramiko.return_value)

    command = """
        sudo yum update -y
        sudo dnf upgrade --assumeyes --releasever=latest
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    mock_logger.debug.assert_any_call("Updating instance")
    mock_logger.info_success.assert_any_call("Instance updated successfully")


@patch("configurer.ami.ami_pre_configurer.ami_pre_configurer.AmiPreConfigurer.check_instance_updates")
def test_configure_motd_logo(mock_updates, mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_updates.return_value = True
    mock_ami_customizer.configure_motd_logo(mock_paramiko.return_value)

    sftp = mock_paramiko.return_value.open_sftp.return_value

    commands = [
        """
        sudo yum update -y
        sudo dnf upgrade --assumeyes --releasever=latest
        """,
        f"""
        sudo mv /tmp/{mock_ami_customizer.wazuh_banner_path.name} {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo chmod 755 {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo chown root:root {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo rm -f {mock_ami_customizer.default_motd_file_path}
        """,
    ]

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    for command in commands:
        command = command.replace("\n", "").replace(" ", "")
        mock_exec_command.assert_any_call(command=command, client=mock_paramiko.return_value)

    sftp.put.assert_called_once_with(
        str(mock_ami_customizer.wazuh_banner_path), f"/tmp/{mock_ami_customizer.wazuh_banner_path.name}"
    )


def test_set_wazuh_logo(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_ami_customizer._set_wazuh_logo(mock_paramiko.return_value)

    sftp = mock_paramiko.return_value.open_sftp.return_value
    command = f"""
        sudo mv /tmp/{mock_ami_customizer.wazuh_banner_path.name} {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo chmod 755 {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo chown root:root {mock_ami_customizer.motd_scripts_directory}/{mock_ami_customizer.wazuh_banner_path.name}
        sudo rm -f {mock_ami_customizer.default_motd_file_path}
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    sftp.put.assert_called_once_with(
        str(mock_ami_customizer.wazuh_banner_path), f"/tmp/{mock_ami_customizer.wazuh_banner_path.name}"
    )

    mock_logger.debug.assert_any_call("Setting Wazuh logo")
    mock_logger.info_success.assert_any_call("Wazuh motd banner set successfully")


def test_set_wazuh_logo_sftp_fails(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    sftp = mock_paramiko.return_value.open_sftp.return_value
    sftp.put.side_effect = Exception("SFTP error")

    with pytest.raises(RuntimeError, match="Error uploading Wazuh banner to the remote host: SFTP error"):
        mock_ami_customizer._set_wazuh_logo(mock_paramiko.return_value)

    mock_logger.error.assert_any_call("Error uploading Wazuh banner to the remote host")


def test_set_wazuh_logo_command_fails(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_exec_command.return_value = ("", "command not found")

    with pytest.raises(RuntimeError, match="Error setting Wazuh motd banner: command not found"):
        mock_ami_customizer._set_wazuh_logo(mock_paramiko.return_value)

    mock_exec_command.assert_called_once()
    mock_logger.error.assert_any_call("Error setting Wazuh motd banner")


def test_stop_journald_log_storage_success(
    mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko, mock_modify_file
):
    mock_ami_customizer.stop_journald_log_storage(mock_paramiko.return_value)

    parameters = [
        ("#Storage=auto", "Storage=none"),
        ("#ForwardToSyslog=yes", "ForwardToSyslog=yes"),
    ]

    command = """
        sudo systemctl restart systemd-journald
        sudo journalctl --flush
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_modify_file.assert_called_once_with(
        filepath=mock_ami_customizer.journald_file_path,
        replacements=parameters,
        client=mock_paramiko.return_value,
    )
    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call("Stopping journald log storage")


def test_stop_journald_log_storage_failure(mock_ami_customizer, mock_logger, mock_exec_command, mock_modify_file):
    mock_exec_command.return_value = ("", "systemctl: command not found")
    with pytest.raises(
        RuntimeError,
        match="Error stopping journald log storage: systemctl: command not found",
    ):
        mock_ami_customizer.stop_journald_log_storage(None)

    mock_modify_file.assert_called_once()
    mock_exec_command.assert_called_once()

    mock_logger.debug.assert_any_call("Stopping journald log storage")
    mock_logger.error.assert_any_call("Error stopping journald log storage")


def test_create_service_to_set_ram(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_ami_customizer.create_service_to_set_ram(mock_paramiko.return_value)

    commands = [
        f"""
        sudo mv /tmp/{mock_ami_customizer.local_set_ram_script_path.name} {mock_ami_customizer.ram_service_script_destination_path}/{mock_ami_customizer.local_set_ram_script_path.name}
        sudo chmod 755 {mock_ami_customizer.ram_service_script_destination_path}/{mock_ami_customizer.local_set_ram_script_path.name}
        """.replace("\n", "").replace(" ", ""),
        f"""
        sudo mv /tmp/{mock_ami_customizer.local_update_indexer_heap_service_path.name} {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_update_indexer_heap_service_path.name}
        sudo chmod 755 {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_update_indexer_heap_service_path.name}
        sudo chown root:root {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_update_indexer_heap_service_path.name}
        sudo systemctl --quiet enable {mock_ami_customizer.local_update_indexer_heap_service_path.name}
        """,
    ]

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_paramiko.return_value.open_sftp.return_value.put.assert_any_call(
        str(mock_ami_customizer.local_update_indexer_heap_service_path),
        f"/tmp/{mock_ami_customizer.local_update_indexer_heap_service_path.name}",
    )
    mock_paramiko.return_value.open_sftp.return_value.put.assert_any_call(
        str(mock_ami_customizer.local_set_ram_script_path),
        f"/tmp/{mock_ami_customizer.local_set_ram_script_path.name}",
    )
    for command in commands:
        command = command.replace("\n", "").replace(" ", "")
        mock_exec_command.assert_any_call(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call(
        f'Creating "{mock_ami_customizer.local_update_indexer_heap_service_path.name}" service'
    )
    mock_logger.info_success.assert_any_call(
        f'"{mock_ami_customizer.local_update_indexer_heap_service_path.name.split(".")[0]}" service created successfully'
    )


def test_create_service_to_set_ram_sftp_fails(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    sftp = mock_paramiko.return_value.open_sftp.return_value
    sftp.put.side_effect = Exception("SFTP error")

    with pytest.raises(RuntimeError, match="Error uploading files to the remote host: SFTP error"):
        mock_ami_customizer.create_service_to_set_ram(mock_paramiko.return_value)

    mock_logger.error.assert_any_call("Error uploading files to the remote host")


def test_create_service_to_set_ram_command_fails(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_exec_command.return_value = ("", "command not found")

    with pytest.raises(RuntimeError, match="Error creating script for set RAM service: command not found"):
        mock_ami_customizer.create_service_to_set_ram(mock_paramiko.return_value)

    mock_exec_command.assert_called_once()
    mock_logger.error.assert_any_call("Error creating script for set RAM service")


def test_create_custom_certs_service(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    mock_ami_customizer.create_customize_certs_service_files(mock_paramiko.return_value)

    commands = [
        f"""
        sudo mv /tmp/{mock_ami_customizer.local_customize_certs_service_path.name} {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_service_path.name}
        sudo chmod 755 {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_service_path.name}
        sudo chown root:root {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_service_path.name}
        sudo systemctl --quiet enable {mock_ami_customizer.local_customize_certs_service_path.name}
        """.replace("\n", "").replace(" ", ""),
        f"""
        sudo mv /tmp/{mock_ami_customizer.local_customize_certs_timer_path.name} {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_timer_path.name}
        sudo chmod 755 {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_timer_path.name}
        sudo chown root:root {mock_ami_customizer.systemd_services_path}/{mock_ami_customizer.local_customize_certs_timer_path.name}
        sudo systemctl --quiet enable {mock_ami_customizer.local_customize_certs_timer_path.name}
        """.replace("\n", "").replace(" ", ""),
    ]

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_paramiko.return_value.open_sftp.return_value.put.assert_any_call(
        str(mock_ami_customizer.local_customize_certs_service_path),
        f"/tmp/{mock_ami_customizer.local_customize_certs_service_path.name}",
    )
    mock_paramiko.return_value.open_sftp.return_value.put.assert_any_call(
        str(mock_ami_customizer.local_customize_certs_timer_path),
        f"/tmp/{mock_ami_customizer.local_customize_certs_timer_path.name}",
    )
    for command in commands:
        command = command.replace("\n", "").replace(" ", "")
        mock_exec_command.assert_any_call(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call(
        f'Creating "{mock_ami_customizer.local_customize_certs_service_path.name}" service'
    )


def test_create_ami_custom_service_success(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    file_local_path = Path("/path/to/service_file.service")
    mock_ami_customizer.create_ami_custom_service(file_local_path, mock_paramiko.return_value)

    sftp = mock_paramiko.return_value.open_sftp.return_value
    tmp_service_path = f"/tmp/{file_local_path.name}"
    commands = [
        f"""
        sudo mv {tmp_service_path} {mock_ami_customizer.systemd_services_path}/{file_local_path.name}
        sudo chmod 755 {mock_ami_customizer.systemd_services_path}/{file_local_path.name}
        sudo chown root:root {mock_ami_customizer.systemd_services_path}/{file_local_path.name}
        sudo systemctl --quiet enable {file_local_path.name}
        """.replace("\n", "").replace(" ", "")
    ]

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    sftp.put.assert_called_once_with(str(file_local_path), tmp_service_path)
    sftp.close.assert_called_once()
    for command in commands:
        command = command.replace("\n", "").replace(" ", "")
        mock_exec_command.assert_any_call(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call(f'Creating "{file_local_path.name}" service')
    mock_logger.info_success.assert_any_call(f'"{file_local_path.name.split(".")[0]}" service created successfully')


def test_create_ami_custom_service_sftp_failure(mock_ami_customizer, mock_logger, mock_paramiko):
    file_local_path = Path("/path/to/service_file.service")
    sftp = mock_paramiko.return_value.open_sftp.return_value
    sftp.put.side_effect = Exception("SFTP error")

    with pytest.raises(RuntimeError, match="Error uploading files to the remote host: SFTP error"):
        mock_ami_customizer.create_ami_custom_service(file_local_path, mock_paramiko.return_value)

    sftp.put.assert_called_once_with(str(file_local_path), f"/tmp/{file_local_path.name}")
    sftp.close.assert_called_once()
    mock_logger.error.assert_any_call("Error uploading files to the remote host")


def test_create_ami_custom_service_command_failure(mock_ami_customizer, mock_logger, mock_exec_command, mock_paramiko):
    file_local_path = Path("/path/to/service_file.service")
    mock_exec_command.return_value = ("", "command not found")

    with pytest.raises(RuntimeError, match=f"Error creating service {file_local_path.name}: command not found"):
        mock_ami_customizer.create_ami_custom_service(file_local_path, mock_paramiko.return_value)

    tmp_service_path = f"/tmp/{file_local_path.name}"
    command = f"""
        sudo mv {tmp_service_path} {mock_ami_customizer.systemd_services_path}/{file_local_path.name}
        sudo chmod 755 {mock_ami_customizer.systemd_services_path}/{file_local_path.name}
        sudo chown root:root {mock_ami_customizer.systemd_services_path}/{file_local_path.name}
        sudo systemctl --quiet enable {file_local_path.name}
        """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)
    mock_logger.error.assert_any_call(f"Error creating service {file_local_path.name}")
