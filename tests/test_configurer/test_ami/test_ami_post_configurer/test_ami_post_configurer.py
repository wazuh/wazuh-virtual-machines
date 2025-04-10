from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from configurer.ami.ami_post_configurer.ami_post_configurer import AmiPostConfigurer
from utils.enums import CertificatesComponent, RemoteDirectories


@pytest.fixture()
def main_methods() -> list[str]:
    """Fixture to provide a list of main methods for testing."""
    return [
        "create_custom_dir",
        "create_certs_env",
        "stop_wazuh_server",
        "stop_wazuh_indexer",
        "stop_wazuh_dashboard",
        "change_ssh_port_to_default",
        "clean_cloud_instance_files",
        "clean_journal_logs",
        "clean_yum_cache",
        "clean_logout_files",
        "enable_journal_log_storage",
        "clean_generated_logs",
        "clean_history",
        "clean_authorized_keys",
        "clean_wazuh_configure_directory",
    ]


@pytest.fixture()
def mock_ami_post_configurer(valid_inventory) -> AmiPostConfigurer:
    return AmiPostConfigurer(inventory=valid_inventory)


@pytest.fixture
def mock_exec_command(autouse=True):
    mock_exec_command = MagicMock()
    with patch("configurer.ami.ami_post_configurer.ami_post_configurer.exec_command", mock_exec_command):
        mock_exec_command.return_value = "", ""
        yield mock_exec_command


@pytest.fixture(autouse=True)
def mock_modify_file():
    with patch("configurer.ami.ami_post_configurer.ami_post_configurer.modify_file") as mock_modify:
        mock_modify.return_value = None
        yield mock_modify


@pytest.fixture
def mock_post_configurer_methods(main_methods):
   
    mocks = {method: MagicMock() for method in main_methods}
    with patch.multiple("configurer.ami.ami_post_configurer.ami_post_configurer.AmiPostConfigurer", **mocks):
        yield mocks


def test_post_customize(mock_ami_post_configurer, mock_post_configurer_methods, main_methods, mock_paramiko, mock_logger):
    mock_ami_post_configurer.post_customize()

    for method in main_methods:
        mock_post_configurer_methods[method].assert_called_once_with(client=mock_paramiko.return_value)

    mock_logger.debug_title.assert_called_once_with("AMI post configuration")
    mock_logger.info_success.assert_any_call("AMI post configuration completed successfully")


@patch("configurer.ami.ami_post_configurer.ami_post_configurer.generate_yaml")
@patch("configurer.ami.ami_post_configurer.ami_post_configurer.create_directory_structure")
def test_create_custom_dir_success(mock_create_structure, mock_generate_yaml, mock_ami_post_configurer, mock_paramiko):
    root_dir_path = Path(__file__).parents[4]
    post_configurer_template = root_dir_path / "configurer" / "ami" / "ami_post_configurer" / "templates"
    template_file = "ami_custom_service_directory.j2"
    context = {
        "remote_certs_path": RemoteDirectories.CERTS,
        "certs_tool": CertificatesComponent.CERTS_TOOL,
        "certs_config": CertificatesComponent.CONFIG,
    }

    mock_generate_yaml.return_value = {"template": "test_value"}

    mock_ami_post_configurer.create_custom_dir(mock_paramiko.return_value)

    mock_generate_yaml.assert_called_once_with(
        context=context, template_dir=str(post_configurer_template), template_file=template_file
    )
    mock_create_structure.assert_called_once_with(
        base_path=mock_ami_post_configurer.custom_dir_base_path,
        directory_template=mock_generate_yaml.return_value,
        remote_user=mock_ami_post_configurer.inventory.ansible_user,
        client=mock_paramiko.return_value,
    )


def test_create_certs_env_success(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.create_certs_env(mock_paramiko.return_value)

    command = f"""
        sudo dnf install -y python{mock_ami_post_configurer.enviroment_python_version}
        sudo python{mock_ami_post_configurer.enviroment_python_version} -m venv {mock_ami_post_configurer.custom_dir_base_path}/{mock_ami_post_configurer.custom_dir_name}/{mock_ami_post_configurer.environment_name}
        sudo {mock_ami_post_configurer.custom_dir_base_path}/{mock_ami_post_configurer.custom_dir_name}/{mock_ami_post_configurer.environment_name}/bin/pip install --upgrade pip
        sudo {mock_ami_post_configurer.custom_dir_base_path}/{mock_ami_post_configurer.custom_dir_name}/{mock_ami_post_configurer.environment_name}/bin/pip install {" ".join(mock_ami_post_configurer.custom_env_dependencies)}
    """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Creating custom environment")
    mock_logger.info_success.assert_called_once_with("Custom environment created successfully")


def test_create_certs_env_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error creating the custom environment: Command failed"):
        mock_ami_post_configurer.create_certs_env(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error creating the custom environment")


def test_stop_service_success(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.stop_service("testing-service", mock_paramiko.return_value)

    command = "sudo systemctl stop testing-service"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Stopping testing-service service")
    mock_logger.info_success.assert_called_once_with("testing-service service stopped successfully")


def test_stop_service_fails(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error stopping the testing-service service: Command failed"):
        mock_ami_post_configurer.stop_service("testing-service", mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error stopping the testing-service service")


def test_stop_wazuh_server(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.stop_wazuh_server(mock_paramiko.return_value)
    command = "sudo systemctl stop wazuh-server"
    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Stopping wazuh-server service")
    mock_logger.info_success.assert_called_once_with("wazuh-server service stopped successfully")


def test_stop_wazuh_indexer(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.stop_wazuh_indexer(mock_paramiko.return_value)

    commands = [
        """
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-alerts-*" &&
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-archives-*" &&
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-states-vulnerabilities-*" &&
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-statistics-*" &&
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-monitoring-*"
    """,
        """
    sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    """,
        """
    sudo systemctl stop wazuh-indexer
    """,
    ]

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    for command in commands:
        command = command.replace("\n", "").replace(" ", "")
        mock_exec_command.assert_any_call(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call("Removing indexer index list")
    mock_logger.debug.assert_any_call("Indexer index list removed successfully")
    mock_logger.debug.assert_any_call("Running indexer security init script")
    mock_logger.debug.assert_any_call("Indexer security init script executed successfully")
    mock_logger.debug.assert_any_call("Stopping wazuh-indexer service")
    mock_logger.info_success.assert_any_call("wazuh-indexer service stopped successfully")


def test_remove_indexer_index_list(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.remove_indexer_index_list(mock_paramiko.return_value)

    command = """
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-alerts-*" &&
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-archives-*" &&
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-states-vulnerabilities-*" &&
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-statistics-*" &&
    sudo curl -s -o /dev/null -w "%{http_code}" -X DELETE -u "admin:admin" -k "https://localhost:9200/wazuh-monitoring-*"
    """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call("Removing indexer index list")
    mock_logger.debug.assert_any_call("Indexer index list removed successfully")


def test_remove_indexer_index_list_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error removing the indexer index list: Command failed"):
        mock_ami_post_configurer.remove_indexer_index_list(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error removing the indexer index list")


def test_run_security_init_script(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.run_security_init_script(mock_paramiko.return_value)

    command = "sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call("Running indexer security init script")
    mock_logger.debug.assert_any_call("Indexer security init script executed successfully")


def test_run_security_init_script_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error running the indexer security init script: Command failed"):
        mock_ami_post_configurer.run_security_init_script(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error running the indexer security init script")


def test_stop_and_disable_dashboard_success(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.stop_wazuh_dashboard(mock_paramiko.return_value)

    commands = ["sudo systemctl stop wazuh-dashboard", "sudo systemctl --quiet disable wazuh-dashboard"]

    for command in commands:
        mock_exec_command.assert_any_call(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_any_call("Stopping wazuh-dashboard service")
    mock_logger.info_success.assert_any_call("wazuh-dashboard service stopped successfully")
    mock_logger.debug.assert_any_call("Disabling wazuh-dashboard service")
    mock_logger.info_success.assert_any_call("wazuh-dashboard service disabled successfully")


def test_stop_and_disable_dashboard_fails_disabling(
    mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger
):
    mock_exec_command.side_effect = [("", ""), ("", "Command failed")]

    with pytest.raises(Exception, match="Error disabling the wazuh-dashboard service: Command failed"):
        mock_ami_post_configurer.stop_wazuh_dashboard(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error disabling the wazuh-dashboard service")


def test_stop_and_disable_dashboard_fails_stopping(
    mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger
):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error stopping the wazuh-dashboard service: Command failed"):
        mock_ami_post_configurer.stop_wazuh_dashboard(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error stopping the wazuh-dashboard service")


def test_change_ssh_port_to_default_and_restart_service(
    mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger, mock_modify_file
):
    mock_ami_post_configurer.change_ssh_port_to_default(mock_paramiko.return_value)

    replacements = [
        (r"Port \d+", "#Port 22"),
    ]
    command = "sudo systemctl restart sshd.service"
    ssh_file = "/etc/ssh/sshd_config"

    mock_modify_file.assert_called_once_with(
        filepath=Path(ssh_file), replacements=replacements, client=mock_paramiko.return_value
    )

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Changing SSH port to default (22)")
    mock_logger.info_success.assert_called_once_with("SSH port changed to default successfully")


def test_change_ssh_port_to_default_and_restart_service_fails_restarting_service(
    mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger, mock_modify_file
):
    replacements = [
        (r"Port \d+", "#Port 22"),
    ]
    command = "sudo systemctl restart sshd.service"
    ssh_file = "/etc/ssh/sshd_config"

    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error restarting the SSH service: Command failed"):
        mock_ami_post_configurer.change_ssh_port_to_default(mock_paramiko.return_value)

    mock_modify_file.assert_called_once_with(
        filepath=Path(ssh_file), replacements=replacements, client=mock_paramiko.return_value
    )

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error restarting the SSH service")


def test_clean_cloud_instance_files(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.clean_cloud_instance_files(mock_paramiko.return_value)

    command = f"[ -d {mock_ami_post_configurer.cloud_instances_path} ] && sudo rm -rf {mock_ami_post_configurer.cloud_instances_path}/*"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Cleaning up cloud instance files")
    mock_logger.info_success.assert_called_once_with("Cloud instance files cleaned up successfully")


def test_clean_cloud_instance_files_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error cleaning up cloud instance files: Command failed"):
        mock_ami_post_configurer.clean_cloud_instance_files(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error cleaning up cloud instance files")


def test_clean_journal_logs(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.clean_journal_logs(mock_paramiko.return_value)

    command = f"[ -d {mock_ami_post_configurer.journal_logs_path} ] && sudo rm -rf {mock_ami_post_configurer.journal_logs_path}/*"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Cleaning up journal logs")
    mock_logger.info_success.assert_called_once_with("Journal logs cleaned up successfully")


def test_clean_journal_logs_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error cleaning up journal logs: Command failed"):
        mock_ami_post_configurer.clean_journal_logs(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error cleaning up journal logs")


def test_clean_yum_cache(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.clean_yum_cache(mock_paramiko.return_value)

    command = "sudo dnf clean all"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Cleaning up yum cache")
    mock_logger.info_success.assert_called_once_with("Yum cache cleaned up successfully")


def test_clean_yum_cache_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error cleaning up yum cache: Command failed"):
        mock_ami_post_configurer.clean_yum_cache(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error cleaning up yum cache")


def test_clean_logout_files(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.clean_logout_files(mock_paramiko.return_value)

    command = f"""
    echo '' | sudo tee /home/{mock_ami_post_configurer.inventory.ansible_user}/.bash_logout > /dev/null
    echo '' | sudo tee /root/.bash_logout > /dev/null
    """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Cleaning up logout files")
    mock_logger.info_success.assert_called_once_with("Logout files cleaned up successfully")


def test_clean_logout_files_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error cleaning up logout files: Command failed"):
        mock_ami_post_configurer.clean_logout_files(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error cleaning up logout files")


def test_enable_journal_log_storage(
    mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger, mock_modify_file
):
    mock_ami_post_configurer.enable_journal_log_storage(mock_paramiko.return_value)

    replacements = [
        ("Storage=none", "#Storage=auto"),
        ("ForwardToSyslog=yes", "#ForwardToSyslog=yes"),
    ]

    mock_modify_file.assert_called_once_with(
        filepath=mock_ami_post_configurer.journald__config_file_path,
        replacements=replacements,
        client=mock_paramiko.return_value,
    )

    mock_logger.debug.assert_called_once_with("Enabling journal log storage")
    mock_logger.info_success.assert_called_once_with("Journal log storage enabled successfully")


def test_clean_generated_logs(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.clean_generated_logs(mock_paramiko.return_value)

    command = f"""
    if [ -d {mock_ami_post_configurer.log_directory_path} ] && sudo find {mock_ami_post_configurer.log_directory_path} -type f | read; then
        sudo find {mock_ami_post_configurer.log_directory_path} -type f -exec sudo bash -c 'cat /dev/null > "$1"' _ {{}} \\;
    fi
    if [ -d {mock_ami_post_configurer.wazuh_indexer_log_path} ] && sudo find {mock_ami_post_configurer.wazuh_indexer_log_path} -type f | read; then
        sudo find {mock_ami_post_configurer.wazuh_indexer_log_path} -type f -exec sudo bash -c 'cat /dev/null > "$1"' _ {{}} \\;
    fi
    if [ -d {mock_ami_post_configurer.wazuh_server_log_path} ] && sudo find {mock_ami_post_configurer.wazuh_server_log_path} -type f | read; then
        sudo find {mock_ami_post_configurer.wazuh_server_log_path} -type f -exec sudo bash -c 'cat /dev/null > "$1"' _ {{}} \\;
    fi
    if [ -d {mock_ami_post_configurer.wazuh_dashboard_log_path} ] && sudo find {mock_ami_post_configurer.wazuh_dashboard_log_path} -type f | read; then
        sudo find {mock_ami_post_configurer.wazuh_dashboard_log_path} -type f -exec sudo bash -c 'cat /dev/null > "$1"' _ {{}} \\;
    fi
    """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with(
        f'Cleaning up generated logs in "{mock_ami_post_configurer.log_directory_path}"'
    )
    mock_logger.info_success.assert_called_once_with("Generated logs cleaned up successfully")


def test_clean_generated_logs_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error cleaning up generated logs: Command failed"):
        mock_ami_post_configurer.clean_generated_logs(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error cleaning up generated logs")


def test_clean_history(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.clean_history(mock_paramiko.return_value)

    command = f"""
    echo '' | sudo tee /home/{mock_ami_post_configurer.inventory.ansible_user}/.bash_history > /dev/null
    echo '' | sudo tee /root/.bash_history > /dev/null
    """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Cleaning up history files")
    mock_logger.info_success.assert_called_once_with("History files cleaned up successfully")


def test_clean_history_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error cleaning up history files: Command failed"):
        mock_ami_post_configurer.clean_history(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error cleaning up history files")


def test_authorized_keys(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.clean_authorized_keys(mock_paramiko.return_value)

    command = f"""
    echo '' | sudo tee /home/{mock_ami_post_configurer.inventory.ansible_user}/.ssh/authorized_keys > /dev/null
    echo '' | sudo tee /root/.ssh/authorized_keys > /dev/null
    """.replace("\n", "").replace(" ", "")

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Cleaning up authorized keys")
    mock_logger.info_success.assert_called_once_with("Authorized keys cleaned up successfully")


def test_authorized_keys_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(Exception, match="Error cleaning up authorized keys: Command failed"):
        mock_ami_post_configurer.clean_authorized_keys(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with("Error cleaning up authorized keys")


def test_clean_wazuh_configure_directory(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_ami_post_configurer.clean_wazuh_configure_directory(mock_paramiko.return_value)

    command = f"sudo rm -rf {RemoteDirectories.WAZUH_ROOT_DIR}"

    mock_exec_command.assert_called_once_with(command=command, client=mock_paramiko.return_value)

    mock_logger.debug.assert_called_once_with("Cleaning up Wazuh configure directory")
    mock_logger.info_success.assert_called_once_with("Wazuh configure directory cleaned up successfully")


def test_clean_wazuh_configure_directory_fail(mock_ami_post_configurer, mock_exec_command, mock_paramiko, mock_logger):
    mock_exec_command.return_value = ("", "Command failed")

    with pytest.raises(
        Exception,
        match=f"Error cleaning up Wazuh configure directory {RemoteDirectories.WAZUH_ROOT_DIR}: Command failed",
    ):
        mock_ami_post_configurer.clean_wazuh_configure_directory(mock_paramiko.return_value)

    mock_logger.error.assert_called_once_with(
        f"Error cleaning up Wazuh configure directory {RemoteDirectories.WAZUH_ROOT_DIR}"
    )
