from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from configurer.ami.ami_post_configurer.ami_post_configurer import AmiPostConfigurer
from utils.enums import CertificatesComponent, RemoteDirectories


@pytest.fixture()
def mock_ami_post_configurer(valid_inventory) -> AmiPostConfigurer:
    return AmiPostConfigurer(inventory=valid_inventory)


@pytest.fixture
def mock_exec_command(autouse=True):
    mock_exec_command = MagicMock()
    with patch("configurer.ami.ami_post_configurer.ami_post_configurer.exec_command", mock_exec_command):
        mock_exec_command.return_value = "", ""
        yield mock_exec_command


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
