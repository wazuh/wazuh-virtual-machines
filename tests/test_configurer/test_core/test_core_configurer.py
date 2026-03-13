import json
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from configurer.core.core_configurer import CoreConfigurer
from configurer.core.utils import ComponentCertsConfigParameter, ComponentConfigFile
from utils import Component


@pytest.fixture
def example_config_file():
    return {
        Component.WAZUH_INDEXER: [
            {"path": "/path/indexer/config", "replace": {"keys": [".key1"], "values": ["value1"]}}
        ],
        Component.WAZUH_MANAGER: [
            {"path": "/path/manager/config", "replace": {"keys": [".key2"], "values": ['"value2"']}}
        ],
        Component.WAZUH_DASHBOARD: [
            {"path": "/path/dashboard/config", "replace": {"keys": [".key3"], "values": ["value3"]}}
        ],
        Component.WAZUH_AGENT: [{"path": "/path/agent/config", "replace": {"keys": [".key4"], "values": ["value4"]}}],
    }


@pytest.fixture
def mock_exec_command():
    mock_exec_command = MagicMock()
    with (
        patch("configurer.core.models.wazuh_components_config_manager.exec_command", mock_exec_command),
        patch("configurer.core.models.certificates_manager.exec_command", mock_exec_command),
        patch("configurer.core.core_configurer.exec_command", mock_exec_command),
    ):
        mock_exec_command.return_value = "", ""
        yield mock_exec_command


@pytest.fixture()
def mock_open_file(example_config_file):
    with patch("builtins.open", mock_open(read_data=json.dumps(example_config_file))) as mocked_file:
        yield mocked_file


@patch("configurer.core.core_configurer.CoreConfigurer.start_services")
@patch("paramiko.SSHClient")
def test_configure(mock_paramiko, mock_start_services, mock_open_file, mock_exec_command, mock_logger):
    mock_paramiko.return_value = MagicMock()
    core_configurer_instance = CoreConfigurer(inventory=None, files_configuration_path=Path("test_path.yml"))

    core_configurer_instance.configure()

    # Replace file entries
    mock_exec_command.assert_any_call(command="sudo yq -i  '.key1 = \"value1\" ' /path/indexer/config", client=None)
    mock_exec_command.assert_any_call(
        command='sudo yq -i  \'.key2 = ""value2"" | .key2 style="double"\' /path/manager/config', client=None
    )
    mock_exec_command.assert_any_call(command="sudo yq -i  '.key3 = \"value3\" ' /path/dashboard/config", client=None)
    mock_exec_command.assert_any_call(command="sudo yq -i  '.key4 = \"value4\" ' /path/agent/config", client=None)

    # Generate certifates and copy them to the current component certs directory
    mock_exec_command.assert_any_call(
        command=f"sudo yq  '.[\"{ComponentCertsConfigParameter.WAZUH_INDEXER_KEY}\"]' {ComponentConfigFile.WAZUH_INDEXER}",
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=f"sudo yq  '.[\"{ComponentCertsConfigParameter.WAZUH_INDEXER_CERT}\"]' {ComponentConfigFile.WAZUH_INDEXER}",
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=f"sudo yq  '.[\"{ComponentCertsConfigParameter.WAZUH_INDEXER_CA}\"]' {ComponentConfigFile.WAZUH_INDEXER}",
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=f"sudo yq -p xml -o xml '.{ComponentCertsConfigParameter.WAZUH_MANAGER_KEY}' {ComponentConfigFile.WAZUH_MANAGER}",
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=f"sudo yq -p xml -o xml '.{ComponentCertsConfigParameter.WAZUH_MANAGER_CERT}' {ComponentConfigFile.WAZUH_MANAGER}",
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=f"sudo yq -p xml -o xml '.{ComponentCertsConfigParameter.WAZUH_MANAGER_CA}' {ComponentConfigFile.WAZUH_MANAGER}",
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=f"sudo yq  '.[\"{ComponentCertsConfigParameter.WAZUH_DASHBOARD_KEY}\"]' {ComponentConfigFile.WAZUH_DASHBOARD}",
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=f"sudo yq  '.[\"{ComponentCertsConfigParameter.WAZUH_DASHBOARD_CERT}\"]' {ComponentConfigFile.WAZUH_DASHBOARD}",
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=f"sudo yq  '.[\"{ComponentCertsConfigParameter.WAZUH_DASHBOARD_CA}\"]' {ComponentConfigFile.WAZUH_DASHBOARD}",
        client=None,
    )

    mock_start_services.assert_called_once_with(client=None)

    mock_logger.warning.assert_any_call("No inventory provided. Using local connection")
    mock_logger.debug_title.assert_any_call("Starting core configuration process")
    mock_logger.debug_title.assert_any_call("Configuring components")
    mock_logger.info_success.assert_any_call("Core configuration process finished")
    mock_logger.debug_title.assert_any_call("Starting certificates creation and configuration process")
    mock_logger.debug_title.assert_any_call("Starting services")


def test_start_services_success(mock_exec_command, mock_logger):
    core_configurer_instance = CoreConfigurer(inventory=None, files_configuration_path=Path("test_path.yml"))
    core_configurer_instance.start_services(client=None)

    start_service_command_template = """
    sudo systemctl --quiet enable {component}
    sudo systemctl start {component}
    """
    security_init_command_template = f"""
    {start_service_command_template}
    sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    """

    for command_call in mock_exec_command.call_args_list:
        command_call.kwargs["command"] = command_call.kwargs["command"].replace("\n", "").replace(" ", "")

    mock_exec_command.assert_any_call(
        command="sudo systemctl daemon-reload".replace("\n", "").replace(" ", ""), client=None
    )
    mock_exec_command.assert_any_call(
        command=security_init_command_template.format(component="wazuh-indexer").replace("\n", "").replace(" ", ""),
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=start_service_command_template.format(component="wazuh-manager").replace("\n", "").replace(" ", ""),
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=start_service_command_template.format(component="wazuh-dashboard").replace("\n", "").replace(" ", ""),
        client=None,
    )
    mock_exec_command.assert_any_call(
        command=start_service_command_template.format(component="wazuh-agent").replace("\n", "").replace(" ", ""),
        client=None,
    )

    mock_logger.debug.assert_any_call("wazuh indexer service started")
    mock_logger.debug.assert_any_call("wazuh manager service started")
    mock_logger.debug.assert_any_call("wazuh dashboard service started")
    mock_logger.debug.assert_any_call("wazuh agent service started")
    mock_logger.info_success.assert_any_call("All services started")
    mock_logger.error.assert_not_called()


@pytest.mark.parametrize(
    "service_error, side_effect",
    [
        ("Error reloading daemon", [("", "Daemon error")]),
        ("Error starting", [("", ""), ("", "error starting service")]),
    ],
)
def test_start_services_error(service_error, side_effect, mock_exec_command, mock_logger):
    mock_exec_command.side_effect = side_effect
    core_configurer_instance = CoreConfigurer(inventory=None, files_configuration_path=Path("test_path.yml"))

    with pytest.raises(RuntimeError) as exc_info:
        core_configurer_instance.start_services(client=None)

    exc_info.match(service_error)
