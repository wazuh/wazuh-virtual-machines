import json
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from configurer.core.core_configurer import (
    AUTHD_PASS_MAX_RETRIES,
    WAZUH_AGENT_AUTHD_PASS_FILE,
    WAZUH_MANAGER_AUTHD_PASS_FILE,
    CoreConfigurer,
)
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


@patch("configurer.core.core_configurer.CoreConfigurer.set_authd_password")
def test_start_services_sets_authd_password_before_agent(mock_set_authd_password, mock_exec_command, mock_logger):
    call_order = []
    mock_set_authd_password.side_effect = lambda client=None: call_order.append("set_authd_password")
    original_side_effect = mock_exec_command.side_effect

    def track_exec_command(*args, **kwargs):
        if "start wazuh-agent" in kwargs.get("command", ""):
            call_order.append("start_agent")
        return ("", "")

    mock_exec_command.side_effect = track_exec_command

    core_configurer_instance = CoreConfigurer(inventory=None, files_configuration_path=Path("test_path.yml"))
    core_configurer_instance.start_services(client=None)

    mock_exec_command.side_effect = original_side_effect

    # The agent registration password must be configured exactly once, before starting the agent.
    mock_set_authd_password.assert_called_once_with(client=None)
    assert call_order.index("set_authd_password") < call_order.index("start_agent")


def test_set_authd_password_success(mock_exec_command, mock_logger):
    # First call checks that the manager password file exists, second call copies it to the agent.
    mock_exec_command.side_effect = [("found", ""), ("", "")]
    core_configurer_instance = CoreConfigurer(inventory=None, files_configuration_path=Path("test_path.yml"))
    core_configurer_instance.set_authd_password(client=None)

    check_command = mock_exec_command.call_args_list[0].kwargs["command"]
    assert f"sudo test -f {WAZUH_MANAGER_AUTHD_PASS_FILE}" in check_command

    copy_command = mock_exec_command.call_args_list[1].kwargs["command"]
    assert f"sudo cp {WAZUH_MANAGER_AUTHD_PASS_FILE} {WAZUH_AGENT_AUTHD_PASS_FILE}" in copy_command
    assert f"sudo chown root:wazuh {WAZUH_AGENT_AUTHD_PASS_FILE}" in copy_command
    assert f"sudo chmod 640 {WAZUH_AGENT_AUTHD_PASS_FILE}" in copy_command

    mock_logger.error.assert_not_called()
    mock_logger.debug.assert_any_call("Wazuh agent registration password set successfully")


@patch("configurer.core.core_configurer.time.sleep")
def test_set_authd_password_retries_until_file_is_ready(mock_sleep, mock_exec_command, mock_logger):
    # The manager password file is not ready on the first two checks, then appears.
    mock_exec_command.side_effect = [("", ""), ("", ""), ("found", ""), ("", "")]
    core_configurer_instance = CoreConfigurer(inventory=None, files_configuration_path=Path("test_path.yml"))
    core_configurer_instance.set_authd_password(client=None)

    assert mock_sleep.call_count == 2
    mock_logger.debug.assert_any_call("Wazuh agent registration password set successfully")


@patch("configurer.core.core_configurer.time.sleep")
def test_set_authd_password_file_not_found(mock_sleep, mock_exec_command, mock_logger):
    # The manager password file never appears.
    mock_exec_command.return_value = ("", "")
    core_configurer_instance = CoreConfigurer(inventory=None, files_configuration_path=Path("test_path.yml"))

    with pytest.raises(RuntimeError, match="Wazuh manager Authd password file not found"):
        core_configurer_instance.set_authd_password(client=None)

    assert mock_exec_command.call_count == AUTHD_PASS_MAX_RETRIES
    assert mock_sleep.call_count == AUTHD_PASS_MAX_RETRIES
    mock_logger.error.assert_any_call("Wazuh manager Authd password file not found")


def test_set_authd_password_error(mock_exec_command, mock_logger):
    # The file exists, but copying it to the agent fails.
    mock_exec_command.side_effect = [("found", ""), ("", "some error")]
    core_configurer_instance = CoreConfigurer(inventory=None, files_configuration_path=Path("test_path.yml"))

    with pytest.raises(RuntimeError, match="Error setting the Wazuh agent registration password"):
        core_configurer_instance.set_authd_password(client=None)

    mock_logger.error.assert_any_call("Error setting the Wazuh agent registration password")


@patch("configurer.core.core_configurer.CoreConfigurer.set_authd_password")
def test_start_services_success(mock_set_authd_password, mock_exec_command, mock_logger):
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
    keystore_command_template = f"""
    {start_service_command_template}
    sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username -v admin
    sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password -v admin
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
        command=keystore_command_template.format(component="wazuh-manager").replace("\n", "").replace(" ", ""),
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
