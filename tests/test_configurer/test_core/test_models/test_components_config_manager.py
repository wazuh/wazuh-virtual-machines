import json
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from configurer.core.models.wazuh_components_config_manager import WazuhComponentConfigManager
from utils.enums import Component


@pytest.fixture
def example_config_file():
    return {
        Component.WAZUH_INDEXER: [
            {"path": "/path/indexer/config", "replace": {"keys": [".key1"], "values": ["value1"]}}
        ],
        Component.WAZUH_MANAGER: [
            {"path": "/path/manager/config.conf", "replace": {"keys": [".key2"], "values": ['"value2"']}}
        ],
        Component.WAZUH_DASHBOARD: [
            {"path": "/path/dashboard/config", "replace": {"keys": [".key3"], "values": ["value3"]}}
        ],
    }


@pytest.fixture
def example_config_file_with_placeholders():
    return {
        Component.WAZUH_INDEXER: [
            {"path": "/path/indexer/config", "replace": {"keys": [".key1"], "values": ["__indexer_node_name__"]}}
        ],
        Component.WAZUH_MANAGER: [
            {"path": "/path/manager/config.conf", "replace": {"keys": [".key2"], "values": ['"__manager_ip__"']}}
        ],
        Component.WAZUH_DASHBOARD: [
            {"path": "/path/dashboard/config", "replace": {"keys": [".key3"], "values": ["value3"]}}
        ],
    }


@pytest.fixture()
def mock_open_file(example_config_file):
    with patch("builtins.open", mock_open(read_data=json.dumps(example_config_file))) as mocked_file:
        yield mocked_file


@pytest.fixture()
def mock_open_file_with_placeholders(example_config_file_with_placeholders):
    with patch("builtins.open", mock_open(read_data=json.dumps(example_config_file_with_placeholders))) as mocked_file:
        yield mocked_file


@pytest.fixture
def mock_exec_command():
    with patch("configurer.core.models.wazuh_components_config_manager.exec_command") as mock_exec_command:
        mock_exec_command.return_value = ("", "")
        yield mock_exec_command


def test_config_manager_initialization(mock_open_file, example_config_file):
    config_manager = WazuhComponentConfigManager(Path("test_path"))
    assert config_manager.config_mappings_file == example_config_file
    mock_open_file.assert_called_once_with(Path("test_path"))


@pytest.mark.parametrize(
    "mapping_property, expected_mapping",
    [
        ("indexer_mapping", {"path": Path("/path/indexer/config"), "keys": [".key1"], "values": ["value1"]}),
        ("manager_mapping", {"path": Path("/path/manager/config.conf"), "keys": [".key2"], "values": ['"value2"']}),
        ("dashboard_mapping", {"path": Path("/path/dashboard/config"), "keys": [".key3"], "values": ["value3"]}),
    ],
)
def test_component_mapping_with_valid_data(mapping_property, expected_mapping, mock_open_file):
    config_manager = WazuhComponentConfigManager(Path("test_path"))
    result = getattr(config_manager, mapping_property)
    assert result.replace_content[0] == expected_mapping


@pytest.mark.parametrize(
    "component_without_mapping", [Component.WAZUH_INDEXER, Component.WAZUH_MANAGER, Component.WAZUH_DASHBOARD]
)
def test_component_mapping_without_data(mock_open_file, component_without_mapping):
    config_manager = WazuhComponentConfigManager(Path("test_path"))
    config_manager.config_mappings_file.pop(component_without_mapping)

    for component in Component:
        # For now we do not have the agent in the core configurer. This will be updated in this issue: https://github.com/wazuh/wazuh-virtual-machines/issues/567
        if component != Component.ALL and component != Component.WAZUH_AGENT and component != component_without_mapping:
            assert getattr(config_manager, f"{component.name.lower().split('_')[1]}_mapping") is not None
    assert getattr(config_manager, f"{component_without_mapping.name.lower().split('_')[1]}_mapping") is None


@pytest.mark.parametrize(
    "component, command_to_execute",
    [
        (Component.WAZUH_INDEXER, "sudo yq -i  '.key1 = \"value1\" ' /path/indexer/config"),
        (
            Component.WAZUH_MANAGER,
            'sudo yq -i -p xml -o xml \'.key2 = ""value2"" | .key2 style="double"\' /path/manager/config.conf',
        ),
        (Component.WAZUH_DASHBOARD, "sudo yq -i  '.key3 = \"value3\" ' /path/dashboard/config"),
    ],
)
def test_replace_file_entries(component, command_to_execute, mock_logger, mock_open_file, mock_exec_command):  #
    config_manager = WazuhComponentConfigManager(Path("test_path"))
    component_path = getattr(config_manager, f"{component.name.lower().split('_')[1]}_mapping").replace_content[0][
        "path"
    ]
    component_key = getattr(config_manager, f"{component.name.lower().split('_')[1]}_mapping").replace_content[0][
        "keys"
    ][0]
    component_value = getattr(config_manager, f"{component.name.lower().split('_')[1]}_mapping").replace_content[0][
        "values"
    ][0]

    config_manager.replace_file_entries(component)
    assert command_to_execute in mock_exec_command.call_args_list[0].kwargs["command"]

    mock_logger.debug.assert_any_call(
        f"Replacing entries for {component.replace('_', ' ').capitalize()} configuration file"
    )
    mock_logger.debug.assert_any_call(f"Replacing key:{component_key} with value:{component_value} in {component_path}")


def test_replace_file_with_invalid_component(mock_logger, mock_open_file):
    config_manager = WazuhComponentConfigManager(Path("test_path"))

    with pytest.raises(ValueError, match="Invalid component: all"):
        config_manager.replace_file_entries(Component.ALL)


@patch.object(WazuhComponentConfigManager, "indexer_mapping", None)
def test_replace_file_without_entries_to_replace(mock_logger, mock_open_file):
    config_manager = WazuhComponentConfigManager(Path("test_path"))

    config_manager.replace_file_entries(Component.WAZUH_INDEXER)
    mock_logger.debug.assert_called_once_with("No entries to replace for Wazuh indexer configuration file")


def test_replace_file_fails_to_execute_command(mock_logger, mock_open_file, mock_exec_command):
    config_manager = WazuhComponentConfigManager(Path("test_path"))
    mock_exec_command.return_value = ("", "Error while replacing key:.key1 with value:value1 in /path/indexer/config")
    with pytest.raises(ValueError, match="Error while replacing key:.key1 with value:value1 in /path/indexer/config: "):
        config_manager.replace_file_entries(Component.WAZUH_INDEXER)
        mock_logger.error.assert_called_once_with(
            "Error while replacing key:.key1 with value:value1 in /path/indexer/config"
        )


def test_replace_placeholders(
    mock_logger, example_config_file_with_placeholders, mock_open_file_with_placeholders, mock_exec_command
):
    config_manager = WazuhComponentConfigManager(Path("test_path"))
    print(example_config_file_with_placeholders)
    value_indexer = example_config_file_with_placeholders[Component.WAZUH_INDEXER][0]["replace"]["values"][0]
    value_manager = example_config_file_with_placeholders[Component.WAZUH_MANAGER][0]["replace"]["values"][0]
    value_dashboard = example_config_file_with_placeholders[Component.WAZUH_DASHBOARD][0]["replace"]["values"][0]

    if "__" in value_indexer:
        config_manager._indexer_placeholder = {value_indexer: "indexer_replacement_value"}
        content = config_manager.indexer_mapping.replace_content  # type: ignore
        config_manager._replace_placeholders(content, Component.WAZUH_INDEXER)
        assert content[0]["values"][0] == "indexer_replacement_value"

    if "__" in value_manager:
        config_manager._manager_placeholder = {value_manager: "manager_replacement_value"}
        content = config_manager.manager_mapping.replace_content  # type: ignore
        config_manager._replace_placeholders(content, Component.WAZUH_MANAGER)
        assert content[0]["values"][0] == "manager_replacement_value"

    if "__" in value_dashboard:
        config_manager._dashboard_placeholder = {value_dashboard: "dashboard_replacement_value"}
        content = config_manager.dashboard_mapping.replace_content  # type: ignore
        config_manager._replace_placeholders(content, Component.WAZUH_DASHBOARD)
        assert content[0]["values"][0] == "dashboard_replacement_value"
