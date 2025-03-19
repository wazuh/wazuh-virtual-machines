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
        Component.WAZUH_SERVER: [{"path": "/path/server/config", "replace": {"keys": [".key2"], "values": ["value2"]}}],
        Component.WAZUH_DASHBOARD: [
            {"path": "/path/dashboard/config", "replace": {"keys": [".key3"], "values": ["value3"]}}
        ],
    }


@pytest.fixture()
def mock_open_file(example_config_file):
    with patch("builtins.open", mock_open(read_data=json.dumps(example_config_file))) as mocked_file:
        yield mocked_file


def test_config_manager_initialization(mock_open_file, example_config_file):
    config_manager = WazuhComponentConfigManager(Path("test_path"))
    assert config_manager.config_mappings_file == example_config_file
    mock_open_file.assert_called_once_with(Path("test_path"))


@pytest.mark.parametrize(
    "mapping_property, expected_mapping",
    [
        ("indexer_mapping", {"path": Path("/path/indexer/config"), "keys": [".key1"], "values": ["value1"]}),
        ("server_mapping", {"path": Path("/path/server/config"), "keys": [".key2"], "values": ["value2"]}),
        ("dashboard_mapping", {"path": Path("/path/dashboard/config"), "keys": [".key3"], "values": ["value3"]}),
    ],
)
def test_indexer_mapping_with_valid_data(mapping_property, expected_mapping, mock_open_file):
    config_manager = WazuhComponentConfigManager(Path("test_path"))
    result = getattr(config_manager, mapping_property)
    assert result.replace_content[0] == expected_mapping
