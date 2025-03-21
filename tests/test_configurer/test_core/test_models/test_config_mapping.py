from pathlib import Path

import pytest

from configurer.core.models.wazuh_config_mapping import WazuhConfigMapping


def test_set_content_valid_input():
    files_config = [
        {"path": "/path/to/file1", "replace": {"keys": ["key1", "key2"], "values": ["value1", "value2"]}},
        {"path": "/path/to/file2", "replace": {"keys": ["key3"], "values": ["value3"]}},
    ]
    wazuh_config_mapping = WazuhConfigMapping(files_config)
    expected_output = [
        {"path": Path("/path/to/file1"), "keys": ["key1", "key2"], "values": ["value1", "value2"]},
        {"path": Path("/path/to/file2"), "keys": ["key3"], "values": ["value3"]},
    ]
    assert wazuh_config_mapping.replace_content == expected_output


def test_set_content_missing_keys_or_values():
    files_config = [
        {"path": "/path/to/file1", "replace": {"keys": ["key1", "key2"]}},
    ]
    with pytest.raises(KeyError, match="Missing 'keys' or 'values' key in 'replace' mapping file section"):
        WazuhConfigMapping(files_config)


def test_set_content_missing_path():
    files_config = [
        {"replace": {"keys": ["key1", "key2"], "values": ["value1", "value2"]}},
    ]
    with pytest.raises(KeyError, match="The key 'replace' or 'path' was not found in the mapping file"):
        WazuhConfigMapping(files_config)


def test_set_content_missing_type_section():
    files_config = [
        {"path": "/path/to/file1"},
    ]
    with pytest.raises(KeyError, match="The key 'replace' or 'path' was not found in the mapping file"):
        WazuhConfigMapping(files_config)


def test_set_content_empty_input():
    files_config = []
    wazuh_config_mapping = WazuhConfigMapping(files_config)
    assert wazuh_config_mapping.replace_content == []
