from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from provisioner.models.utils.file_formatter import (
    Component,
    file_to_dict,
    format_certificates_urls_file,
    format_component_urls_file,
    get_component_packages,
    get_component_packages_by_arch,
    get_component_packages_by_type,
)


@patch("builtins.open", new_callable=mock_open, read_data="key: value")
def test_file_to_dict_valid_file(mock_file):
    new_dict = file_to_dict(Path("fake_path.yaml"))
    assert new_dict == {"key": "value"}

@patch("builtins.open", new_callable=mock_open, read_data="{}")
def test_file_to_dict_empty_file(mock_file):
    with pytest.raises(ValueError, match="No content found in raw URLs file"):
        file_to_dict(Path("fake_path.yaml"))

@patch("builtins.open", side_effect=FileNotFoundError)
def test_file_to_dict_non_existent_file(mock_file):
    with pytest.raises(FileNotFoundError, match="File not found in non_existent.yaml path"):
        file_to_dict(Path("non_existent.yaml"))

def test_get_component_packages_valid():
    raw_urls_content = {
        "wazuh_indexer_url_amd64_deb": "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
        "wazuh_indexer_url_arm64_deb": "https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/",
        "wazuh_server_url_amd64_deb": "https://packages.wazuh.com/wazuh-server-example/amd64/deb/",
    }
    component = Component.WAZUH_INDEXER
    expected_output = {
        "wazuh_indexer": [
            "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
            "https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/",
        ]
    }
    assert get_component_packages(raw_urls_content, component) == expected_output

def test_get_component_packages_no_matching_component():
    raw_urls_content = {
        "wazuh_indexer_url_amd64_deb": "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
        "wazuh_indexer_url_arm64_deb": "https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/",
    }
    component = Component.WAZUH_SERVER
    expected_output = {}
    assert get_component_packages(raw_urls_content, component) == expected_output

def test_get_component_packages_empty_raw_urls_content():
    raw_urls_content = {}
    component = Component.WAZUH_INDEXER
    expected_output = {}
    assert get_component_packages(raw_urls_content, component) == expected_output



def test_get_component_packages_by_arch_valid():
    component_packages = [
        "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
        "https://packages.wazuh.com/wazuh-indexer-example/x86_64/rpm/",
    ]
    expected_output = {
        "amd64": "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
        "x86_64": "https://packages.wazuh.com/wazuh-indexer-example/x86_64/rpm/",
    }
    assert get_component_packages_by_arch(component_packages) == expected_output

def test_get_component_packages_by_arch_no_matching_arch():
    component_packages = [
        "https://packages.wazuh.com/wazuh-indexer-example/noarch/deb/",
    ]
    expected_output = {}
    assert get_component_packages_by_arch(component_packages) == expected_output

def test_get_component_packages_by_arch_empty_list():
    component_packages = []
    expected_output = {}
    assert get_component_packages_by_arch(component_packages) == expected_output

def test_get_component_packages_by_arch_partial_match():
    component_packages = [
        "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
        "https://packages.wazuh.com/wazuh-indexer-example/noarch/deb/",
    ]
    expected_output = {
        "amd64": "https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/",
    }
    assert get_component_packages_by_arch(component_packages) == expected_output

def test_get_component_packages_by_type_valid():
    component_packages = {
        'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
        'arm64': 'https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/',
        'x86_64': 'https://packages.wazuh.com/wazuh-indexer-example/x86_64/rpm/',
    }
    expected_output = {
        'deb': {
            'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
            'arm64': 'https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/',
        },
        'rpm': {
            'x86_64': 'https://packages.wazuh.com/wazuh-indexer-example/x86_64/rpm/',
        }
    }
    assert get_component_packages_by_type(component_packages) == expected_output

def test_get_component_packages_by_type_no_matching_type():
    component_packages = {
        'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/noarch/',
    }
    expected_output = {
        'deb': {},
        'rpm': {},
    }
    assert get_component_packages_by_type(component_packages) == expected_output

def test_get_component_packages_by_type_empty_dict():
    component_packages = {}
    expected_output = {
        'deb': {},
        'rpm': {},
    }
    assert get_component_packages_by_type(component_packages) == expected_output

def test_get_component_packages_by_type_partial_match():
    component_packages = {
        'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
        'arm64': 'https://packages.wazuh.com/wazuh-indexer-example/arm64/noarch/',
    }
    expected_output = {
        'deb': {
            'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
        },
        'rpm': {},
    }
    assert get_component_packages_by_type(component_packages) == expected_output

@patch("builtins.open", new_callable=mock_open, read_data="certs_tool: certs-url\ncerts_config: certs_config-url")
def test_format_certificates_urls_file_valid(mock_file):
    expected_output = {
        'certs_tool': 'certs-url',
        'config': 'certs_config-url'
    }
    assert format_certificates_urls_file(Path("fake_certificates_urls.yaml")) == expected_output

@patch("builtins.open", new_callable=mock_open, read_data="{}")
def test_format_certificates_urls_file_empty(mock_file):
    with pytest.raises(ValueError, match="No content found in raw URLs file"):
        format_certificates_urls_file(Path("fake_certificates_urls.yaml"))

@patch("builtins.open", new_callable=mock_open, read_data="certs_tool: certs-tool-url")
def test_format_certificates_urls_file_partial(mock_file):
    raw_urls_path = Path("fale_certificates_urls.yaml")
    expected_output = {
        'certs_tool': 'certs-tool-url',
        'config': ''
    }
    assert format_certificates_urls_file(raw_urls_path) == expected_output
    
@patch("builtins.open", new_callable=mock_open, read_data="""
wazuh_indexer_url_amd64_deb: https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/
wazuh_indexer_url_arm64_deb: https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/
wazuh_server_url_x86_64_rpm: https://packages.wazuh.com/wazuh-server-example/x86_64/rpm/
""")
def test_format_component_urls_file_valid(mock_file):
    expected_output = {
        'wazuh_indexer': {
            'deb': {
                'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
                'arm64': 'https://packages.wazuh.com/wazuh-indexer-example/arm64/deb/',
            },
            'rpm': {}
        },
        'wazuh_server': {
            'deb': {},
            'rpm': {
                'x86_64': 'https://packages.wazuh.com/wazuh-server-example/x86_64/rpm/',
            }
        },
        'wazuh_dashboard': {
            'deb': {},
            'rpm': {}
        }
    }
    assert format_component_urls_file(Path("fake_component_urls.yaml")) == expected_output

@patch("builtins.open", new_callable=mock_open, read_data="{}")
def test_format_component_urls_file_empty(mock_file):
    with pytest.raises(ValueError, match="No content found in raw URLs file"):
        format_component_urls_file(Path("fake_component_urls.yaml"))

@patch("builtins.open", new_callable=mock_open, read_data="""
wazuh_indexer_url_amd64_deb: https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/
wazuh_server_url_arm64_rpm: https://packages.wazuh.com/wazuh-server-example/x86_64/rpm/
""")
def test_format_component_urls_file_partial(mock_file):
    expected_output = {
        'wazuh_indexer': {
            'deb': {
                'amd64': 'https://packages.wazuh.com/wazuh-indexer-example/amd64/deb/',
            },
            'rpm': {}
        },
        'wazuh_server': {
            'deb': {},
            'rpm': {
                'x86_64': 'https://packages.wazuh.com/wazuh-server-example/x86_64/rpm/',
            },
        },
        'wazuh_dashboard': {
            'deb': {},
            'rpm': {}
        }
    }
    assert format_component_urls_file(Path("fake_component_urls.yaml")) == expected_output

@patch("builtins.open", side_effect=FileNotFoundError)
def test_format_component_urls_file_non_existent(mock_file):
    with pytest.raises(FileNotFoundError, match="File not found in non_existent.yaml path"):
        format_component_urls_file(Path("non_existent.yaml"))
