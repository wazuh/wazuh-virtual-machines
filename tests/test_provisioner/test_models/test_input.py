from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
import yaml
from pydantic import SecretStr

from models import Inventory
from provisioner.models.certs_info import CertsInfo
from provisioner.models.components_dependencies import ComponentsDependencies
from provisioner.models.input import Input
from provisioner.models.package_info import PackageInfo
from provisioner.utils import Component_arch, Package_type
from utils import Component

INPUT_EXAMPLE = Input(
    component=Component.WAZUH_INDEXER,
    inventory_path=Path("/path/to/inventory"),
    packages_url_path=Path("/path/to/packages_url"),
    package_type=Package_type.RPM,
    arch=Component_arch.X86_64,
    dependencies_path=Path("/path/to/dependencies"),
)

INVENTORY_EXAMPLE = {
    "all": {
        "hosts": {
            "test_host": {
                "ansible_user": "test_user",
                "ansible_password": "test_password",
                "ansible_host": "127.0.0.1",
                "ansible_connection": "ssh",
                "ansible_port": 22,
                "ansible_ssh_private_key_file": "/path/to/key",
                "ansible_ssh_common_args": "-o StrictHostKeyChecking=no",
            }
        }
    }
}


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data="dependency1: version1\ndependency2: version2\n",
)
def test_dependencies_success(mock_open):
    dependencies = INPUT_EXAMPLE.dependencies

    assert isinstance(dependencies, ComponentsDependencies)
    assert dependencies.dependencies_content == {
        "dependency1": "version1",
        "dependency2": "version2",
    }


@patch("builtins.open", side_effect=FileNotFoundError)
def test_dependencies_file_not_found(mock_open):
    with pytest.raises(FileNotFoundError, match="Dependencies file not found at /path/to/dependencies"):
        _ = INPUT_EXAMPLE.dependencies


@patch("provisioner.models.input.format_component_urls_file")
def test_packages_url_content_success(mock_format_component_urls_file):
    mock_format_component_urls_file.return_value = {
        "package1": "url1",
        "package2": "url2",
    }

    packages_url_content = INPUT_EXAMPLE.packages_url_content

    mock_format_component_urls_file.assert_called_once_with(Path("/path/to/packages_url"))
    assert isinstance(packages_url_content, PackageInfo)
    assert packages_url_content.packages_url_content == {
        "package1": "url1",
        "package2": "url2",
    }
    assert packages_url_content.package_type == Package_type.RPM
    assert packages_url_content.arch == Component_arch.X86_64


@patch("provisioner.models.input.format_component_urls_file", side_effect=FileNotFoundError)
def test_packages_url_content_file_not_found(mock_format_component_urls_file):
    with pytest.raises(FileNotFoundError, match="Packages file not found at /path/to/packages_url"):
        _ = INPUT_EXAMPLE.packages_url_content


@patch("provisioner.models.input.format_certificates_urls_file")
def test_certificates_content_success(mock_format_certificates_urls_file):
    mock_format_certificates_urls_file.return_value = {"cert1": "url1", "cert2": "url2"}

    certificates_content = INPUT_EXAMPLE.certificates_content

    mock_format_certificates_urls_file.assert_called_once_with(Path("/path/to/packages_url"))
    assert isinstance(certificates_content, CertsInfo)
    assert certificates_content.certs_url_content == {"cert1": "url1", "cert2": "url2"}


@patch(
    "provisioner.models.input.format_certificates_urls_file",
    side_effect=FileNotFoundError,
)
def test_certificates_content_file_not_found(mock_format_certificates_urls_file):
    with pytest.raises(FileNotFoundError, match="Certificates file not found at /path/to/packages_url"):
        _ = INPUT_EXAMPLE.certificates_content


@patch("builtins.open", new_callable=mock_open, read_data=yaml.dump(INVENTORY_EXAMPLE))
def test_inventory_content_success(mock_open):
    host_name = "test_host"

    inventory_content = INPUT_EXAMPLE.inventory_content

    assert isinstance(inventory_content, Inventory)
    assert inventory_content.ansible_host_name == host_name
    assert inventory_content.ansible_user == "test_user"
    assert inventory_content.ansible_password == SecretStr("test_password")
    assert inventory_content.ansible_host == "127.0.0.1"
    assert inventory_content.ansible_connection == "ssh"
    assert inventory_content.ansible_port == 22
    assert inventory_content.ansible_ssh_private_key_file == Path("/path/to/key")
    assert inventory_content.ansible_ssh_common_args == "-o StrictHostKeyChecking=no"


@patch("builtins.open", new_callable=mock_open, read_data=yaml.dump(INVENTORY_EXAMPLE))
def test_inventory_content_no_host_name(mock_open):
    inventory_content = INPUT_EXAMPLE.inventory_content

    assert isinstance(inventory_content, Inventory)
    assert inventory_content.ansible_host_name == "test_host"
    assert inventory_content.ansible_user == "test_user"
    assert inventory_content.ansible_password == SecretStr("test_password")
    assert inventory_content.ansible_host == "127.0.0.1"
    assert inventory_content.ansible_connection == "ssh"
    assert inventory_content.ansible_port == 22
    assert inventory_content.ansible_ssh_private_key_file == Path("/path/to/key")
    assert inventory_content.ansible_ssh_common_args == "-o StrictHostKeyChecking=no"
