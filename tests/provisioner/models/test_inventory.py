from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
import yaml
from pydantic import SecretStr

from provisioner.models.inventory import Inventory

CORRECT_INVENTORY = {
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

INVENTORY_WITHOUT_HOSTS_KEY = {
    "all": {
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

INVENTORY_WITHOUT_ALL_KEY = {
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

INVENTORY_WITHOUT_HOST_USER = {
    "all": {
        "hosts": {
            "test_host": {
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


@patch("builtins.open", new_callable=mock_open, read_data=yaml.dump(CORRECT_INVENTORY))
def test_inventory_init_success(mock_open):
    inventory = Inventory(inventory_path=Path("testing"), host_name="test_host")

    assert inventory.ansible_host_name == "test_host"
    assert inventory.ansible_user == "test_user"
    assert inventory.ansible_password == SecretStr("test_password")
    assert inventory.ansible_host == "127.0.0.1"
    assert inventory.ansible_connection == "ssh"
    assert inventory.ansible_port == 22
    assert inventory.ansible_ssh_private_key_file == Path("/path/to/key")
    assert inventory.ansible_ssh_common_args == "-o StrictHostKeyChecking=no"


@patch("builtins.open", side_effect=FileNotFoundError)
def test_inventory_init_file_not_found(mock_open):
    inventory_path = Path("not_found_path")

    with pytest.raises(FileNotFoundError, match=f"Inventory file not found at {inventory_path}"):
        Inventory(inventory_path=inventory_path)


@patch("builtins.open", new_callable=mock_open, read_data=yaml.dump(CORRECT_INVENTORY))
def test_inventory_host_not_found(mock_open):
    with pytest.raises(KeyError, match="Host non_existent_host not found in inventory file"):
        Inventory(inventory_path=Path("testing"), host_name="non_existent_host")


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data=yaml.dump(INVENTORY_WITHOUT_HOSTS_KEY),
)
def test_inventory_invalid_format_missing_hosts(mock_open):
    with pytest.raises(KeyError, match="Invalid inventory format: 'hosts' section is missing"):
        Inventory(inventory_path=Path("testing"), host_name="test_host")


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data=yaml.dump(INVENTORY_WITHOUT_ALL_KEY),
)
def test_inventory_invalid_format_missing_all(mock_open):
    with pytest.raises(ValueError, match="Invalid inventory format: 'all' section is missing"):
        Inventory(inventory_path=Path("testing"), host_name="test_host")


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data=yaml.dump(INVENTORY_WITHOUT_HOST_USER),
)
def test_inventory_invalid_format_missing_user(mock_open):
    with pytest.raises(ValueError, match="Invalid inventory host parameters. Use the correct ones"):
        Inventory(inventory_path=Path("testing"), host_name="test_host")


@patch("builtins.open", new_callable=mock_open, read_data=yaml.dump(CORRECT_INVENTORY))
def test_inventory_to_dict(mock_open):
    inventory = Inventory(inventory_path=Path("testing"))
    CORRECT_INVENTORY["all"]["hosts"]["test_host"]["ansible_password"] = SecretStr("test_password")

    assert inventory.to_dict() == CORRECT_INVENTORY.get("all", {}).get("hosts", {})


@patch("builtins.open", new_callable=mock_open, read_data=yaml.dump(CORRECT_INVENTORY))
def test_check_inventory_without_host_name(mock_open):
    inventory = Inventory(inventory_path=Path("testing"))
    assert inventory.ansible_host_name == "test_host"
