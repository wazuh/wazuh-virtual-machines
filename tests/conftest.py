from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
import yaml

from models.inventory import Inventory

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

@pytest.fixture
@patch("builtins.open", new_callable=mock_open, read_data=yaml.dump(CORRECT_INVENTORY))
def valid_inventory(mock_open) -> Inventory:
    return Inventory(Path("mocked_path.yml"))

@pytest.fixture()
def mock_logger():
    with patch("provisioner.provisioner.logger") as mock_logger_provisioner, patch(
        "provisioner.models.certs_info.logger"
    ) as mock_logger_certs, patch("generic.remote_connection.logger") as mock_logger_remote_connection:
        yield mock_logger_provisioner, mock_logger_certs, mock_logger_remote_connection
