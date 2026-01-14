from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

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


@pytest.fixture
def mock_open_file():
    with patch("builtins.open", mock_open(read_data='{"test_key": "test_value"}')) as mocked_file:
        yield mocked_file


@pytest.fixture
def mock_logger(autouse=True):
    mock = MagicMock()
    logger_paths = [
        "provisioner.provisioner.logger",
        "provisioner.models.certs_info.logger",
        "provisioner.models.password_tool_info.logger",
        "generic.remote_connection.logger",
        "configurer.core.models.wazuh_components_config_manager.logger",
        "configurer.core.models.certificates_manager.logger",
        "configurer.core.core_configurer.logger",
        "configurer.ami.ami_pre_configurer.ami_pre_configurer.logger",
        "configurer.ami.ami_post_configurer.ami_post_configurer.logger",
        "configurer.ami.ami_post_configurer.create_service_directory.logger",
    ]

    patches = [patch(path, mock) for path in logger_paths]

    for p in patches:
        p.start()

    yield mock

    for p in patches:
        p.stop()
