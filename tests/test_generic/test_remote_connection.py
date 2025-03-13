from dataclasses import dataclass
from unittest.mock import MagicMock, patch

from generic import remote_connection
from models import Inventory


@dataclass
class MockedClass:
    inventory: Inventory | None = None

    @remote_connection
    def some_method(self, *args, **kwargs):
        return kwargs.get("client")


@patch("paramiko.SSHClient")
def test_remote_connection_with_inventory(
    mock_paramiko, mock_logger, valid_inventory
):  # inventory fixture is provided by conftest.py
    instance = MockedClass(inventory=valid_inventory)

    mock_client = MagicMock()
    mock_paramiko.return_value = mock_client

    result = instance.some_method()

    mock_paramiko.assert_called_once()
    mock_client.connect.assert_called_once_with(
        hostname="127.0.0.1", username="test_user", port=22, password="test_password", key_filename="/path/to/key"
    )
    assert result == mock_client

    assert mock_logger[2].info_success.call_count == 2

    mock_logger[2].info_success.assert_any_call("Connected to host 127.0.0.1")
    mock_logger[2].info_success.assert_any_call("Closing connection to host 127.0.0.1")


@patch("paramiko.SSHClient")
def test_remote_connection_without_inventory(mock_paramiko, mock_logger):
    instance = MockedClass(inventory=None)

    result = instance.some_method()

    mock_paramiko.assert_not_called()
    assert result is None

    assert mock_logger[2].warning.call_count == 1
    mock_logger[2].info_success.assert_not_called()
    mock_logger[2].warning.assert_called_once_with("No inventory provided. Using local connection")
