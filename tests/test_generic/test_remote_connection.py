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
def test_remote_connection_with_inventory(mock_paramiko, mock_logger, valid_inventory):
    instance = MockedClass(inventory=valid_inventory)

    mock_client = MagicMock()
    mock_paramiko.return_value = mock_client

    result = instance.some_method()

    mock_paramiko.assert_called_once()
    mock_client.connect.assert_called_once_with(
        hostname="127.0.0.1", username="test_user", port=22, password="test_password", key_filename="/path/to/key"
    )
    assert result == mock_client

    # Verificar que se llamaron los logs correctamente
    mock_logger.info_success.assert_any_call("Connected to host 127.0.0.1")
    mock_logger.info_success.assert_any_call("Closing connection to host 127.0.0.1")


@patch("paramiko.SSHClient")
def test_remote_connection_without_inventory(mock_paramiko, mock_logger):
    instance = MockedClass(inventory=None)

    result = instance.some_method()

    mock_paramiko.assert_not_called()
    assert result is None

    mock_logger.warning.assert_called_once_with("No inventory provided. Using local connection")
