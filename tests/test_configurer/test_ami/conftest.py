from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_paramiko():
    with patch("paramiko.SSHClient") as mock_ssh_client:
        client_mock = MagicMock()
        mock_ssh_client.return_value = client_mock

        stdin, stdout, stderr = MagicMock(), MagicMock(), MagicMock()

        stdout.read.return_value.decode.return_value = ""
        stderr.read.return_value.decode.return_value = ""

        client_mock.exec_command.return_value = (stdin, stdout, stderr)

        client_mock.open_sftp.return_value = MagicMock()

        yield mock_ssh_client
