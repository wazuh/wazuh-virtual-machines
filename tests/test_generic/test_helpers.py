from unittest.mock import MagicMock, patch

import pytest

from generic import exec_command


@pytest.mark.parametrize(
    "command, client, expected_output, expected_error_output",
    [
        ("echo 'Hello, World!'", None, "Hello, World!\n", ""),
        ("invalid_command", None, "", "sh: 1: invalid_command: not found\n"),
    ],
)
def test_exec_command_local(command, client, expected_output, expected_error_output):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = expected_output
        mock_run.return_value.stderr = expected_error_output

        output, error_output = exec_command(command, client)

        mock_run.assert_called_once_with(command, shell=True, capture_output=True, text=True)
        assert output == expected_output
        assert error_output == expected_error_output


@pytest.mark.parametrize(
    "command, expected_output, expected_error_output",
    [
        ("echo 'Hello, World!'", "Hello, World!\n", ""),
        ("invalid_command", "", "sh: 1: invalid_command: not found\n"),
    ],
)
@patch("paramiko.SSHClient")
def test_exec_command_remote(mock_paramiko, command, expected_output, expected_error_output):
    mock_client_instance = MagicMock()
    mock_paramiko.return_value = mock_client_instance

    mock_stdout = MagicMock()
    mock_stdout.read.return_value = expected_output.encode()
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = expected_error_output.encode()

    mock_client_instance.exec_command.return_value = (None, mock_stdout, mock_stderr)

    output, error_output = exec_command(command, mock_client_instance)

    mock_client_instance.exec_command.assert_called_once_with(command=command)
    assert output == expected_output
    assert error_output == expected_error_output
