from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from generic import exec_command
from generic.helpers import change_inventory_user, modify_file_local, modify_file_remote


# Fixture needed for the modify method
@pytest.fixture
def mock_exec_command():
    mock_exec_command = MagicMock()
    with patch("generic.helpers.exec_command", mock_exec_command):
        mock_exec_command.return_value = "", ""
        yield mock_exec_command


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


def test_modify_file_local(mock_open_file):
    filepath = Path("test.txt")
    # the default data that return the mock_open_file is '{"test_key": "test_value"}'
    replacements = [("test_key", "new_test_key"), ("test_value", "new_test_value")]

    modify_file_local(filepath, replacements)

    mock_open_file.assert_any_call(filepath)
    mock_open_file.assert_any_call(filepath, "w")
    mock_open_file.return_value.write.assert_called_once_with('{"new_test_key": "new_test_value"}')


@patch("paramiko.SSHClient")
def test_modify_file_remote(mock_paramiko, mock_exec_command):
    filepath = Path("test.txt")
    replacements = [("test_key", "test_remote_key"), ("test_value", "test_remote_value")]
    content = '{"test_key": "test_value"}'
    expected_content = '{"test_remote_key": "test_remote_value"}'
    mock_exec_command.side_effect = [(content, ""), ("", "")]
    mock_paramiko.return_value = MagicMock()

    modify_file_remote(filepath, replacements, mock_paramiko.return_value)

    commands = [
        f"sudo cat {filepath}",
        f"sudo tee {filepath} > /dev/null <<EOF\n{expected_content}\nEOF",
    ]

    for command in commands:
        mock_exec_command.assert_any_call(command, mock_paramiko.return_value)


@patch("paramiko.SSHClient")
def test_modify_file_remote_fails_to_read_content(mock_paramiko, mock_exec_command):
    filepath = Path("test.txt")
    replacements = [("test_key", "test_remote_key"), ("test_value", "test_remote_value")]
    content = '{"test_key": "test_value"}'

    mock_exec_command.return_value = (content, "Error")
    mock_paramiko.return_value = MagicMock()

    with pytest.raises(RuntimeError, match="Error reading test.txt: Error"):
        modify_file_remote(filepath, replacements, mock_paramiko.return_value)

    command = f"sudo cat {filepath}"

    mock_exec_command.assert_any_call(command, mock_paramiko.return_value)


@patch("paramiko.SSHClient")
def test_modify_file_remote_fails_to_write_content(mock_paramiko, mock_exec_command):
    filepath = Path("test.txt")
    replacements = [("test_key", "test_remote_key"), ("test_value", "test_remote_value")]
    content = '{"test_key": "test_value"}'
    expected_content = '{"test_remote_key": "test_remote_value"}'
    mock_exec_command.side_effect = [(content, ""), ("", "Error")]
    mock_paramiko.return_value = MagicMock()

    with pytest.raises(RuntimeError, match="Error writing to test.txt: Error"):
        modify_file_remote(filepath, replacements, mock_paramiko.return_value)

    commands = [
        f"sudo cat {filepath}",
        f"sudo tee {filepath} > /dev/null <<EOF\n{expected_content}\nEOF",
    ]

    for command in commands:
        mock_exec_command.assert_any_call(command, mock_paramiko.return_value)


def test_change_inventory_user(mock_open_file):
    inventory_path = Path("inventory.yml")
    new_user = "new_user"

    change_inventory_user(inventory_path, new_user)

    mock_open_file.assert_any_call(inventory_path)
    mock_open_file.assert_any_call(inventory_path, "w")
