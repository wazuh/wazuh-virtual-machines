from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from generic.helpers import add_content_to_file, change_inventory_user, exec_command, modify_file


@pytest.fixture
def mock_exec_command():
    """Patches generic.helpers.exec_command and returns the mock."""
    m = MagicMock(return_value=("", ""))
    with patch("generic.helpers.exec_command", m):
        yield m


@pytest.mark.parametrize(
    "command, expected_output, expected_error",
    [
        ("echo 'Hello, World!'", "Hello, World!\n", ""),
        ("invalid_command", "", "sh: 1: invalid_command: not found\n"),
    ],
)
def test_exec_command_local(command, expected_output, expected_error):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = expected_output
        mock_run.return_value.stderr = expected_error

        output, error_output = exec_command(command, client=None)

        mock_run.assert_called_once_with(command, shell=True, capture_output=True, text=True)
        assert output == expected_output
        assert error_output == expected_error


@pytest.mark.parametrize(
    "command, expected_output, expected_error",
    [
        ("echo 'Hello, World!'", "Hello, World!\n", ""),
        ("invalid_command", "", "sh: 1: invalid_command: not found\n"),
    ],
)
def test_exec_command_remote(command, expected_output, expected_error):
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = expected_output.encode()
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = expected_error.encode()
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    output, error_output = exec_command(command, client=mock_client)

    mock_client.exec_command.assert_called_once_with(command=command)
    assert output == expected_output
    assert error_output == expected_error


def test_modify_file_applies_replacements(mock_exec_command):
    filepath = Path("test.txt")
    original_content = '{"key": "value", "foo": "bar"}'
    expected_content = '{"new_key": "new_value", "foo": "bar"}'
    replacements = [("key", "new_key"), ("value", "new_value")]

    mock_exec_command.side_effect = [(original_content, ""), ("", "")]

    modify_file(filepath, replacements)

    write_command = f"sudo tee {filepath} > /dev/null <<EOF\n{expected_content}\nEOF"
    mock_exec_command.assert_any_call(f"sudo cat {filepath}", None)
    mock_exec_command.assert_any_call(write_command, None)


def test_modify_file_multiple_replacements(mock_exec_command):
    filepath = Path("config.conf")
    original = "host=localhost\nport=9200\nuser=admin"
    expected = "host=remotehost\nport=9200\nuser=elastic"
    replacements = [("localhost", "remotehost"), ("admin", "elastic")]

    mock_exec_command.side_effect = [(original, ""), ("", "")]

    modify_file(filepath, replacements)

    write_command = f"sudo tee {filepath} > /dev/null <<EOF\n{expected}\nEOF"
    mock_exec_command.assert_any_call(write_command, None)


def test_modify_file_no_replacements(mock_exec_command):
    filepath = Path("unchanged.txt")
    content = "nothing changes here"

    mock_exec_command.side_effect = [(content, ""), ("", "")]

    modify_file(filepath, [])

    write_command = f"sudo tee {filepath} > /dev/null <<EOF\n{content}\nEOF"
    mock_exec_command.assert_any_call(write_command, None)


def test_modify_file_raises_on_read_error(mock_exec_command):
    filepath = Path("test.txt")
    mock_exec_command.return_value = ("", "Permission denied")

    with pytest.raises(RuntimeError, match="Error reading test.txt: Permission denied"):
        modify_file(filepath, [])


def test_modify_file_raises_on_write_error(mock_exec_command):
    filepath = Path("test.txt")
    content = "some content"
    mock_exec_command.side_effect = [(content, ""), ("", "Read-only file system")]

    with pytest.raises(RuntimeError, match="Error writing to test.txt: Read-only file system"):
        modify_file(filepath, [])


def test_modify_file_remote_applies_replacements(mock_exec_command):
    filepath = Path("remote.txt")
    original_content = '{"test_key": "test_value"}'
    expected_content = '{"remote_key": "remote_value"}'
    replacements = [("test_key", "remote_key"), ("test_value", "remote_value")]
    mock_client = MagicMock()

    mock_exec_command.side_effect = [(original_content, ""), ("", "")]

    modify_file(filepath, replacements, client=mock_client)

    mock_exec_command.assert_any_call(f"sudo cat {filepath}", mock_client)
    write_command = f"sudo tee {filepath} > /dev/null <<EOF\n{expected_content}\nEOF"
    mock_exec_command.assert_any_call(write_command, mock_client)


def test_modify_file_remote_raises_on_read_error(mock_exec_command):
    filepath = Path("remote.txt")
    mock_client = MagicMock()
    mock_exec_command.return_value = ("", "Connection refused")

    with pytest.raises(RuntimeError, match="Error reading remote.txt: Connection refused"):
        modify_file(filepath, [], client=mock_client)


def test_modify_file_remote_raises_on_write_error(mock_exec_command):
    filepath = Path("remote.txt")
    mock_client = MagicMock()
    mock_exec_command.side_effect = [("content", ""), ("", "Disk full")]

    with pytest.raises(RuntimeError, match="Error writing to remote.txt: Disk full"):
        modify_file(filepath, [], client=mock_client)


def test_change_inventory_user_replaces_user():
    inventory_path = Path("inventory.yml")
    original = "ansible_user: old_user\nansible_host: 127.0.0.1\n"
    expected = "ansible_user: new_user\nansible_host: 127.0.0.1\n"
    m = mock_open(read_data=original)

    with patch("builtins.open", m):
        change_inventory_user(inventory_path, "new_user")

    m.assert_any_call(inventory_path)
    m.assert_any_call(inventory_path, "w")
    m().write.assert_called_once_with(expected)


def test_change_inventory_user_preserves_rest_of_file():
    inventory_path = Path("inventory.yml")
    original = "all:\n  hosts:\n    myhost:\n      ansible_user: deployer\n      ansible_port: 22\n"
    expected = "all:\n  hosts:\n    myhost:\n      ansible_user: admin\n      ansible_port: 22\n"
    m = mock_open(read_data=original)

    with patch("builtins.open", m):
        change_inventory_user(inventory_path, "admin")

    m().write.assert_called_once_with(expected)


def test_add_content_to_file_local_success(mock_exec_command):
    filepath = Path("test.txt")
    content = "new line"

    add_content_to_file(filepath, content)

    expected_command = f"echo '{content}' | sudo tee -a {filepath} > /dev/null"
    mock_exec_command.assert_called_once_with(expected_command, None)


def test_add_content_to_file_remote_success(mock_exec_command):
    filepath = Path("remote.txt")
    content = "remote line"
    mock_client = MagicMock()

    mock_exec_command.return_value = ("", "")

    add_content_to_file(filepath, content, client=mock_client)

    expected_command = f"echo '{content}' | sudo tee -a {filepath} > /dev/null"
    mock_exec_command.assert_called_once_with(expected_command, mock_client)


def test_add_content_to_file_raises_on_stderr_local(mock_exec_command):
    filepath = Path("test.txt")
    content = "line"
    mock_exec_command.return_value = ("", "Permission denied")

    with pytest.raises(
        RuntimeError,
        match="Failed to append to test.txt: Error appending to test.txt: Permission denied",
    ):
        add_content_to_file(filepath, content)
