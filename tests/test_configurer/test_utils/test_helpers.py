import subprocess
from unittest.mock import patch

import pytest

from configurer.utils.helpers import run_command


@pytest.fixture
def mock_run():
    with patch("subprocess.run") as mock_run:
        yield mock_run


@pytest.fixture
def mock_logger():
    with patch("configurer.utils.helpers.logger") as mock_logger:
        yield mock_logger


@pytest.mark.parametrize(
    "commands",
    [("echo Hello"), (["echo Hello", "echo World"])],
)
def test_run_command_success_no_output(commands, mock_run, mock_logger):
    mock_run.return_value = subprocess.CompletedProcess(args=commands, returncode=0, stdout="", stderr="")

    result = run_command(commands, output=False)

    assert result is None

    if not isinstance(commands, list):
        commands = [commands]

    for command in commands:
        mock_run.assert_any_call(command, capture_output=True, text=True, shell=True)
        mock_logger.info.assert_any_call(f"Executing: {command}")

    mock_logger.info_success.assert_any_call("Command executed successfully.")


@pytest.mark.parametrize(
    "commands, expected_stdout, expected_stderr, expected_return_code",
    [
        ("echo Hello", ["Hello"], [""], [0]),
        (["echo Hello", "echo World"], ["Hello", "World"], ["", ""], [0, 0]),
    ],
)
def test_run_command_success_output(
    commands, expected_stdout, expected_stderr, expected_return_code, mock_run, mock_logger
):
    def mock_subprocess_run(command, capture_output, text, shell):
        if command == "echo Hello":
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="Hello", stderr="")
        elif command == "echo World":
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="World", stderr="")
        return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="Error")

    mock_run.side_effect = mock_subprocess_run

    result = run_command(commands, output=True)

    assert result == (expected_stdout, expected_stderr, expected_return_code)

    if not isinstance(commands, list):
        commands = [commands]

    for command in commands:
        mock_run.assert_any_call(command, capture_output=True, text=True, shell=True)
        mock_logger.info.assert_any_call(f"Executing: {command}")

    mock_logger.info_success.assert_any_call("Command executed successfully.")


def test_run_command_command_failure_without_check(mock_run, mock_logger):
    mock_run.return_value = subprocess.CompletedProcess(
        args="invalid_command", returncode=1, stdout="", stderr="Error occurred"
    )

    result = run_command("invalid_command", check=False, output=True)

    assert result == ([""], ["Error occurred"], [1])

    mock_run.assert_called_once_with("invalid_command", capture_output=True, text=True, shell=True)
    mock_logger.info.assert_called_once_with("Executing: invalid_command")
    mock_logger.warning.assert_any_call("Command failed with return code 1")
    mock_logger.warning.assert_any_call("Error output: Error occurred")


def test_run_command_command_failure_with_check(mock_run, mock_logger):
    mock_run.return_value = subprocess.CompletedProcess(
        args="invalid_command", returncode=1, stdout="", stderr="Error occurred"
    )

    with pytest.raises(RuntimeError, match="Error executing command: Error occurred"):
        run_command("invalid_command", check=True)

    mock_run.assert_called_once_with("invalid_command", capture_output=True, text=True, shell=True)
    mock_logger.info.assert_called_once_with("Executing: invalid_command")
    mock_logger.error.assert_called_once_with("Error output: Error occurred")
