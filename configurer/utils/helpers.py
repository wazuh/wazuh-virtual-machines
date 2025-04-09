import subprocess
from typing import Union

from utils.logger import Logger

logger = Logger("Configurer helpers")


def run_command(
    commands: Union[str, list[str]], check=False, output=False
) -> Union[tuple[list[str], list[str], list[int]], None]:  # noqa: UP007
    """
    Executes one or more shell commands.
    Args:
        commands (Union[str, list[str]]): A single command as a string or a list of commands to execute.
        check (bool, optional): If True, raises a RuntimeError if any command produces an error output. Defaults to False.
        output (bool, optional): If True, returns the stdout, stderr, and return codes of the executed commands in a list. Defaults to False.
    Returns:
        Union[tuple[list[str], list[str], list[int]], None]: If output parameter is True, returns a tuple containing lists of stdout, stderr, and return codes for each command. Otherwise, returns None.
    """
    if isinstance(commands, str):
        commands = [commands]

    stdout_list = []
    stderr_list = []
    returncode_list = []

    for command in commands:
        logger.info(f"Executing: {command}")
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        if check and result.stderr:
            logger.error(f"Error output: {result.stderr}")
            raise RuntimeError(f"Error executing command: {result.stderr}")
        elif not check and result.returncode != 0:
            logger.warning(f"Command failed with return code {result.returncode}")
            logger.warning(f"Error output: {result.stderr}")
        else:
            logger.info_success("Command executed successfully.")

        if output:
            stdout_list.append(result.stdout.strip())
            stderr_list.append(result.stderr.strip())
            returncode_list.append(result.returncode)

    return (stdout_list, stderr_list, returncode_list) if output else None
