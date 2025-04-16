import re
import subprocess
from pathlib import Path

import paramiko


def exec_command(command: str, client: paramiko.SSHClient | None = None) -> tuple[str, str]:
    """
    Executes a shell command either locally or on a remote server via SSH.

    Args:
        command (str): The shell command to execute.
        client (paramiko.SSHClient | None, optional): An SSH client instance for remote execution.
            If None, the command is executed locally. Defaults to None.

    Returns:
        tuple[str, str]: A tuple containing the standard output and standard error of the command execution.
            - The first element is the standard output (stdout).
            - The second element is the standard error (stderr).
    """
    if not client:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout
        error_output = result.stderr
    else:
        _, stdout, stderr = client.exec_command(command=command)
        output = stdout.read().decode()
        error_output = stderr.read().decode()

    return output, error_output


def modify_file(filepath: Path, replacements: list[tuple[str, str]], client: paramiko.SSHClient | None = None) -> None:
    """
    Modify the content of a file either locally or on a remote server.

    This function applies a series of string replacements to the content of a file.
    If an SSH client is provided, the modifications are performed on a remote file.
    Otherwise, the modifications are applied to a local file.

    Args:
        filepath (Path): The path to the file to be modified.
        replacements (List[tuple[str, str]]): A list of tuples where each tuple contains
            a target string and its replacement string. Firts string is the pattern to search for,
            and the second string is the replacement.
        client (paramiko.SSHClient | None, optional): An SSH client instance for remote
            file modification. If None, the file is modified locally. Defaults to None.
    Returns:
        None
    """
    if not client:
        modify_file_local(filepath, replacements)
    else:
        modify_file_remote(filepath, replacements, client)


def modify_file_local(filepath: Path, replacements: list[tuple[str, str]]) -> None:
    """
    Modify the content of a local file by applying a series of search-and-replace operations.

    Args:
        filepath (Path): The path to the file to be modified.
        replacements (List[tuple[str, str]]): A list of tuples where each tuple contains a
            pattern (str) to search for and a replacement (str) to substitute. Firts string is the pattern to search for,
            and the second string is the replacement.

    Returns:
        None
    """
    with open(filepath) as file:
        content = file.read()

    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)

    with open(filepath, "w") as file:
        file.write(content)


def modify_file_remote(filepath: Path, replacements: list[tuple[str, str]], client: paramiko.SSHClient) -> None:
    """
    Modifies the content of a remote file by applying a series of search-and-replace operations.

    Args:
        filepath (Path): The path to the remote file to be modified.
        replacements (List[tuple[str, str]]): A list of tuples where each tuple contains a pattern to search for
            and its corresponding replacement string. Firts string is the pattern to search for,
            and the second string is the replacement.
        client (paramiko.SSHClient): An active SSH client used to execute commands on the remote machine.

    Returns:
        None
    """
    try:
        output, error_output = exec_command(f"sudo cat {filepath}", client)
        if error_output:
            raise RuntimeError(f"Error reading {filepath}: {error_output}")

        for pattern, replacement in replacements:
            output = re.sub(pattern, replacement, output, flags=re.MULTILINE)

        command = f"sudo tee {filepath} > /dev/null <<EOF\n{output}\nEOF"
        output, error_output = exec_command(command, client)
        if error_output:
            raise RuntimeError(f"Error writing to {filepath}: {error_output}")
    except Exception as e:
        raise RuntimeError(f"Failed to modify {filepath}: {str(e)}") from e


def change_inventory_user(inventory_path: Path, new_user: str) -> None:
    with open(inventory_path) as file:
        content = file.read()

    new_content = re.sub(r"(?<=ansible_user:).+", f" {new_user}", content)

    with open(inventory_path, "w") as file:
        file.write(new_content)
