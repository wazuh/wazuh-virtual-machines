import re
import subprocess
from pathlib import Path
from typing import List

import paramiko


def exec_command(command: str, client: paramiko.SSHClient | None = None) -> tuple[str, str]:
    if not client:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout
        error_output = result.stderr
    else:
        stdin, stdout, stderr = client.exec_command(command=command)
        output = stdout.read().decode()
        error_output = stderr.read().decode()

    return output, error_output


def modify_file(filepath: Path, replacements: List[tuple[str, str]], client: paramiko.SSHClient | None = None) -> None:
    if not client:
        modify_file_local(filepath, replacements)
    else:
        modify_file_remote(filepath, replacements, client)


def modify_file_local(filepath: Path, replacements: List[tuple[str, str]]) -> None:
    with open(filepath) as file:
        content = file.read()

    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)

    with open(filepath, "w") as file:
        file.write(content)


def modify_file_remote(filepath: Path, replacements: List[tuple[str, str]], client: paramiko.SSHClient) -> None:
    try:
        output, error_output = exec_command(f"sudo cat {filepath}", client)
        if error_output:
            raise RuntimeError(f"Error reading {filepath}: {error_output}")

        for pattern, replacement in replacements:
            output = re.sub(pattern, replacement, output)

        command = f"sudo tee {filepath} > /dev/null <<EOF\n{output}\nEOF"
        output, error_output = exec_command(command, client)
        if error_output:
            raise RuntimeError(f"Error writing to {filepath}: {error_output}")
    except Exception as e:
        raise RuntimeError(f"Failed to modify {filepath}: {str(e)}") from e
