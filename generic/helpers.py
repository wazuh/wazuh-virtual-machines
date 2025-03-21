import subprocess

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
