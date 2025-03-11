import subprocess
from typing import List, Union

from utils import Logger

logger = Logger("log")


def run_command(commands: Union[List[str], List[List[str]]], check=True) -> List[subprocess.CompletedProcess[str]]:
    if not isinstance(commands[0], list) or isinstance(commands[0], str):
        commands = [commands]
    
    results = []
    for command in commands:
        if not isinstance(commands[0], list) or isinstance(commands[0], str):
            logger.info(f"Executing: {command}")
        else:
            logger.info(f"Executing: {' '.join(command)}")
        try:
            result = subprocess.run(command, check=check, capture_output=True, text=True, shell=True)
            logger.info_success("Command executed successfully.")
            results.append(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing command: {e}")
            raise
    
    return results
