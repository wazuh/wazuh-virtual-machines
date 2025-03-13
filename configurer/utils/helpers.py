import subprocess
from typing import List, Tuple, Union

from utils.logger import Logger

logger = Logger("Configurer helpers")

def run_command(commands: Union[str, List[str]], check=False, output=False) -> Union[Tuple[List[str], List[str], List[int]], None]:    
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
