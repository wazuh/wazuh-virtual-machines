import os
from pathlib import Path

import paramiko
import yaml
from jinja2 import Environment, FileSystemLoader

from generic.helpers import exec_command
from utils import CertificatesComponent, Logger, RemoteDirectories

logger = Logger("Ami Post Customizer")


def create_directory_structure(base_path: str, directory_template: dict, client: paramiko.SSHClient) -> None:
    """
    Create a directory structure on the remote server using SFTP.
    Args:
        directory_template (dict): The directory structure template.
        client (paramiko.SSHClient): The SSH client used for the connection.
    """

    base_path = os.path.join(base_path, directory_template["name"])
    create_directory(base_path, client)

    for file in directory_template.get("files", []):
        file_path = file["path"]
        local = file.get("local", False)
        copy_file_to_directory(file_path, base_path, client, local)

    for directory in directory_template.get("directories", []):
        create_directory_structure(base_path, directory, client)
    
    
def create_directory(path: str, client: paramiko.SSHClient) -> None:
    """
    Create a directory on the remote server using SFTP.

    Args:
        path (Path): The path of the directory to create.
        client (paramiko.SSHClient): The SSH client used for the connection.
    """
    command = f"sudo mkdir -p {path}"
    _, error_output = exec_command(command=command, client=client)
    if error_output:
        logger.error(f"Error creating directory {path}: {error_output}")
        raise RuntimeError(f"Error creating directory {path}: {error_output}")
    logger.debug(f"Directory {path} created successfully")
        
        
def copy_file_to_directory(file_path: str, directory_path: str, client: paramiko.SSHClient, local: bool) -> None:
    """
    Copy a file to a directory on the remote server using SFTP.

    Args:
        file_path (Path): The path of the file to copy.
        directory_path (Path): The destination directory path.
        client (paramiko.SSHClient): The SSH client used for the connection.
    """
    if local:
        sftp = client.open_sftp()
        try:
            sftp.put(file_path, f"/home/ec2-user/{os.path.basename(file_path)}")
        except Exception as e:
            logger.error(f"Error copying file {file_path} to {directory_path}: {e}")
            raise RuntimeError(f"Error copying file {file_path} to {directory_path}: {e}") from e
        
        command = f"sudo mv /home/ec2-user/{os.path.basename(file_path)} {directory_path}"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error(f"Error copying file {file_path} to {directory_path}: {error_output}")
            raise RuntimeError(f"Error copying file {file_path} to {directory_path}: {error_output}")
        
        logger.debug(f"Local file {file_path} copied to {directory_path} remote directory")
    else:
        command = f"sudo cp {file_path} {directory_path}"
        _, error_output = exec_command(command=command, client=client)
        if error_output:
            logger.error(f"Error copying file {file_path} to {directory_path}: {error_output}")
            raise RuntimeError(f"Error copying file {file_path} to {directory_path}: {error_output}")

        logger.debug(f"Remote file {file_path} copied to {directory_path} remote directory")
        

def generate_yaml(context: dict, template_dir: str, template_file: str = "ami_custom_service_directory.j2") -> dict:
    """
    Generate a YAML file from a Jinja2 template and context.
    Args:
        context (dict): The context to render the template.
        template_dir (str): The directory where the template is located.
        template_file (str): The name of the template file.
    Returns:
        dict: The rendered YAML content as a dictionary.
    """

    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template(template_file)

    rendered_yaml = template.render(context)

    yaml_dict = yaml.safe_load(rendered_yaml)

    return yaml_dict


if __name__ == "__main__":
    script_dir = Path(__file__).resolve().parent / "templates"
    context = {
        "remote_certs_path": RemoteDirectories.CERTS,
        "certs_tool": CertificatesComponent.CERTS_TOOL,
        "certs_config": CertificatesComponent.CONFIG,
    }
    yaml_content = generate_yaml(context=context, template_dir=str(script_dir))
    print(yaml_content)