import os
from pathlib import Path

from configurer.utils import run_command
from utils import Logger

from .generate_base_box import main as generate_base_box_main
from .install_dependencies import main as install_dependencies_main

logger = Logger("OVA PreConfigurer - Main module")

VAGRANTFILE_PATH = "configurer/ova/ova_pre_configurer/static/Vagrantfile"
VAGRANT_BOX_PATH = "al2023.box"


def add_vagrant_box(box_path: str = VAGRANT_BOX_PATH) -> None:
    """
    This function adds the box with the name 'al2023' using the provided box path.

    Args:
        box_path (str): The path to the Vagrant box file. Defaults to VAGRANT_BOX_PATH.

    Returns:
        None
    """
    logger.debug("Adding Vagrant box.")
    run_command(f"vagrant box add --name al2023 {box_path}")


def run_vagrant_up(max_retries: int = 10, vagrantfile: Path | None = None) -> bool | None:
    """
    Attempts to start a Vagrant virtual machine by running the 'vagrant up' command.
    If it fails, it destroys the Vagrant machine and retries the operation up to a specified number of times.

    Args:
        max_retries (int): The maximum number of attempts to start the Vagrant VM. Default is 100.

    Returns:
        bool: True if the Vagrant VM starts successfully, False otherwise.

    Raises:
        RuntimeError: If the Vagrant VM fails to start after the maximum number of retries.
    """
    attempts = 0
    vagrant_command = f"VAGRANT_VAGRANTFILE={vagrantfile} vagrant up" if vagrantfile else "vagrant up"

    while attempts < max_retries:
        attempts += 1
        logger.debug(f"Attempt {attempts} to run 'vagrant up'.")
        stdout, stderr, returncode = run_command(vagrant_command, output=True)
        if returncode[0] == 0:
            logger.info_success("Vagrant VM started.")
            return True

        logger.warning(f"Vagrant VM failed to start on attemtp {attempts}. Retrying...")

        logger.debug("Destroying Vagrant machine")
        run_command("vagrant destroy -f")

        if attempts == max_retries:
            logger.error("Max attemps reached. Failed execution.")
            raise RuntimeError("Vagrant VM failed to start after maximum retries.")


def deploy_vm(vagrantfile_path: str = VAGRANTFILE_PATH) -> None:
    """
    Deploys a virtual machine using Vagrant.

    This function performs the following steps:
    1. Copies the static Vagrantfile to the current directory.
    2. Adds the Vagrant box.
    3. Runs `vagrant up` to start the virtual machine.

    Args:
        vagrantfile_path (str): The path to the Vagrantfile. Defaults to the value of VAGRANTFILE_PATH.

    Returns:
        None
    """
    logger.debug("Deploying VM.")
    run_command(f"cp {vagrantfile_path} .", check=True)
    add_vagrant_box()
    run_vagrant_up()


def prepare_vm() -> None:
    """
    Prepares the deployed virtual machine by installing python3-pip, Hatch and copying the wazuh-virtual-machines repository.
    It removes unnecessary files before copying the repository.

    Returns:
        None
    """
    logger.debug("Installing python3-pip on the VM.")
    run_command('vagrant ssh -c "sudo yum install -y python3-pip"')

    logger.debug("Installing Hatch on the VM.")
    run_command('vagrant ssh -c "sudo pip3 install hatch"')
    run_command('vagrant ssh -c "sudo pip3 install virtualenv==20.31.2"')

    logger.debug("Removing unnecessary files before copying the repository.")
    for filename in os.listdir("."):
        if filename.startswith("al2023") and os.path.isfile(filename):
            os.remove(filename)

    logger.debug("Copying the wazuh-virtual-machines repository to the VM.")
    commands = [
        "vagrant ssh-config > ssh-config",
        "scp -r -F ssh-config ../wazuh-virtual-machines default:/tmp/wazuh-virtual-machines",
    ]
    run_command(commands, check=True)


def main() -> None:
    """
    Main function to run the OVA PreConfigurer process.
    This function performs the following steps:
    1. Runs Dependencies Installer module.
    2. Generates the base box with Amazon Linux 2023.
    3. Deploys the virtual machine using the previously generated Vagrant box.

    Returns:
        None
    """
    logger.info("--- Starting OVA PreConfigurer ---")
    logger.info("Installing dependencies.")
    install_dependencies_main()

    logger.info("Generating base box.")
    generate_base_box_main()

    deploy_vm()
    prepare_vm()
    logger.info_success("OVA PreConfigurer completed.")


if __name__ == "__main__":
    main()
