import os
import re
import shutil
from pathlib import Path

from configurer.ova.ova_pre_configurer.ova_pre_configurer import run_vagrant_up
from generic import exec_command
from utils import Logger

from .helpers import clean_output_lines, get_wazuh_version, render_vagrantfile

ROOT_DIR = Path(__file__).resolve().parent.parent
CURRENT_PATH = Path(__file__).resolve().parent
URL_FILENAME = "artifacts_urls.yaml"
VERSION_FILENAME = "VERSION.json"
STANDARIZE_OVA_FILENAME = "setOVADefault.sh"
OVA_OVF_TEMPLATE = "wazuh_ovf_template"
VAGRANT_METADATA_PATH = ROOT_DIR / ".vagrant" / "machines" / "default" / "virtualbox"
VERSION_FILEPATH = ROOT_DIR / VERSION_FILENAME
OVA_SCRIPTS_PATH = ROOT_DIR / "utils" / "scripts" / "ova_build"
STANDARIZE_OVA_FILEPATH = OVA_SCRIPTS_PATH / STANDARIZE_OVA_FILENAME
OVA_OVF_TEMPLATE_FILEPATH = OVA_SCRIPTS_PATH / OVA_OVF_TEMPLATE

logger = Logger("Build Local OVA")


def setup_execution_environment(vm_name: str, packages_url_path: str) -> None:
    """
    Set up the execution environment for the OVA image creation. This includes copying the packages URL file
    to the root directory and rendering the Vagrantfile with the specified VM name.
    The Vagrantfile is used to configure the virtual machine for the OVA image creation process.

    Args:
        vm_name (str): The name of the virtual machine that will be created throught the Vagrantfile.
        packages_url_path (str): The path to the packages URL file.

    Returns:
        None
    """
    logger.debug_title("Setting up execution environment")

    copied_file = shutil.copy(packages_url_path, ROOT_DIR)
    os.rename(copied_file, ROOT_DIR / URL_FILENAME)

    vagrant_context = {
        "vm_name": vm_name,
    }
    script_dir = ROOT_DIR / "wazuh_local_ova" / "templates"
    output_vagrantfile = ROOT_DIR / "wazuh_local_ova" / "Vagrantfile"

    logger.debug("Creating Vagrantfile")

    render_vagrantfile(
        context=vagrant_context,
        template_dir=str(script_dir),
        template_file="Vagrantfile.j2",
        output_path=str(output_vagrantfile),
    )

    logger.info_success("Vagrantfile created successfully")


def configure_vagrant_vm() -> str:
    """
    Configures a Vagrant virtual machine (VM) for the Wazuh environment.
    Para ello crea una Vagrant VM y dentro de ella, se ejecuta Hatch con la configuración
    usada para crear la OVA productiva.
    # ingles
    This function is responsible for setting up the Wazuh environment in a Vagrant VM.
    It creates a Vagrant VM and executes Hatch with the configuration used to create the production OVA.

    Returns:
        str: The UUID of the configured Vagrant VM.
    """

    logger.debug_title("Creating the Wazuh environment into the VM")
    logger.debug("Running vagrant up")

    run_vagrant_up(vagrantfile=ROOT_DIR / "wazuh_local_ova" / "Vagrantfile")

    vagrant_uuid_file = VAGRANT_METADATA_PATH / "index_uuid"
    with open(vagrant_uuid_file) as file:
        vagrant_uuid = file.read()

    logger.info("""
        Starting the Configuration process. This may take a while. When the process is finished,
        the logs generated during the configuration will be displayed in the console. 
    """)

    command = f"vagrant ssh {vagrant_uuid} -c 'cd /tmp/ && sudo hatch run dev-ova-post-configurer:run --packages-url-path {URL_FILENAME}'"
    output, error_output = exec_command(command=command)
    if error_output:
        raise RuntimeError(f"Error running command in the remote VM: {error_output}")

    logger.info_success("Configuration process finished")
    logger.debug("Displaying logs from the configuration process...")

    spining_pattern = re.compile(
        r"(Installing Python distribution|Creating environment|Installing project in development mode|Syncing dependencies|Checking dependencies)"
    )
    print(clean_output_lines(output, spining_pattern))  # Remove spinner lines from hatch environment

    return vagrant_uuid


def export_ova_image(vagrant_uuid: str, name: str, ova_dest: str) -> None:
    """
    Export the configured Vagrant VM as an OVA image. This function handles the export process,
    including modifying the VM settings, exporting the VM to a temporary directory, and
    standardizing the OVA image.
    Args:
        vagrant_uuid (str): The UUID of the configured Vagrant VM.
        name (str): The name of the OVA image to be created.
        ova_dest (str): The destination directory where the OVA image will be saved.
    Returns:
        None
    """

    logger.info("Exporting the OVA image")

    logger.debug("Getting Wazuh version")
    wazuh_version = get_wazuh_version(version_file=VERSION_FILEPATH)
    vbox_vm_id_file = VAGRANT_METADATA_PATH / "id"
    with open(vbox_vm_id_file) as file:
        vbox_vm_id = file.read()

    logger.debug("Creating temporary directory")
    temp_dir = CURRENT_PATH / "tmp"
    temp_dir.mkdir(exist_ok=True)

    logger.debug("Exporting VM to the temporary directory")
    commands = [
        f"vagrant halt {vagrant_uuid}",
        f'vboxmanage modifyvm "{vbox_vm_id}" --nic2 hostonly',
        f'vboxmanage modifyvm "{vbox_vm_id}" --cableconnected2 on',
        f'vboxmanage export "{vbox_vm_id}" -o "{temp_dir}/{name}-raw.ova"',
        f'bash {STANDARIZE_OVA_FILEPATH} "{temp_dir}" "{temp_dir}/{name}-raw.ova" "{temp_dir}/{name}.ova" "{OVA_OVF_TEMPLATE_FILEPATH}" "{wazuh_version}"',
        f"vagrant destroy -f {vagrant_uuid}",
    ]

    for command in commands:
        _, error_output = exec_command(command=command)
        if error_output and "100%" not in error_output:  # Ignore 100% completion messages
            raise RuntimeError(f"Error running command during the exporting VM proccess: {error_output}")

    logger.debug("OVA configuration process finished, moving the OVA image to the output directory")

    shutil.move(f"{temp_dir}/{name}.ova", f"{ova_dest}/{name}.ova")

    logger.debug("Cleaning up temporary files")
    shutil.rmtree(temp_dir)

    logger.info_success(f"OVA image exported successfully in {ova_dest}/{name}.ova")


def generate_checksum(name: str, ova_dest: str) -> None:
    """
    Generate a SHA512 checksum for the exported OVA image. This function creates a checksum file
    in the same directory as the OVA image, allowing for verification of the image's integrity.
    Args:
        name (str): The name of the OVA image.
        ova_dest (str): The destination directory where the OVA sha file is located.
    Returns:
        None
    """

    logger.debug_title("Generating SHA512 checksum")

    sha512_command = f"sha512sum {ova_dest}/{name}.ova > {ova_dest}/{name}.ova.sha512"
    _, error_output = exec_command(sha512_command)
    if error_output:
        raise RuntimeError(f"Error generating SHA512 checksum: {error_output}")

    logger.info_success(f"SHA512 checksum generated: {ova_dest}/{name}.sha512")
