import re
import shutil
import urllib.request
from pathlib import Path
from typing import Literal

import yaml

from configurer.ova.ova_pre_configurer.ova_pre_configurer import run_vagrant_up
from generic import exec_command
from utils import Logger

from .enums import ArtifactFilePath, EnvironmentType
from .helpers import clean_output_lines, get_wazuh_stage, get_wazuh_version, render_vagrantfile

ROOT_DIR = Path(__file__).resolve().parent.parent
CURRENT_PATH = Path(__file__).resolve().parent
ARTIFACT_URLS_FILENAME = "artifact_urls.yml"
VAGRANT_BOX_YAML_KEY = "wazuh_ova_base_box"
VAGRANT_BOX_NAME = "wazuh_local_ova_base_box"
VERSION_FILENAME = "VERSION.json"
STANDARIZE_OVA_FILENAME = "setOVADefault.sh"
OVA_OVF_TEMPLATE = "wazuh_ovf_template"
VAGRANT_METADATA_PATH = ROOT_DIR / ".vagrant" / "machines" / "default" / "virtualbox"
VERSION_FILEPATH = ROOT_DIR / VERSION_FILENAME
OVA_SCRIPTS_PATH = ROOT_DIR / "utils" / "scripts" / "ova_build"
STANDARIZE_OVA_FILEPATH = OVA_SCRIPTS_PATH / STANDARIZE_OVA_FILENAME
OVA_OVF_TEMPLATE_FILEPATH = OVA_SCRIPTS_PATH / OVA_OVF_TEMPLATE

logger = Logger("Build Local OVA")


def fetch_artifact_urls_file(
    environment: Literal[EnvironmentType.PRE_RELEASE, EnvironmentType.RELEASE],
) -> Path:
    """
    Fetch the artifact URLs file based on the selected environment.

    - Release / Pre-release: downloads ``artifact_urls.yml`` transparently from the
      corresponding URL defined in ``ArtifactFilePath`` for the selected environment.
      The version and stage (revision) are read automatically from ``VERSION.json``.

    Args:
        environment (EnvironmentType): The target environment. Only Release and
            Pre-release are relevant for this function, as the Dev environment
            uses a local file.

    Returns:
        Path: Local path to the artifact URLs file.
    """

    wazuh_version = get_wazuh_version(VERSION_FILEPATH)
    wazuh_stage = get_wazuh_stage(VERSION_FILEPATH)
    url = ArtifactFilePath[environment.name].build(version=wazuh_version, revision=wazuh_stage)
    local_path = CURRENT_PATH / ARTIFACT_URLS_FILENAME

    logger.debug(f"Downloading artifact URLs file from {url}")
    urllib.request.urlretrieve(url, local_path)

    if not local_path.exists():
        raise FileNotFoundError(f"Failed to download the artifact URLs file from {url}")

    return local_path


def get_box_url_from_artifact_urls(artifact_urls_path: Path) -> str:
    """
    Parse the artifact URLs YAML file and return the vagrant box URL.

    The YAML file must contain the key defined by ``VAGRANT_BOX_YAML_KEY``
    whose value is the URL/S3-path to the ``.box`` file.

    Args:
        artifact_urls_path (Path): Path to the artifact URLs YAML file.

    Returns:
        str: The vagrant box URL.
    """
    with open(artifact_urls_path) as f:
        urls = yaml.safe_load(f)

    box_url = urls.get(VAGRANT_BOX_YAML_KEY)
    if not box_url:
        raise ValueError(
            f"Key '{VAGRANT_BOX_YAML_KEY}' not found in {artifact_urls_path}. Please add it to the artifact URLs file."
        )
    return box_url


def setup_execution_environment(vm_name: str, box_name: str = VAGRANT_BOX_NAME) -> None:
    """
    Set up the execution environment for the OVA image creation. This includes rendering the Vagrantfile with the specified VM name and box source.
    The Vagrantfile is used to configure the virtual machine for the OVA image creation process.

    Args:
        vm_name (str): The name of the virtual machine that will be created throught the Vagrantfile.
        box_name (str): The name to register the Vagrant box under. Defaults to ``al2023``.

    Returns:
        None
    """
    logger.debug_title("Setting up execution environment")

    vagrant_context = {
        "vm_name": vm_name,
        "box_name": box_name,
    }
    script_dir = CURRENT_PATH / "templates"
    output_vagrantfile = CURRENT_PATH / "Vagrantfile"

    logger.debug("Creating Vagrantfile")

    render_vagrantfile(
        context=vagrant_context,
        template_dir=str(script_dir),
        template_file="Vagrantfile.j2",
        output_path=str(output_vagrantfile),
    )

    logger.info_success("Vagrantfile created successfully")


def configure_vagrant_vm(packages_url_filename: Path, box_url: str) -> str:
    """
    Configures a Vagrant virtual machine (VM) for the Wazuh environment.
    Para ello crea una Vagrant VM y dentro de ella, se ejecuta Hatch con la configuración
    usada para crear la OVA productiva.

    This function is responsible for setting up the Wazuh environment in a Vagrant VM.
    It creates a Vagrant VM and executes Hatch with the configuration used to create the production OVA.

    Returns:
        str: The UUID of the configured Vagrant VM.
    """

    logger.debug_title("Creating the Wazuh environment into the VM")
    
    try:
        logger.debug(f"Copying {packages_url_filename} to the {CURRENT_PATH} directory")
        shutil.copy(packages_url_filename, CURRENT_PATH / ARTIFACT_URLS_FILENAME)
    except shutil.SameFileError:
        logger.debug(f"File {CURRENT_PATH / ARTIFACT_URLS_FILENAME} already exists. No need to copy it.")

    logger.debug("Downloading and adding the Vagrant box")

    urllib.request.urlretrieve(box_url, CURRENT_PATH / f"{VAGRANT_BOX_NAME}.box")

    exec_command(f"vagrant box add --name {VAGRANT_BOX_NAME} {CURRENT_PATH / f'{VAGRANT_BOX_NAME}.box'}")
    run_vagrant_up(vagrantfile=CURRENT_PATH / "Vagrantfile")

    vagrant_uuid_file = VAGRANT_METADATA_PATH / "index_uuid"
    with open(vagrant_uuid_file) as file:
        vagrant_uuid = file.read()

    logger.info("""
        Starting the Configuration process. This may take a while. When the process is finished,
        the logs generated during the configuration will be displayed in the console. 
    """)

    command = f"vagrant ssh {vagrant_uuid} -c 'cd /tmp/ && sudo hatch run dev-ova-post-configurer:run --packages-url-path {CURRENT_PATH / ARTIFACT_URLS_FILENAME}'"
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
