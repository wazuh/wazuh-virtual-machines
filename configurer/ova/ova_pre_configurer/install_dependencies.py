import os
import re

import requests

from configurer.utils import run_command
from utils import Logger

logger = Logger("OVA PreConfigurer - Dependencies Installer")

VIRTUALBOX_DOWNLOAD_BASE_URL = "https://download.virtualbox.org/virtualbox/"
REQUIRED_PACKAGES = [
    f"kernel-devel-{os.uname().release}",
    f"kernel-headers-{os.uname().release}",
    "dkms",
    "elfutils-libelf-devel",
    "gcc",
    "make",
    "perl",
    "python3-pip",
    "git",
]
VAGRANT_REPO_URL = "https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo"


def update_packages() -> None:
    """
    Updates all system packages using the 'yum' package manager.

    Returns:
        None
    """
    logger.debug("Updating all system packages.")
    run_command("sudo yum update -y")


def download_virtualbox_installer() -> None:
    """
    Downloads the latest VirtualBox installer for Linux (amd64) and makes it executable.
    This function performs the following steps:
    1. Retrieves the latest stable version of VirtualBox from the official VirtualBox website.
    2. Constructs the download page URL for the latest version.
    3. Downloads the installer to the /tmp directory.
    4. Makes the downloaded installer executable.

    Raises:
        RuntimeError: If there is an error retrieving the latest VirtualBox version.
        Exception: If the installer URL cannot be found on the download page.
        requests.exceptions.RequestException: If there is an error during any of the HTTP requests.
        RuntimeError: If there is an error getting the VirtualBox download page.

    Returns:
        None
    """

    version_url = VIRTUALBOX_DOWNLOAD_BASE_URL + "LATEST-STABLE.TXT"

    try:
        response = requests.get(version_url)
        response.raise_for_status()
        latest_version = response.text.strip()
        logger.debug(f"Latest VirtualBox version: {latest_version}")
    except Exception as e:
        logger.error(f"Error getting latest VirtualBox version: {e}")
        raise RuntimeError("Error getting latest VirtualBox version.") from e

    download_page_url = VIRTUALBOX_DOWNLOAD_BASE_URL + f"{latest_version}/"

    try:
        response = requests.get(download_page_url)
        response.raise_for_status()

    except Exception as e:
        logger.error(f"Error getting VirtualBox download page: {e}")
        raise Exception("Error getting VirtualBox download page.") from e

    try:
        match = re.search(rf"VirtualBox-{latest_version}-\d+-Linux_amd64.run", response.text)
        if match:
            installer_url = download_page_url + match.group(0)
            dest = f"/tmp/VirtualBox-{latest_version}.run"

            response = requests.get(installer_url, stream=True)
            response.raise_for_status()

            with open(dest, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.debug(f"VirtualBox installer version {latest_version} downloaded to {dest}")

            logger.debug("Making installer executable.")
            os.chmod(dest, 0o755)

        else:
            logger.error("Could not find VirtualBox installer URL.")
            raise

    except Exception as e:
        raise Exception("Could not find VirtualBox installer URL.") from e


def install_required_packages() -> None:
    """
    Installs the required packages and development tools on a system using yum.

    Returns:
        None
    """
    logger.debug(f"Installing required packages: {', '.join(REQUIRED_PACKAGES)}")
    run_command("sudo yum install -y " + " ".join(REQUIRED_PACKAGES))

    logger.debug("Installing Development tools.")
    run_command("sudo yum groupinstall 'Development Tools' -y")


def add_exclude_amazonlinux_repo(repo_path: str = "/etc/yum.repos.d/amazonlinux.repo") -> None:
    """
    This function reads the specified repository configuration file, searches for the
    "[amazonlinux]" section, and adds an "exclude kernel-devel* kernel-headers*" to avoid
    unwanted updates of these packages.

    Args:
        repo_path (str): The path to the Amazon Linux repository configuration file.
                         Defaults to "/etc/yum.repos.d/amazonlinux.repo".

    Returns:
        None
    """
    with open(repo_path) as file:
        lines = file.readlines()

    exclude_line = "exclude=kernel-devel* kernel-headers*\n"

    for i, line in enumerate(lines):
        if line.strip() == "[amazonlinux]":
            lines.insert(i + 1, exclude_line)
            break

    with open(repo_path, "w") as file:
        file.writelines(lines)


def run_virtualbox_installer() -> None:
    """
    Executes the VirtualBox installer script.

    Returns:
        None
    """
    logger.debug("Running VirtualBox installer.")
    run_command("sudo bash /tmp/VirtualBox-*.run")


def rebuild_virtualbox_kernel_modules() -> None:
    """
    Rebuilds the VirtualBox kernel modules by running the vboxconfig command.

    Returns:
        None
    """
    logger.debug("Rebuilding VirtualBox kernel modules.")
    run_command("sudo /sbin/vboxconfig")


def install_vagrant() -> None:
    """
    Installs Vagrant and its dependencies using the specified repository URL.

    Returns:
        None
    """
    logger.debug("Installing Vagrant.")
    commands = [
        "sudo yum install -y yum-utils shadow-utils",
        f"sudo yum-config-manager --add-repo {VAGRANT_REPO_URL}",
        "sudo yum -y install vagrant",
        "vagrant plugin install vagrant-scp",
    ]
    run_command(commands)


def main() -> None:
    """
    Main function to install dependencies for the OVA PreConfigurer.
    This function performs the following steps:
    1. Updates the package list.
    2. Installs the required packages.
    3. Downloads the VirtualBox installer.
    4. Runs the VirtualBox installer.
    5. Updates the package list again.
    6. Rebuilds the VirtualBox kernel modules.
    7. Installs Vagrant.

    Returns:
        None
    """
    logger.info("Installing dependencies of the OVA PreConfigurer.")

    update_packages()
    install_required_packages()
    add_exclude_amazonlinux_repo()
    download_virtualbox_installer()
    run_virtualbox_installer()
    update_packages()
    rebuild_virtualbox_kernel_modules()
    install_vagrant()

    logger.info_success("Dependencies installed successfully.")
