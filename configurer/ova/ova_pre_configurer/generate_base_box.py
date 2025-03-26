import os
import shutil
import tempfile
from pathlib import Path
from typing import List

from configurer.utils import run_command
from utils import Logger

logger = Logger("OVA PreConfigurer - Generate Base Box")

OS_URL = "https://cdn.amazonlinux.com/al2023/os-images/latest/"
OS = "al2023"


def get_os_version() -> str:
    """
    Retrieves the operating system version from a specified URL.

    Returns:
        str: The extracted OS version.

    Raises:
        RuntimeError: If the OS version cannot be determined from the response.
    """
    result, _, _ = run_command(f"curl -I {OS_URL}", output=True)
    if result:
        for line in result[0].split("\n"):
            if "location" in line:
                return line.strip().split("/")[-2]
    raise RuntimeError("Error getting OS version")


def check_dependencies() -> None:
    """
    This function verifies the presence of the following commands: "vboxmanage", "wget", "tar", and "chroot".
    If any of these commands are not found, it logs an error message and raises an exception.

    Raises:
        Exception: If any of the required commands are not found in the system's PATH.
    """
    required_cmds = ["vboxmanage", "wget", "tar", "chroot"]
    missing_cmds = []

    for cmd in required_cmds:
        if not shutil.which(cmd):
            logger.error(f"Command {cmd} not found in PATH")
            missing_cmds.append(cmd)

    if missing_cmds:
        raise Exception(f"Commands {', '.join(missing_cmds)} not found in PATH")


def download_and_extract_ova(version: str, vmdk_filename: str, ova_filename: str) -> None:
    """
    Downloads and extracts a specified OVA file if the VMDK file does not already exist.

    Args:
        version (str): The version of the Amazon Linux OVA to download.
        vmdk_filename (str): The name of the VMDK file to check for existence and extract from the OVA.
        ova_filename (str): The name of the OVA file to download and extract.

    Returns:
        None
    """
    if not os.path.exists(vmdk_filename):
        commands = [
            f"wget https://cdn.amazonlinux.com/al2023/os-images/{version}/vmware/{ova_filename}",
            f"tar -xvf {ova_filename} {vmdk_filename}",
        ]
        run_command(commands)


def convert_vmdk_to_raw(vmdk_filename: str, raw_file: str) -> None:
    """
    Converts a VMDK file to a RAW file format using VBoxManage commands.

    Args:
        vmdk_filename (str): The path to the source VMDK file.
        raw_file (str): The path where the converted RAW file will be saved.

    Returns:
        None
    """
    commands = [
        f"vboxmanage clonemedium {vmdk_filename} {raw_file} --format RAW",
        f"vboxmanage closemedium {vmdk_filename}",
        f"vboxmanage closemedium {raw_file}",
    ]
    run_command(commands)


def mount_and_setup_image(raw_file: str, mount_dir: str) -> None:
    """
    Mounts a raw disk image to a specified directory, sets up the environment for the setup script,
    runs a configuration script in a chroot environment, and then unmounts everything.

    Args:
        raw_file (str): The path to the raw disk image file.
        mount_dir (str): The directory where the raw disk image will be mounted.

    Returns:
        None
    """
    run_command(f"mount -o loop,offset=12582912 {raw_file} {mount_dir}")
    create_isolate_setup_configuration(mount_dir)
    commands = [
        f"mount -o bind /dev {Path(mount_dir) / 'dev'}",
        f"mount -o bind /proc {Path(mount_dir) / 'proc'}",
        f"mount -o bind /sys {Path(mount_dir) / 'sys'}",
        f"chroot {mount_dir} python3 -m configurer.ova.ova_pre_configurer.setup",
        f"umount {Path(mount_dir) / 'sys'}",
        f"umount {Path(mount_dir) / 'proc'}",
        f"umount {Path(mount_dir) / 'dev'}",
        f"umount {mount_dir}",
    ]
    run_command(commands)


def create_isolate_setup_configuration(dir_name: str = "isolate_setup") -> None:
    """
    Creates a directory structure for an isolated setup configuration and copies necessary files.

    Args:
        dir_name (str): The name of the base directory to create the isolated setup configuration. Defaults to "isolate_setup".

    Returns:
        None
    """
    commands = [
        f"mkdir -p {dir_name}/configurer/ova/ova_pre_configurer",
        f"mkdir -p {dir_name}/configurer/utils",
        f"cp configurer/ova/ova_pre_configurer/setup.py {dir_name}/configurer/ova/ova_pre_configurer/",
        f"cp configurer/utils/helpers.py {dir_name}/configurer/utils/",
    ]
    run_command(commands, check=True)


def convert_raw_to_vdi(raw_file, vdi_file) -> None:
    """
    Converts a raw disk image file to a VirtualBox VDI file format.

    Args:
        raw_file (str): The path to the raw disk image file.
        vdi_file (str): The path where the converted VDI file will be saved.

    Returns:
        None
    """
    run_command(f"vboxmanage convertfromraw {raw_file} {vdi_file} --format VDI")


def create_virtualbox_vm(vdi_file) -> None:
    """
    Creates a VirtualBox virtual machine and configures it with the specified VDI file.

    Args:
        vdi_file (str): The path to the VDI file to be attached to the virtual machine.

    Returns:
        None
    """
    commands = [
        f"vboxmanage createvm --name {OS} --ostype Linux26_64 --register",
        f"vboxmanage modifyvm {OS} --memory 1024 --vram 16 --audio-enabled off",
        f"vboxmanage storagectl {OS} --name IDE --add ide",
        f"vboxmanage storagectl {OS} --name SATA --add sata --portcount 1",
        f"vboxmanage storageattach {OS} --storagectl IDE --port 1 --device 0 --type dvddrive --medium emptydrive",
        f"vboxmanage storageattach {OS} --storagectl SATA --port 0 --device 0 --type hdd --medium {vdi_file}",
    ]
    run_command(commands)


def package_vagrant_box() -> None:
    """
    This function accomplishes two operations:
    - Packages the Vagrant box using the `vagrant package` command.
    - Exports the Vagrant box as an OVA file using the `vboxmanage export` command.

    Returns:
        None
    """
    commands = [
        f"vagrant package --base {OS} --output {OS}.box",
        f"vboxmanage export {OS} -o {OS}.ova",
    ]
    run_command(commands)


def cleanup(temp_dirs: List[str]) -> None:
    """
    Remove temporary directories and unregister the virtual machine in VirtualBox.

    Args:
        temp_dirs (List[str]): A list of paths to temporary directories to be removed.

    Returns:
        None
    """
    base_dir = "/home/ec2-user/wazuh-virtual-machines"
    for temp_dir in temp_dirs:
        if os.path.abspath(temp_dir) != os.path.abspath(base_dir) and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    run_command(f"vboxmanage unregistervm {OS} --delete")


def main() -> None:
    """
    Main function to generate a base Vagrant box of Amazon Linux 2023.

    This function performs the following steps:
    1. Checks for necessary dependencies.
    2. Retrieves the operating system version.
    3. Constructs filenames for the OVA and VMDK files based on the OS and version.
    4. Creates temporary directories and files for processing.
    5. Downloads and extracts the OVA file from Amazon Linux 2023.
    6. Converts the VMDK file to a raw image.
    7. Mounts and sets up the raw image.
    8. Converts the raw image to a VDI file.
    9. Creates a VirtualBox virtual machine using the VDI file.
    10. Packages the virtual machine into a Vagrant box.
    11. Cleans up temporary directories and files.

    Raises:
        Any exceptions that occur during the process will be handled in the cleanup step.
    """
    logger.info("--- Generating Base Box ---")

    check_dependencies()
    version = get_os_version()
    ova_filename = f"{OS}-vmware_esx-{version}-kernel-6.1-x86_64.xfs.gpt.ova"
    vmdk_filename = f"{OS}-vmware_esx-{version}-kernel-6.1-x86_64.xfs.gpt-disk1.vmdk"

    current_dir = os.getcwd()
    raw_file = os.path.join(current_dir, f"{OS}.raw")
    vdi_file = os.path.join(current_dir, f"{OS}.vdi")
    mount_dir = os.path.join(current_dir, "mount_dir")
    os.makedirs(mount_dir, exist_ok=True)

    temp_dirs = [os.path.dirname(raw_file), os.path.dirname(vdi_file), mount_dir]

    try:
        download_and_extract_ova(version, vmdk_filename, ova_filename)
        convert_vmdk_to_raw(vmdk_filename, raw_file)
        mount_and_setup_image(raw_file, mount_dir)
        convert_raw_to_vdi(raw_file, vdi_file)
        create_virtualbox_vm(vdi_file)
        package_vagrant_box()
    finally:
        cleanup(temp_dirs)

    logger.info_success("Base box generation completed.")


if __name__ == "__main__":
    main()
