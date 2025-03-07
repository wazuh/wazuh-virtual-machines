import os
import shutil
import tempfile

from configurer.utils import run_command
from utils import Logger

logger = Logger("log")

OS_URL = "https://cdn.amazonlinux.com/al2023/os-images/latest/"
OS = "al2023"

def get_os_version():
    command = [
        ["curl", "-I", OS_URL]
    ]
    result = run_command(command)
    for line in result.stdout.split("\n"):
        if "Location" in line:
            return line.strip().split("/")[-2]
    return "latest"

def check_dependencies():
    required_cmds = ["vboxmanage", "wget", "tar", "chroot"]
    for cmd in required_cmds:
        if not shutil.which(cmd):
            logger.error(f"Command {cmd} not found in PATH")
            raise Exception(f"Command {cmd} not found in PATH")
        
def download_and_extract_ova(version, vmdk_filename, ova_filename):
    if not os.path.exists(vmdk_filename):
        commands = [
            ["wget", f"https://cdn.amazonlinux.com/al2023/os-images/{version}/vmware/{ova_filename}"],
            ["tar", "-xvf", ova_filename, vmdk_filename]
        ]
        run_command(commands)

def convert_vmdk_to_raw(vmdk_filename, raw_file):
    commands = [
        ["vboxmanage", "clonemedium", vmdk_filename, raw_file, "--format", "RAW"],
        ["vboxmanage", "closemedium", vmdk_filename],
        ["vboxmanage", "closemedium", raw_file]
    ]
    run_command(commands)
    
def mount_and_setup_image(raw_file, mount_dir):
    commands = [
        ["mount", "-o", "loop,offset=12582912", raw_file, mount_dir],
        ["cp", "setup.py", os.path.join(mount_dir, ".")],
        ["mount", "-o", "bind", "/dev", os.path.join(mount_dir, "dev")],
        ["mount", "-o", "bind", "/proc", os.path.join(mount_dir, "proc")],
        ["mount", "-o", "bind", "/sys", os.path.join(mount_dir, "sys")],
        ["chroot", mount_dir, "python3", "setup.py"],
        ["umount", os.path.join(mount_dir, "sys")],
        ["umount", os.path.join(mount_dir, "proc")],
        ["umount", os.path.join(mount_dir, "dev")],
        ["umount", mount_dir]
    ]
    run_command(commands)

def convert_raw_to_vdi(raw_file, vdi_file):
    commands = [
        ["vboxmanage", "convertfromraw", raw_file, vdi_file, "--format", "VDI"],
    ]
    run_command(commands)
    
def create_virtualbox_vm(vdi_file):
    commands = [
        ["vboxmanage", "createvm", "--name", OS, "--ostype", "Linux26_64", "--register"],
        ["vboxmanage", "modifyvm", OS, "--memory", "1024", "--vram", "16", "audio", "none"],
        ["vboxmanage", "storagectl", OS, "--name", "IDE", "--add", "ide"],
        ["vboxmanage", "storagectl", OS, "--name", "SATA", "--add", "sata", "--portcount", "1"],
        ["vboxmanage", "storageattach", OS, "--storagectl", "IDE", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", "emptydrive"],
        ["vboxmanage", "storageattach", OS, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", vdi_file]
    ]
    run_command(commands)
    
def package_vagrant_box():
    commands = [
        ["vagrant", "package", "--base", OS, "--output", f"{OS}.box"],
        ["vboxmanage", "export", OS, "-o", f"{OS}.ova"]
    ]
    run_command(commands)
    
def cleanup(temp_dirs):
    for temp_dir in temp_dirs:
        shutil.rmtree(temp_dir)
    commands = [
        ["vboxmanage", "unregistervm", OS, "--delete"]
    ]
    run_command(commands)
    
def main():
    check_dependencies()
    version = get_os_version()
    ova_filename = f"{OS}-vmware_esx-{version}-kernel-6.1-x86_64.xfs.gpt.ova"
    vmdk_filename = f"{OS}-vmware_esx-{version}-kernel-6.1-x86_64.xfs.gpt-disk1.vmdk"
    raw_file = os.path.join(tempfile.mkdtemp(), f"{OS}.raw")
    vdi_file = os.path.join(tempfile.mkdtemp(), f"{OS}.vdi")
    
    mount_dir = tempfile.mkdtemp()
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
        
if __name__ == "__main__":
    main()

