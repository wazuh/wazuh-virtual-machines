import os
import shutil
import tempfile

from configurer.utils import run_command
from utils import Logger

logger = Logger("OVA PreConfigurer - Generate Base Box")

OS_URL = "https://cdn.amazonlinux.com/al2023/os-images/latest/"
OS = "al2023"

def get_os_version() -> str:
    result, _, _ = run_command(f"curl -I {OS_URL}", output=True)
    for line in result[0].split("\n"):
        if "location" in line:
            return line.strip().split("/")[-2]
    return "latest"

def check_dependencies() -> None:
    required_cmds = ["vboxmanage", "wget", "tar", "chroot"]
    for cmd in required_cmds:
        if not shutil.which(cmd):
            logger.error(f"Command {cmd} not found in PATH")
            raise Exception(f"Command {cmd} not found in PATH")
        
def download_and_extract_ova(version: str, vmdk_filename: str, ova_filename: str) -> None:
    if not os.path.exists(vmdk_filename):
        commands = [
            f"wget https://cdn.amazonlinux.com/al2023/os-images/{version}/vmware/{ova_filename}",
            f"tar -xvf {ova_filename} {vmdk_filename}"
        ]
        run_command(commands)

def convert_vmdk_to_raw(vmdk_filename: str, raw_file: str) -> None:
    commands = [
        f"vboxmanage clonemedium {vmdk_filename} {raw_file} --format RAW",
        f"vboxmanage closemedium {vmdk_filename}",
        f"vboxmanage closemedium {raw_file}"
    ]
    run_command(commands)
    
def mount_and_setup_image(raw_file, mount_dir):
    run_command(f"mount -o loop,offset=12582912 {raw_file} {mount_dir}")
    create_isolate_setup_configuration(mount_dir)
    commands = [
        f"mount -o bind /dev {os.path.join(mount_dir, 'dev')}",
        f"mount -o bind /proc {os.path.join(mount_dir, 'proc')}",
        f"mount -o bind /sys {os.path.join(mount_dir, 'sys')}",
        f"chroot {mount_dir} python3 -m configurer.ova.ova_pre_configurer.setup",
        f"umount {os.path.join(mount_dir, 'sys')}",
        f"umount {os.path.join(mount_dir, 'proc')}",
        f"umount {os.path.join(mount_dir, 'dev')}",
        f"umount {mount_dir}"
    ]
    run_command(commands)
    
def create_isolate_setup_configuration(dir_name: str = "isolate_setup"):
    commands = [
        f"mkdir -p {dir_name}/configurer/ova/ova_pre_configurer",
        f"mkdir -p {dir_name}/configurer/utils",
        f"mkdir -p {dir_name}/utils",
        f"cp configurer/ova/ova_pre_configurer/setup.py {dir_name}/configurer/ova/ova_pre_configurer/",
        f"cp utils/logger.py {dir_name}/utils/",
        f"cp configurer/utils/helpers.py {dir_name}/configurer/utils/"
    ]
    run_command(commands, check=True)

def convert_raw_to_vdi(raw_file, vdi_file):
    run_command(f"vboxmanage convertfromraw {raw_file} {vdi_file} --format VDI")
    
def create_virtualbox_vm(vdi_file):
    commands = [
        f"vboxmanage createvm --name {OS} --ostype Linux26_64 --register",
        f"vboxmanage modifyvm {OS} --memory 1024 --vram 16 --audio-enabled off",
        f"vboxmanage storagectl {OS} --name IDE --add ide",
        f"vboxmanage storagectl {OS} --name SATA --add sata --portcount 1",
        f"vboxmanage storageattach {OS} --storagectl IDE --port 1 --device 0 --type dvddrive --medium emptydrive",
        f"vboxmanage storageattach {OS} --storagectl SATA --port 0 --device 0 --type hdd --medium {vdi_file}"
    ]
    run_command(commands)
    
def package_vagrant_box():
    commands = [
        f"vagrant package --base {OS} --output {OS}.box",
        f"vboxmanage export {OS} -o {OS}.ova"
    ]
    run_command(commands)
    
def cleanup(temp_dirs):
    for temp_dir in temp_dirs:
        shutil.rmtree(temp_dir)
    run_command(f"vboxmanage unregistervm {OS} --delete")
    
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
