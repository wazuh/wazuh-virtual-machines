import os
import re

import requests

from configurer.utils import run_command
from utils import Logger

logger = Logger("OVA PreConfigurer - Dependencies Installer")

def update_packages():
    logger.info("Updating all system packages.")
    run_command("sudo yum update -y")
    
def install_pip():
    logger.info("Installing pip.")
    run_command("sudo yum install python3-pip -y")
    
def download_virtualbox_installer():
    version_url = "https://download.virtualbox.org/virtualbox/LATEST-STABLE.TXT"
    
    try:
        response = requests.get(version_url)
        response.raise_for_status()
        latest_version = response.text.strip()
        logger.info(f"Latest VirtualBox version: {latest_version}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting latest VirtualBox version: {e}")
        raise
    
    download_page_url = f"https://download.virtualbox.org/virtualbox/{latest_version}/"
    
    try:
        response = requests.get(download_page_url)
        response.raise_for_status()
                          
        match = re.search(rf'VirtualBox-{latest_version}-\d+-Linux_amd64.run', response.text)
        if match:
            installer_url = download_page_url + match.group(0)
            dest = f"/tmp/VirtualBox-{latest_version}.run"
            
            response = requests.get(installer_url, stream=True)
            response.raise_for_status()
            
            with open(dest, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info(f"VirtualBox installer version {latest_version} downloaded to {dest}")
            
            logger.info("Making installer executable.")
            os.chmod(dest, 0o755)
            
        else:
            logger.error("Could not find VirtualBox installer URL.")
            raise Exception("Could not find VirtualBox installer URL.")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting VirtualBox download page: {e}")
        raise
    
def install_required_packages():
    packages = [
        "kernel-devel",
        "kernel-headers",
        "dkms",
        "elfutils-libelf-devel",
        "gcc",
        "make",
        "perl",
        "python3-pip",
        "git"
    ]
    logger.info(f"Installing required packages: {', '.join(packages)}")
    run_command("sudo yum install -y " +  " ".join(packages))
    
    logger.info("Installing Development tools.")
    run_command("sudo yum groupinstall 'Development Tools' -y")
    
def run_virtualbox_installer():
    logger.info("Running VirtualBox installer.")
    run_command("sudo bash /tmp/VirtualBox-*.run")
        
def install_development_tools():
    logger.info("Installing development tools.")
    run_command("sudo yum groupinstall 'Development Tools' -y")
    
def rebuild_virtualbox_kernel_modules():
    logger.info("Rebuilding VirtualBox kernel modules.")
    run_command("sudo /sbin/vboxconfig")
    
def install_vagrant():
    logger.info("Installing Vagrant.")
    commands = [
        ["sudo yum install -y yum-utils shadow-utils"],
        ["sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo"],
        ["sudo yum -y install vagrant"]
    ]
    run_command(commands)
    
def install_git():
    logger.info("Installing Git.")
    run_command("sudo yum install git -y")
    
def main():
    logger.info("Installing dependencies of the OVA PreConfigurer.")
    
    update_packages()
    install_required_packages()
    download_virtualbox_installer()
    run_virtualbox_installer()
    update_packages()
    rebuild_virtualbox_kernel_modules()
    install_vagrant()
    
if __name__ == "__main__":
    main()
