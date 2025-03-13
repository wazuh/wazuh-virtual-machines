from configurer.utils import run_command
from utils import Logger

from .generate_base_box import main as generate_base_box_main
from .install_dependencies import main as install_dependencies_main

logger = Logger("OVA PreConfigurer - Main module")

def add_vagrant_box() -> None:
    logger.info("Adding Vagrant box.")
    run_command("vagrant box add --name al2023 /tmp/wazuh-virtual-machines/al2023.box")
    
def destroy_previous_vms():
    logger.info("Destroying previous VMs.")
    result = run_command("vagrant global-status --prune | awk '/running|saved|poweroff/ {print $1}'", output=True)
    machines = result[0].strip().split("\n")
    machines = [m for m in machines if m]
    
    if not machines:
        logger.info("No previous VMs found.")
        return

    for machine_id in machines:
        run_command(f"vagrant destroy {machine_id} -f")
        
def run_vagrant_up(max_retries=100) -> True | False:
    attempts = 0
    while attempts < max_retries:
        attempts += 1
        logger.debug(f"Attempt {attempts} to run 'vagrant up'.")
        stdout, stderr, returncode = run_command("vagrant up", output=True)
        if returncode[0] == 0:
            logger.info_success("Vagrant VM started.")
            return True
        
        logger.warning(f"Vagrant VM failed to start on attemtp {attempts}. Retrying...")
        
        if attempts == max_retries:
            logger.error("Max attemps reached. Failed execution.")
            raise RuntimeError("Vagrant VM failed to start after maximum retries.")
        
        logger.debug("Destroying Vagrant machine before retrying")
        run_command("vagrant destroy -f")
        
    return False

def deploy_vm():
    logger.info("Deploying VM.")
    run_command("cp configuer/ova/ova_pre_configurer/Vagrantfile .", check=True)
    add_vagrant_box()
    run_vagrant_up()
    

def main():
    logger.info("Starting OVA PreConfigurer.")
    logger.info("Installing dependencies.")
    install_dependencies_main()
    
    logger.info("Generating base box.")
    generate_base_box_main()
    
    deploy_vm()
    logger.info_success("OVA PreConfigurer completed.")
    
if __name__ == "__main__":
    main()
