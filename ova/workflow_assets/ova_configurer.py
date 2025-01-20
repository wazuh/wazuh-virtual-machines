import os
import subprocess
import argparse


def set_hostname():
    """
    Sets the hostname of the machine
    """
    subprocess.run("sudo hostnamectl set-hostname wazuh-server", shell=True, check=True)

def install_git():
    """"
    Installs git
    """
    subprocess.run("sudo yum install git -y", shell=True, check=True)
    
def clone_repositories():
    """
    Clones the wazuh-installation-assistant and wazuh-virtual-machines repositories
    """
    repos = [
        {"url": "https://github.com/wazuh/wazuh-virtual-machines.git", "dest": "/home/ec2-user/wazuh-virtual-machines"},
        {"url": "https://github.com/wazuh/wazuh-installation-assistant.git", "dest": "/home/ec2-user/wazuh-installation-assistant"}
    ]

    for repo in repos:
        subprocess.run(f"git clone {repo['url']} {repo['dest']}", shell=True, check=True)

        
def build_wazuh_install(repo_path, wia_branch):
    """
    Builds the wazuh-install.sh script and moves it to /tmp

    Args:
        repo_path (str): Local path of the repository
        wia_branch (str): Branch of the wazuh-installation-assistant repository (version of Wazuh to install)
    """
    
    if os.path.exists(repo_path):
        os.chdir(repo_path)
        subprocess.run(f"git checkout {wia_branch}", shell=True, check=True)
        subprocess.run("sudo bash builder.sh -i", shell=True, check=True)
        if os.path.exists("wazuh-install.sh"):
            subprocess.run("sudo mv wazuh-install.sh /tmp/wazuh-install.sh", shell=True, check=True)
        

def run_provision_script(repository, debug):
    """
    Runs the provision.sh script
    
    Args:
        repository (str): Production or development repository
        debug (str): Debug mode
    """
    os.chdir("/home/ec2-user/wazuh-virtual-machines/ova")
    subprocess.run(f"sudo bash provision.sh {repository} {debug}", shell=True, check=True)


def create_network_config():
    """
    Creates the network configuration file and restarts the systemd-networkd service
    """
    config_content = """[Match]
Name=eth1
[Network]
DHCP=ipv4
"""

    config_path = "/etc/systemd/network/20-eth1.network"
    
    with open(config_path, "w") as config_file:
        config_file.write(config_content)
        subprocess.run("sudo systemctl restart systemd-networkd", shell=True, check=True)
        

def clean():
    """
    Cleans the VM after the installation
    """
    
    os.remove("/tmp/wazuh-install.sh")
    
    subprocess.run("sudo rm -rf /home/ec2-user/wazuh-virtual-machines /home/ec2-user/wazuh-installation-assistant", shell=True, check=True)
    
    log_clean_commands = [
        "find /var/log/ -type f -exec bash -c 'cat /dev/null > {}' \\;",
        "find /var/ossec/logs -type f -execdir sh -c 'cat /dev/null > \"$1\"' _ {} \\;",
        "find /var/log/wazuh-indexer -type f -execdir sh -c 'cat /dev/null > \"$1\"' _ {} \;",
        "find /var/log/filebeat -type f -execdir sh -c 'cat /dev/null > \"$1\"' _ {} \;",
        "rm -rf /var/log/wazuh-install.log"
    ]
    for command in log_clean_commands:
        subprocess.run(command, shell=True, check=True)
        
    subprocess.run("cat /dev/null > ~/.bash_history && history -c", shell=True, check=True)
    
    yum_clean_commands = [
        "sudo yum clean all",
        "sudo rm -rf /var/cache/yum/*"
    ]
    for command in yum_clean_commands:
        subprocess.run(command, shell=True, check=True)
        
    sshd_config_changes = [
        (r'^#?AuthorizedKeysCommand.*', ''),
        (r'^#?AuthorizedKeysCommandUser.*', ''),
    ]
    for pattern, replacement in sshd_config_changes:
        subprocess.run(f"sudo sed -i '/{pattern}/d' /etc/ssh/sshd_config", shell=True, check=True)
    subprocess.run("sudo systemctl restart sshd", shell=True, check=True)
    

def main():
    """
    Main function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--wia_branch", required=True, help="Branch of the wazuh-installation-assistant repository")
    parser.add_argument("--repository", required=True, help="Production or development repository")
    parser.add_argument("--debug", required=True, help="Debug mode")
    args = parser.parse_args()
    
    set_hostname()
    install_git()
    clone_repositories()
    build_wazuh_install("/home/ec2-user/wazuh-installation-assistant", args.wia_branch)
    run_provision_script(args.repository, args.debug)
    create_network_config()
    clean()
        
if __name__ == "__main__":
    main()
    
