import os
import subprocess
import argparse

def deactivate_selinux():
    with open("/etc/selinux/config", "r") as file:
        lines = file.readlines()
    
    with open("/etc/selinux/config", "w") as file:
        for line in lines:
            if line.strip().startswith("SELINUX="):
                file.write("SELINUX=disabled\n")
            else:
                file.write(line)
    
    subprocess.run("sudo setenforce 0", shell=True, check=True)
    subprocess.run("sudo grubby --update-kernel ALL --args selinux=0", shell=True, check=True)
    
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
        {"url": "https://github.com/wazuh/wazuh-virtual-machines.git", "dest": "/home/vagrant/wazuh-virtual-machines"},
        {"url": "https://github.com/wazuh/wazuh-installation-assistant.git", "dest": "/home/vagrant/wazuh-installation-assistant"}
    ]

    for repo in repos:
        subprocess.run(f"git clone {repo['url']} {repo['dest']}", shell=True, check=True)

        
def build_wazuh_install(repo_path, wia_branch):
    """
    Builds the wazuh-install.sh script and moves it to /tmp

    Args:
        repo_path (str): Local path of the repository
        wia_branch (str): Branch of the wazuh-installation-assistant repository (version of Wazuh to install)
        repository (str): Production or development repository
    """
    
    if os.path.exists(repo_path):
        os.chdir(repo_path)
        subprocess.run(f"git checkout {wia_branch}", shell=True, check=True)
        subprocess.run("sudo bash builder.sh -i", shell=True, check=True)
        if os.path.exists("wazuh-install.sh"):
            subprocess.run("sudo mv wazuh-install.sh /tmp/wazuh-install.sh", shell=True, check=True)
        

def run_provision_script(wvm_branch, repository, debug):
    """
    Runs the provision.sh script
    
    Args:
        repository (str): Production or development repository
        debug (str): Debug mode
    """
    os.chdir("/home/vagrant/wazuh-virtual-machines/ova")
    subprocess.run(f"git checkout {wvm_branch}", shell=True, check=True)
    subprocess.run(f"sudo bash provision.sh {repository} {debug}", shell=True, check=True)

def deactivate_network_manager():
    """
    Deactivates the NetworkManager service
    """
    subprocess.run("sudo systemctl stop NetworkManager", shell=True, check=True)
    subprocess.run("sudo systemctl disable NetworkManager", shell=True, check=True)
    subprocess.run("sudo systemctl enable systemd-networkd", shell=True, check=True)
    subprocess.run("sudo systemctl start systemd-networkd", shell=True, check=True)
    subprocess.run("sudo systemctl start systemd-resolved", shell=True, check=True)

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
    
    if not os.path.exists("/etc/systemd/network"):
        os.makedirs("/etc/systemd/network")
    
    with open(config_path, "w") as config_file:
        config_file.write(config_content)
        subprocess.run("sudo systemctl restart systemd-networkd", shell=True, check=True)
        

def change_ssh_config():
    """
    Changes the /etc/crypto-policies/back-ends/opensshserver.config file to make the ssh compatible with FIPS
    """
    config_path = "/etc/crypto-policies/back-ends/opensshserver.config"
    new_values = {
        "Ciphers": "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "MACs": "MACs hmac-sha2-256,hmac-sha2-512",
        "GSSAPIKexAlgorithms": "GSSAPIKexAlgorithms gss-nistp256-sha256-,gss-group14-sha256-,gss-group16-sha512-",
        "KexAlgorithms": "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521"
    }

    with open(config_path, "r") as file:
        lines = file.readlines()

    with open(config_path, "w") as file:
        for line in lines:
            key = line.split()[0] if line.strip() else ""
            if key in new_values:
                file.write(new_values[key] + "\n")
            else:
                file.write(line)

    subprocess.run("sudo systemctl restart sshd", shell=True, check=True)


def clean():
    """
    Cleans the VM after the installation
    """
    
    os.remove("/tmp/wazuh-install.sh")
    
    subprocess.run("sudo rm -rf /home/vagrant/wazuh-virtual-machines /home/vagrant/wazuh-installation-assistant", shell=True, check=True)
    
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
    parser.add_argument("--wvm_branch", required=True, help="Branch of the wazuh-virtual-machines repository")
    parser.add_argument("--repository", required=True, help="Production or development repository")
    parser.add_argument("--debug", required=True, help="Debug mode")
    args = parser.parse_args()
    
    deactivate_selinux()
    set_hostname()
    install_git()
    clone_repositories()
    build_wazuh_install("/home/vagrant/wazuh-installation-assistant", args.wia_branch)
    run_provision_script(args.wvm_branch, args.repository, args.debug)
    deactivate_network_manager()
    create_network_config()
    change_ssh_config()
    clean()
        
if __name__ == "__main__":
    main()
    
