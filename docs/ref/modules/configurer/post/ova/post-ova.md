# OVA Post Configurer

The **OVA Post Configurer** module is responsible for running the **Provisioner and Core Configurer** modules and then running the **OVA Post Configurer** itself.
The main objective of this module is to configure the final machine so that the user can import it into his virtualizer and have Wazuh running quickly.

> ⚠️ This module is intended to be part of the **Build OVA workflow** developed in the `wazuh-virtual-machines` repository so its separate use is possible but it might require adaptation to work properly.

Once the **Provisioner and Core Configurer** have been executed, the Wazuh components are installed in the VM deployed with the **OVA Pre Configurer**. Subsequently, the **OVA Post Configurer** performs the following configurations on the VM:

1. **GRUB bootloader** is configured to display an image with the **Wazuh logo** when loading the VM.  
2. **FIPS** (Federal Information Processing Standards) is enabled on the VM.  
3. **JVM** heap size is updated to half of the total RAM.  
4. Added `wazuh-starter` service which is responsible for raising each Wazuh component correctly.  
5. Changed the `root` password to `wazuh`.  
6. Changed the VM hostname to `wazuh`.  
7. Disable the SSH connection to the `root` user.  
8. Enable SSH connection via password.  
9. Execute the `messages.sh` script which adds welcome messages both at machine startup and login.  
10. Afterwards the `wazuh-manager` is stopped and the following indexes are deleted:  
    - `wazuh-alerts-*`  
    - `wazuh-archives-*`  
    - `wazuh-states-vulnerabilities-*`  
    - `wazuh-statistics-*`  
    - `wazuh-monitoring-*`  
11. The `security-init.sh` is executed.  
12. Stop `wazuh-indexer` and `wazuh-dashboard` services and disable `wazuh-manager` and `wazuh-dashboard`.  
13. Cleanup tasks are executed.  
14. A network configuration file is created which ensures that a network interface is raised with **DHCP** on **IPv4** accessible.  
15. **SSH** is configured to use modern and secure cryptographic algorithms, in accordance with **FIPS** activation.  
16. Further cleanup of logs, command history, package cache and restart of the `sshd` service.  

## Wazuh Agent registration password rotation

The Wazuh manager generates and persists a random Authd registration password (`/var/wazuh-manager/etc/authd.pass`) the first time it starts. Because this happens during the build, every VM imported from the OVA would otherwise share the same password, which is a security issue.

To avoid this, the `wazuh-starter` service (which runs once on the first boot to start the components in order) rotates the registration password: before starting the manager it removes the pre-generated `authd.pass` files so the manager generates a new, unique password. That password is then copied to the Wazuh agent Authd password file (`/var/ossec/etc/authd.pass`), with the proper ownership (`root:wazuh`) and permissions (`640`), before the agent starts so it can enroll against the manager.

## Considerations

The **OVA Post Configurer** is designed to be executed in a **local machine only**. As mentioned above the execution of this module using **Hatch** will execute the **Provisioner** and **Core Configurer** modules previously.

## Parameters

As this module makes use of the **Provisioner** module, it needs the parameter required by this module which is the `--packages-url-path <path>`. This parameter expects the path to the `.yml` file containing the download URLs of each package. For more information see the **Provisioner** documentation [here](../../../provisioner/provisioner.md).

## Execution

This module can be executed using Hatch running the following command:

```bash
hatch run dev-ova-post-configurer:run --packages-url-path <path-to-file>
```
