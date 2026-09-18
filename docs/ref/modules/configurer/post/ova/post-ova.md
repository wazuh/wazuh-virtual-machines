# OVA Post Configurer

The **OVA Post Configurer** module is responsible for running the **Provisioner and Core Configurer** modules and then running the **OVA Post Configurer** itself.
The main objective of this module is to configure the final machine so that the user can import it into his virtualizer and have Wazuh running quickly.

> ⚠️ This module is intended to be part of the **Build OVA workflow** developed in the `wazuh-virtual-machines` repository so its separate use is possible but it might require adaptation to work properly.

Once the **Provisioner and Core Configurer** have been executed, the Wazuh components are installed in the VM deployed with the **OVA Pre Configurer**. Subsequently, the **OVA Post Configurer** performs the following configurations on the VM:

1. **GRUB bootloader** is configured to display an image with the **Wazuh logo** when loading the VM.  
2. **FIPS** (Federal Information Processing Standards) is enabled on the VM.  
3. **JVM** heap size is updated to a quarter of the total RAM. The `updateIndexerHeap.service` runs on the first boot of the deployed VM, so the heap is sized against the RAM of the final host.
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

## Certificate lifecycle after first boot

First boot generates a fresh root CA and issues every component's certificate from it, including the manager's agent-listener certificate (`remoted.pem`), whose SAN is built from the addresses detected at that moment (`hostname -I`). If the instance's address changes afterward — a new DHCP lease, a different network, a reassigned static IP — `remoted.pem`'s SAN goes stale and agents connecting from the new address fail hostname verification.

[wazuh-virtual-machines#957](https://github.com/wazuh/wazuh-virtual-machines/issues/957), which introduced this first-boot regeneration, asked to decide and document this case: "reissuing the leaf is enough and does not break enrolled agents, since they pin the CA rather than the leaf." Its only requirement about the CA's private key is that it never ships baked into the image (a single `root-ca.key` shared by every VM imported from it would make hostname/chain verification worthless) — nothing in the issue asks a booted instance to destroy its own copy once generated.

So this instance's root CA (`root-ca.pem` and `root-ca.key`) is kept, not deleted, in a fixed, restrictive location: `/etc/wazuh-certificate-authority/` (`700`, files `400`, owner `root:root`). `wazuh-installation-assistant`, which this whole first-boot design otherwise mirrors, does the same with its own equivalent — it `chmod 400`s the generated `root-ca.pem`/`.key` and bundles them into `wazuh-install-files.tar` for the operator to keep (`install_functions/installCommon.sh`) — rather than ever destroying them. An earlier revision of `clean_configuration()` in `wazuh-starter.sh` deleted `root-ca.key` outright instead of securing it; that satisfied the letter of "not baked into the image" but broke the issue's own reissuing guarantee, and was only caught by tracing the issue's exact wording rather than by anything that runs.

**To reissue `remoted.pem`'s SAN after the instance's address changes** (or to add a load balancer's own certificate later, `wazuh-certs-tool.sh -lb`), run `wazuh-certs-tool.sh` again passing `/etc/wazuh-certificate-authority/root-ca.pem` and `.../root-ca.key` as the existing CA, instead of leaving it to generate a new one — this keeps every already-enrolled agent's trust intact, since they pinned the CA and it has not changed. There is no automation for this today; it is a manual operator step.

## Considerations

The **OVA Post Configurer** is designed to be executed in a **local machine only**. As mentioned above the execution of this module using **Hatch** will execute the **Provisioner** and **Core Configurer** modules previously.

## Parameters

As this module makes use of the **Provisioner** module, it needs the parameter required by this module which is the `--packages-url-path <path>`. This parameter expects the path to the `.yml` file containing the download URLs of each package. For more information see the **Provisioner** documentation [here](../../../provisioner/provisioner.md).

## Execution

This module can be executed using Hatch running the following command:

```bash
hatch run dev-ova-post-configurer:run --packages-url-path <path-to-file>
```
