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

## Wazuh Agent enrollment on first boot

Wazuh 5.0 ([wazuh/wazuh#39063](https://github.com/wazuh/wazuh/issues/39063)) replaced the shared Authd registration password with a per-agent `WAZUH_ENROLLMENT_TOKEN`. The pre-installed agent is no longer handed a copy of the manager's `authd.pass`; it is handed a token that the manager mints for it, on this VM, at first boot.

The `wazuh-starter` service, which runs once on the first boot to start the components in order, does it in this order:

1. **Clears the enrollment state baked into the image.** The manager's `authd.pass` and its enrollment token store (`/var/wazuh-manager/etc/enrollment_tokens.json`) are removed, and so is everything on the agent side that would make the token bootstrap decline to run: its trust anchor (`/var/ossec/etc/certs/root-ca.pem`), its re-enrollment secret and the contents of its `client.keys`. The bootstrap refuses to run whenever the agent already holds an anchor or a non-empty `client.keys` — it deletes the token unused in both cases — so a baked anchor or a baked key would silently turn the fresh token into a no-op and leave every VM imported from the OVA enrolled under one identity.
2. **Regenerates the certificates**, which is what puts this VM's own addresses into `remoted.pem`'s SAN. A mint is refused against a certificate whose SAN names loopback and nothing else, so this has to come first.
3. **Mints the token** once the manager is up: `wazuh-manager-authd --create-enrollment-token --address 127.0.0.1 --embed-ca --max-uses 1`. Minting goes through the manager's local `authd` socket, so the manager has to be running; the call is retried while the socket is still coming up.
4. **Stores it** at `/var/ossec/etc/enrollment_token`, created and locked down to `0600 root:root` *before* the token is written into it, the same way the agent installer writes it. The token never appears on a command line.
5. **Starts the agent**, which reads the file on its first start while still root, installs the CA the token carries as its trust anchor, enrolls, and unlinks the file.

Some details worth knowing:

- **`--address 127.0.0.1`.** Manager and agent are on the same VM, so loopback is the one address that is always reachable and never changes, and it is already what the agent's `<manager><endpoint>` holds. It is a SAN entry of `remoted.pem` through the manager node of the cert-tool config.
- **`--embed-ca`** carries the CA inside the token instead of a pin of it, so the agent gets its trust anchor without first fetching `/cacerts` over a connection it cannot verify yet.
- **The token's 30-day TTL** (the CLI default, [wazuh/wazuh#39068](https://github.com/wazuh/wazuh/issues/39068)) is irrelevant here and is left alone on purpose: a token is minted on every first boot and consumed within seconds, so it never gets anywhere near expiring. Do **not** "fix" this later by minting a long-lived token at build time and shipping it in the image — that hands every VM imported from the OVA the same credential, which is the whole reason this runs at first boot.
- **No `<ssl><certificate_authorities>` is configured** for the agent. The bootstrap installs the anchor itself, and the agent then resolves `verification_mode` to `full` from the presence of that file. Naming the path in `ossec.conf` instead would point the agent at a file that does not exist yet: the agent validates the configured CA before the bootstrap runs, and fails closed on a CA it cannot read.

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
