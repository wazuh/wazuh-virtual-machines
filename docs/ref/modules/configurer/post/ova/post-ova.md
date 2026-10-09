# OVA Post Configurer

The **OVA Post Configurer** module is responsible for running the **Provisioner and Core Configurer** modules and then running the **OVA Post Configurer** itself.
The main objective of this module is to configure the final machine so that the user can import it into his virtualizer and have Wazuh running quickly.

> ⚠️ This module is intended to be part of the **Build OVA workflow** developed in the `wazuh-virtual-machines` repository so its separate use is possible but it might require adaptation to work properly.

Once the **Provisioner and Core Configurer** have been executed, the Wazuh components are installed in the VM deployed with the **OVA Pre Configurer**. Subsequently, the **OVA Post Configurer** performs the following configurations on the VM:

1. **GRUB bootloader** is configured to display an image with the **Wazuh logo** when loading the VM.  
2. **FIPS** (Federal Information Processing Standards) is enabled on the VM.  
3. **JVM** heap size is updated to a quarter of the total RAM. The `updateIndexerHeap.service` runs on the first boot of the deployed VM, so the heap is sized against the RAM of the final host.
4. Added `wazuh-starter` service which is responsible for raising each Wazuh component correctly.  
5. The `root` password is not set (it is locked at the end, see step 18).  
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
12. Stop `wazuh-indexer` and `wazuh-dashboard` services and disable every Wazuh service (`wazuh-starter` starts them in order on first boot).  
13. The credentials, certificates and CA resolved at build time are removed (see below).  
14. Cleanup tasks are executed.  
15. A network configuration file is created which ensures that a network interface is raised with **DHCP** on **IPv4** accessible.  
16. **SSH** is configured to use modern and secure cryptographic algorithms, in accordance with **FIPS** activation.  
17. Further cleanup of logs, command history, package cache and restart of the `sshd` service.  
18. The image is generalized (`generalize_image`), as the last step: the SSH `authorized_keys` of every user (with the Vagrant insecure public key) and the SSH host keys are removed, `/etc/machine-id` is emptied, `ec2-user` (created by cloud-init), its sudoers file and the unused `ifcfg-eth0` are removed, the `root` password is locked and the `wazuh-user` password is expired (`chage -d 0`), so it must be changed on the first login. The result is verified and the build fails if anything is left. After this step the build cannot log in to the VM any more, so the OVA builder powers it off through ACPI instead of `vagrant halt`.  

## Credentials: generated per VM on first boot

The Wazuh 5.0 packages generate their own passwords ([wazuh/wazuh-indexer#1928](https://github.com/wazuh/wazuh-indexer/issues/1928)): there are no fixed default passwords such as `admin:admin` or `wazuh:wazuh` any more. Each package runs `resolve-credentials` when it is installed (`--install`) and again when its service starts (`--prestart`), and publishes the passwords it owns to `/etc/wazuh/credentials.env` (`root:root 0600`).

**Build.** The packages are installed, so the build resolves credentials of its own. Once every service is stopped, `purge-build-credentials.sh` (`configurer/core/static/`) runs each package's `resolve-credentials --clear` and removes `/etc/wazuh`. Until the packages' `--clear` covers them, it also applies three workarounds, to be removed in the next release:

1. It restores the indexer's password placeholders in `internal_users.yml`. The indexer's `--clear` keeps the build-time digests, and the first boot would then publish passwords the indexer does not accept.
2. It removes the Server API TLS pair (`apid.pem`/`apid-key.pem`) and JWT signing keypair (`api/configuration/security/private_key.pem`/`public_key.pem`) created during the build. First boot issues a new TLS pair from the instance CA, and the API creates a new keypair.
3. It removes the build CA the indexer postinst imported into the indexer JDK truststore (`cacerts`, alias `wazuh-root-ca`). First boot imports the instance's own CA there instead.

The script fails the build if anything resolved at build time is left: `/etc/wazuh`, the indexer marker, `rbac.db`, the manager keystore, a digest instead of a placeholder, a component certificate, the API pair or keypair, or the truststore alias.

**First boot**, strictly in this order and never in parallel:

1. `wazuh-certs-tool.sh` creates this VM's CA and certificates. The CA goes to `/etc/wazuh/ca/` and each pair to its component. The manager gets the indexer-connector pair, the agent listener pair (`remoted.pem`) and the Server API pair (`apid.pem`), all replacing whatever a failed earlier attempt left there; the same detected addresses go to the SAN of both `remoted.pem` and `apid.pem`. `wazuh-manager-certs stamp` then publishes the manager's new `root-ca.pem` to the agents, so remoted does not warn that the bundle changed outside the tool. The CA is also imported into the indexer JDK truststore as `wazuh-root-ca` (workaround 3). `nodes_dn` and `authcz.admin_dn` are written from the certificates just installed, since their subject order depends on the certs-tool version. Certificates must be in place before the first start: the packages never issue them outside `--install`.
2. The indexer starts: its `--prestart` generates `admin`, `kibanaserver` and `wazuh-manager` and publishes them.
3. `indexer-security-init.sh` loads the security configuration (a manual step of the indexer package).
4. The manager starts: it generates the Server API passwords (`wazuh`, `wazuh-internal-client`) and reads `WAZUH_INDEXER_MANAGER_PASSWORD`.
5. The dashboard starts: it reads `kibanaserver` and `wazuh-internal-client`.

Every readiness check reads its password from `credentials.env` and hands it to curl through its standard input, never on a command line. No passwords tool is involved on first boot: the packages generate a unique password per VM.

**Where the user finds the password.** `credentials.env` is left in place: the dashboard user is `admin`, with the password in `WAZUH_INDEXER_ADMIN_PASSWORD` (`sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-`). The login banner says so, and recommends deleting the file once the passwords are saved.

## Wazuh Agent enrollment on first boot

Wazuh 5.0 ([wazuh/wazuh#39063](https://github.com/wazuh/wazuh/issues/39063)) replaced the shared Authd registration password with a per-agent `WAZUH_ENROLLMENT_TOKEN`. The pre-installed agent is no longer handed a copy of the manager's `authd.pass`; it is handed a token that the manager mints for it, on this VM, at first boot.

The `wazuh-starter` service, which runs once on the first boot to start the components in order, does it in this order:

1. **Clears the enrollment state baked into the image.** The manager's `authd.pass` and its enrollment token store (`/var/wazuh-manager/etc/enrollment_tokens.json`) are removed, and so is everything on the agent side that would make the token bootstrap decline to run: its trust anchor (`/var/ossec/etc/certs/root-ca.pem`), the `.anchor-committed` marker next to it and its re-enrollment secret. Its `client.keys` is emptied later, in step 3. The bootstrap refuses to run whenever the agent already holds an anchor or a non-empty `client.keys` — it deletes the token unused in both cases — so a baked anchor or a baked key would silently turn the fresh token into a no-op and leave every VM imported from the OVA enrolled under one identity.
2. **Regenerates the certificates**, which is what puts this VM's own addresses into `remoted.pem`'s SAN. A mint is refused against a certificate whose SAN names loopback and nothing else, so this has to come first.
3. **Empties the agent's `client.keys`, first removing the agent it names, if any**, once the manager API is up. Doing it in this one step, and not in step 1, means a run that fails before the API is up keeps the ID on disk for the next one. The script only deletes itself once it succeeds, so it runs again on the next boot after a failure; if that failure came after the agent enrolled, the manager still has it registered under the same name and would reject the new enrollment as a duplicate. The agent is removed through the Server API (`DELETE /agents?agents_list=<id>&status=all&older_than=0s&purge=true`), since the 5.0.0 manager has no local CLI to remove agents. A failure here is logged as a warning and does not stop the boot. On a normal first boot `client.keys` is already empty and nothing is removed.
4. **Mints the token** once the manager is up: `wazuh-manager-authd --create-enrollment-token --address 127.0.0.1 --embed-ca --max-uses 1`. Minting goes through the manager's local `authd` socket, so the manager has to be running; the call is retried while the socket is still coming up.
5. **Stores it** at `/var/ossec/etc/enrollment_token`, created and locked down to `0600 root:root` *before* the token is written into it, the same way the agent installer writes it. The token never appears on a command line.
6. **Starts the agent**, which reads the file on its first start while still root, installs the CA the token carries as its trust anchor, enrolls, and unlinks the file.

Some details worth knowing:

- **`--address 127.0.0.1`.** Manager and agent are on the same VM, so loopback is the one address that is always reachable and never changes, and it is already what the agent's `<manager><endpoint>` holds. It is a SAN entry of `remoted.pem` through the manager node of the cert-tool config.
- **`--embed-ca`** carries the CA inside the token instead of a pin of it, so the agent gets its trust anchor without first fetching `/cacerts` over a connection it cannot verify yet.
- **The token's 30-day TTL** (the CLI default, [wazuh/wazuh#39068](https://github.com/wazuh/wazuh/issues/39068)) is irrelevant here and is left alone on purpose: a token is minted on every first boot and consumed within seconds, so it never gets anywhere near expiring. Do **not** "fix" this later by minting a long-lived token at build time and shipping it in the image — that hands every VM imported from the OVA the same credential, which is the whole reason this runs at first boot.
- **No `<ssl><certificate_authorities>` is configured** for the agent. The bootstrap installs the anchor itself, and the agent then resolves `verification_mode` to `full` from the presence of that file. Naming the path in `ossec.conf` instead would point the agent at a file that does not exist yet: the agent validates the configured CA before the bootstrap runs, and fails closed on a CA it cannot read.

## Certificate lifecycle after first boot

First boot generates a fresh root CA and issues every component's certificate from it, including the manager's agent-listener certificate (`remoted.pem`), whose SAN is built from the addresses detected at that moment (`hostname -I`). If the instance's address changes afterward — a new DHCP lease, a different network, a reassigned static IP — `remoted.pem`'s SAN goes stale and agents connecting from the new address fail hostname verification.

[wazuh-virtual-machines#957](https://github.com/wazuh/wazuh-virtual-machines/issues/957), which introduced this first-boot regeneration, asked to decide and document this case: "reissuing the leaf is enough and does not break enrolled agents, since they pin the CA rather than the leaf." Its only requirement about the CA's private key is that it never ships baked into the image (a single `root-ca.key` shared by every VM imported from it would make hostname/chain verification worthless) — nothing in the issue asks a booted instance to destroy its own copy once generated.

So this instance's root CA (`root-ca.pem` and `root-ca.key`) is kept, not deleted, in `/etc/wazuh/ca/`, where the packages' shared credentials library expects it (directory `700`, `root-ca.pem` `644`, `root-ca.key` `400`, owner `root:root`). `wazuh-installation-assistant`, which this whole first-boot design otherwise mirrors, does the same with its own equivalent — it `chmod 400`s the generated `root-ca.pem`/`.key` and bundles them into `wazuh-install-files.tar` for the operator to keep (`install_functions/installCommon.sh`) — rather than ever destroying them. An earlier revision of `clean_configuration()` in `wazuh-starter.sh` deleted `root-ca.key` outright instead of securing it; that satisfied the letter of "not baked into the image" but broke the issue's own reissuing guarantee, and was only caught by tracing the issue's exact wording rather than by anything that runs.

**To reissue `remoted.pem`'s SAN (and `apid.pem`'s, which is built from the same addresses) after the instance's address changes** (or to add a load balancer's own certificate later, `wazuh-certs-tool.sh -lb`), run `wazuh-certs-tool.sh` again with this CA instead of a new one — versions built on the shared credentials library reuse `/etc/wazuh/ca` by default; older ones take `/etc/wazuh/ca/root-ca.pem` and `root-ca.key` as the existing CA — this keeps every already-enrolled agent's trust intact, since they pinned the CA and it has not changed. There is no automation for this today; it is a manual operator step.

## Considerations

The **OVA Post Configurer** is designed to be executed in a **local machine only**. As mentioned above the execution of this module using **Hatch** will execute the **Provisioner** and **Core Configurer** modules previously.

## Parameters

As this module makes use of the **Provisioner** module, it needs the parameter required by this module which is the `--packages-url-path <path>`. This parameter expects the path to the `.yml` file containing the download URLs of each package. For more information see the **Provisioner** documentation [here](../../../provisioner/provisioner.md).

## Execution

This module can be executed using Hatch running the following command:

```bash
hatch run dev-ova-post-configurer:run --packages-url-path <path-to-file>
```
