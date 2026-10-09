# AMI Post Configurer

The **AMI Post-configurer** is responsible for preparing the AMI to be exported as an artifact once the Wazuh components are configured and the pre-configuration steps are completed. This post-configuration process includes:

- Pausing all services.
- Deleting any Wazuh indices created in the indexer during the configuration process.
- Removing the credentials, certificates and CA resolved at build time, so no two instances share them.
- Clearing all log files that may have been generated during the configuration.
- Removing the base directory created in the provisioner step that contains the certs tool and component packages.

These steps ensure that when a user launches an instance from the base AMI image, they will find a clean Wazuh environment.

## Creation of Custom Certificate Service

In the **core-configurer**, certificates are created for each Wazuh component. When creating the AMI, every instance launched from this image will have the same certificates, which could pose a security issue.

To address this, a custom systemd service is created that, when the instance starts for the first time, generates new certificates for each Wazuh component and restarts the services. This ensures that each instance has unique certificates.

For this service, a Python virtual environment is set up with the necessary dependencies to run the corresponding Python scripts. This virtual environment is created during the post-configurer process, so that when the service runs and generates the new certificates, the service files and the virtual environment used for execution are deleted. This ensures that any unnecessary files and dependencies are removed from the system.

## Credentials: generated per instance on first boot

The Wazuh 5.0 packages generate their own passwords ([wazuh/wazuh-indexer#1928](https://github.com/wazuh/wazuh-indexer/issues/1928)): there are no fixed default passwords such as `admin:admin` or `wazuh:wazuh` any more. Each package runs `resolve-credentials` when it is installed (`--install`) and again when its service starts (`--prestart`), and publishes the passwords it owns to `/etc/wazuh/credentials.env` (`root:root 0600`).

**Build.** The packages are installed, so the build resolves credentials of its own. Once every service is stopped, `purge-build-credentials.sh` (`configurer/core/static/`) runs each package's `resolve-credentials --clear` and removes `/etc/wazuh`. Until the packages' `--clear` covers them, it also applies three workarounds, to be removed in the next release:

1. It restores the indexer's password placeholders in `internal_users.yml`. The indexer's `--clear` keeps the build-time digests, and the first boot would then publish passwords the indexer does not accept.
2. It removes the Server API TLS pair (`apid.pem`/`apid-key.pem`) and JWT signing keypair (`api/configuration/security/private_key.pem`/`public_key.pem`) created during the build. First boot issues a new TLS pair from the instance CA, and the API creates a new keypair.
3. It removes the build CA the indexer postinst imported into the indexer JDK truststore (`cacerts`, alias `wazuh-root-ca`). First boot imports the instance's own CA there instead.

The script fails the build if anything resolved at build time is left: `/etc/wazuh`, the indexer marker, `rbac.db`, the manager keystore, a digest instead of a placeholder, a component certificate, the API pair or keypair, or the truststore alias.

**First boot**, strictly in this order and never in parallel:

1. `wazuh-certs-tool.sh` creates this instance's CA and certificates. The CA goes to `/etc/wazuh/ca/` and each pair to its component. The manager gets the indexer-connector pair, the agent listener pair (`remoted.pem`) and the Server API pair (`apid.pem`), all replacing whatever a failed earlier attempt left there; the same detected addresses go to the SAN of both `remoted.pem` and `apid.pem`. `wazuh-manager-certs stamp` then publishes the manager's new `root-ca.pem` to the agents, so remoted does not warn that the bundle changed outside the tool. The CA is also imported into the indexer JDK truststore as `wazuh-root-ca` (workaround 3). `nodes_dn` and `authcz.admin_dn` are written from the certificates just installed, since their subject order depends on the certs-tool version. Certificates must be in place before the first start: the packages never issue them outside `--install`.
2. The indexer starts: its `--prestart` generates `admin`, `kibanaserver` and `wazuh-manager` and publishes them.
3. `indexer-security-init.sh` loads the security configuration (a manual step of the indexer package).
4. The manager starts: it generates the Server API passwords (`wazuh`, `wazuh-internal-client`) and reads `WAZUH_INDEXER_MANAGER_PASSWORD`.
5. The dashboard starts: it reads `kibanaserver` and `wazuh-internal-client`.

Every readiness check reads its password from `credentials.env` and hands it to curl through its standard input, never on a command line. No passwords tool is involved on first boot: the packages generate a unique password per instance.

**Where the user finds the password.** `credentials.env` is left in place: the dashboard user is `admin`, with the password in `WAZUH_INDEXER_ADMIN_PASSWORD` (`sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-`). The login banner says so, and recommends deleting the file once the passwords are saved.

## Wazuh Agent enrollment on first boot

Wazuh 5.0 ([wazuh/wazuh#39063](https://github.com/wazuh/wazuh/issues/39063)) replaced the shared Authd registration password with a per-agent `WAZUH_ENROLLMENT_TOKEN`. The pre-installed agent is no longer handed a copy of the manager's `authd.pass`; it is handed a token that the manager mints for it, on this instance, at first boot.

The same first-boot custom service that regenerates the certificates (`wazuh-ami-customizer.py`) does it in this order:

1. **Clears the enrollment state baked into the image.** The manager's `authd.pass` and its enrollment token store (`/var/wazuh-manager/etc/enrollment_tokens.json`) are removed, and so is everything on the agent side that would make the token bootstrap decline to run: its trust anchor (`/var/ossec/etc/certs/root-ca.pem`) and the `.anchor-committed` marker next to it, its re-enrollment secret and the contents of its `client.keys`. The bootstrap refuses to run whenever the agent already holds an anchor or a non-empty `client.keys` — it deletes the token unused in both cases — so a baked anchor or a baked key would silently turn the fresh token into a no-op and leave every instance launched from the base AMI enrolled under one identity.
2. **Regenerates the certificates**, which is what puts this instance's own addresses into `remoted.pem`'s SAN. A mint is refused against a certificate whose SAN names loopback and nothing else, so this has to come first.
3. **Removes the agent left by an earlier, failed run**, if `client.keys` held an ID before the reset. The customizer only removes its service once it succeeds, so it runs again on the next boot after a failure; if that failure came after the agent enrolled, the manager still has it registered under the same name and would reject the new enrollment as a duplicate. The agent is removed through the Server API (`DELETE /agents?agents_list=<id>&status=all&older_than=0s&purge=true`), since the 5.0.0 manager has no local CLI to remove agents. A failure here is logged as a warning and does not stop the boot. On a normal first boot `client.keys` is empty and this step does nothing.
4. **Mints the token** once the manager is up: `wazuh-manager-authd --create-enrollment-token --address 127.0.0.1 --embed-ca --max-uses 1`. Minting goes through the manager's local `authd` socket, so the manager has to be running; the call is retried while the socket is still coming up.
5. **Stores it** at `/var/ossec/etc/enrollment_token`, created and locked down to `0600 root:root` *before* the token is written into it, the same way the agent installer writes it. The token never appears on a command line.
6. **Starts the agent**, which reads the file on its first start while still root, installs the CA the token carries as its trust anchor, enrolls, and unlinks the file.

Some details worth knowing:

- **`--address 127.0.0.1`.** Manager and agent are on the same instance, so loopback is the one address that is always reachable and never changes, and it is already what the agent's `<manager><endpoint>` holds. It is a SAN entry of `remoted.pem` through the manager node of the cert-tool config.
- **`--embed-ca`** carries the CA inside the token instead of a pin of it, so the agent gets its trust anchor without first fetching `/cacerts` over a connection it cannot verify yet.
- **The token's 30-day TTL** (the CLI default, [wazuh/wazuh#39068](https://github.com/wazuh/wazuh/issues/39068)) is irrelevant here and is left alone on purpose: a token is minted on every first boot and consumed within seconds, so it never gets anywhere near expiring. Do **not** "fix" this later by minting a long-lived token at build time and shipping it in the image — that hands every instance launched from the base AMI the same credential, which is the whole reason this runs at first boot.
- **No `<ssl><certificate_authorities>` is configured** for the agent. The bootstrap installs the anchor itself, and the agent then resolves `verification_mode` to `full` from the presence of that file. Naming the path in `ossec.conf` instead would point the agent at a file that does not exist yet: the agent validates the configured CA before the bootstrap runs, and fails closed on a CA it cannot read.

## Certificate lifecycle after first boot

First boot generates a fresh root CA and issues every component's certificate from it, including the manager's agent-listener certificate (`remoted.pem`), whose SAN is built from the addresses detected at that moment (`hostname -I` plus the instance's public IPv4/IPv6 from `ec2-metadata`). If the instance's address changes afterward — a new private IP, a reassigned Elastic IP, a different public address — `remoted.pem`'s SAN goes stale and agents connecting from the new address fail hostname verification.

[wazuh-virtual-machines#957](https://github.com/wazuh/wazuh-virtual-machines/issues/957), which introduced this first-boot regeneration, asked to decide and document this case: "reissuing the leaf is enough and does not break enrolled agents, since they pin the CA rather than the leaf." Its only requirement about the CA's private key is that it never ships baked into the image (a single `root-ca.key` shared by every instance launched from it would make hostname/chain verification worthless) — nothing in the issue asks a launched instance to destroy its own copy once generated.

So this instance's root CA (`root-ca.pem` and `root-ca.key`) is kept, not deleted, in `/etc/wazuh/ca/`, where the packages' shared credentials library expects it (directory `700`, `root-ca.pem` `644`, `root-ca.key` `400`, owner `root:root`). `wazuh-installation-assistant`, which this whole first-boot design otherwise mirrors, does the same with its own equivalent — it `chmod 400`s the generated `root-ca.pem`/`.key` and bundles them into `wazuh-install-files.tar` for the operator to keep (`install_functions/installCommon.sh`) — rather than ever destroying them. An earlier revision of `clean_up()` in `wazuh-ami-customizer.py` deleted `root-ca.key` outright instead of securing it; that satisfied the letter of "not baked into the image" but broke the issue's own reissuing guarantee, and was only caught by tracing the issue's exact wording rather than by anything that runs.

**To reissue `remoted.pem`'s SAN (and `apid.pem`'s, which is built from the same addresses) after the instance's address changes** (or to add a load balancer's own certificate later, `wazuh-certs-tool.sh -lb`), run `wazuh-certs-tool.sh` again with this CA instead of a new one — versions built on the shared credentials library reuse `/etc/wazuh/ca` by default; older ones take `/etc/wazuh/ca/root-ca.pem` and `root-ca.key` as the existing CA — this keeps every already-enrolled agent's trust intact, since they pinned the CA and it has not changed. There is no automation for this today; it is a manual operator step.

## Considerations

Just like the pre-configurer, this module is designed to be executed on a remote machine, meaning the `--inventory` option must be provided.

The remote machine must be an AWS instance, as this will be the one exported after the configuration process is complete.

## Execution

This module is intended to be executed along with the pre-configurer and not individually. Therefore, there is no Hatch command available for this specific module.

If you need to execute it individually, you can do so via the command line:

```bash
python -m main --execute ami-post-configurer --inventory <path-to-inventory>
```

### Global Execution

A global option has been created for the CLI: `--execute all-ami`. This command allows you to run the entire process of creating and configuring the AMI, which includes:

1. AMI Pre-configurer
2. Provisioner
3. Core-configurer
4. AMI Post-configurer

To run this option, the following required parameters must be specified:

- `--inventory`: Points to an Ansible-compatible inventory file.
- `--packages-url-path`: A file containing the URLs for the components to be installed.

You can execute it in two ways:

- Using Hatch:

    ```bash
    hatch run dev-ami-configurer:run --inventory <path-to-inventory> --packages-url-path <path-to-file>
    ```

- Using the command line:

    ```bash
    python -m main --execute all-ami --inventory <path-to-inventory> --packages-url-path <path-to-file>
    ```
