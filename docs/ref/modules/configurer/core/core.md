# Core Configurer

The `core` module is responsible for installing and configuring all Wazuh components. It ensures the virtual machine is fully functional with all services properly started.

## Main functionalities

- Installation of Wazuh components (Wazuh Manager, Wazuh Indexer, Wazuh Dashboard, and Wazuh Agent).
- Configuration of each component's configuration files, including the Wazuh Agent connection settings.
- Starting all necessary services.

> This module assumes that the `provisioner` has already been executed on the machine. That means all required packages must be available beforehand.

## Wazuh Agent enrollment

The core configurer does **not** enroll the pre-installed agent. It installs it, points its `<manager><endpoint>` at `127.0.0.1` and starts the service, but the agent ships with no key, no trust anchor and no enrollment credential. The enrollment happens on the first boot of the deployed VM instead.

Wazuh 5.0 ([wazuh/wazuh#39063](https://github.com/wazuh/wazuh/issues/39063)) replaced the shared Authd registration password with a per-agent `WAZUH_ENROLLMENT_TOKEN`, which the manager mints locally with `wazuh-manager-authd --create-enrollment-token`. Two reasons make the image the wrong place to do that:

- A mint is refused when the agent listener certificate (`remoted.pem`) names loopback only, and at build time it does. The instance's real addresses only reach that certificate's SAN on the first boot of the deployed instance, when each package issues its certificates again (see [#957](https://github.com/wazuh/wazuh-virtual-machines/issues/957)).
- Anything minted here would be baked into the published image, so every instance launched from it would share one enrollment credential and one agent identity. That is exactly the problem the old registration-password rotation existed to avoid, and a token is no better baked than a password was.

The manager ships with `<auth><use_password>yes</use_password>`, so an agent that carries no credential cannot register by accident in the meantime.

> The token is minted, stored and consumed on the first boot of the deployed VM. See the [OVA](../post/ova/post-ova.md) and [AMI](../post/ami/post-ami.md) post-configurer documentation for details.

## Credentials and certificates at build time

Since 5.0.0 RC 2 ([wazuh/internal-devel-requests#7048](https://github.com/wazuh/internal-devel-requests/issues/7048)) each package resolves its own credentials and certificates. Its postinst (`resolve-credentials --install`) mints its own CA in `/etc/<package>/ca/`, issues its pairs, generates the passwords it owns, publishes them in `/etc/<package>/export/` and imports what it needs from its peers' `export/`. The core configurer relies on that and sets neither a password nor a certificate:

- It runs no certificate tool. A pair issued from another CA would be refused at the next start.
- It does not write the indexer credential into the manager keystore: the manager package already stored `WAZUH_INDEXER_MANAGER_PASSWORD` there, and the old `wazuh-manager`/`wazuh-manager` pair would overwrite it.
- `configuration_mappings.yaml` leaves the manager's `indexer.ssl.*` as packaged (`certs/indexer-ca.pem` and `certs/indexer-connector*.pem`, imported from the indexer) and does not set `nodes_dn`/`admin_dn`: the indexer's `--install` writes them from the pairs it issues.

Everything resolved at build time (passwords, CA, certificates) is removed again by the AMI and OVA post-configurers (`purge-build-credentials.sh`), and each deployed instance resolves its own on first boot. See the [AMI](../post/ami/post-ami.md) and [OVA](../post/ova/post-ova.md) post-configurer documentation.

## Component configuration

Component configuration is handled using the `yq` tool. This command-line utility allows reading and updating YAML files, which is the format used for all component configuration files.

Configuration mappings are defined in the file:

```bash
configurer/core/static/configuration_mappings.yaml
```

Each Wazuh component has a section in this file with the following structure:

- **path**: Filepath to the configuration file to be modified.
- **replace**:
  - **keys**: A list of `yq`-formatted keys to search for in the configuration file.
  - **values**: New values to assign to those keys.

For example, to update the `network.host` setting in the `wazuh_indexer` component:

```yaml
wazuh_indexer:
  - path: /etc/wazuh-indexer/opensearch.yml 
    replace:
      keys:
        - .["network.host"]
      values:
        - "127.0.0.1"
```

## Parameters

- `--inventory`: Required when executing on a remote machine. It must point to an Ansible-compatible inventory file. Not required for local execution.

    ```yaml
    all:
        hosts:
            <ec2-instance-id>:
            ansible_connection: ssh
            ansible_host: <instance-ip-or-dns>
            ansible_port: <instance-port>
            ansible_ssh_common_args: -o StrictHostKeyChecking=no
            ansible_ssh_private_key_file: <instance-private-key-path>
            ansible_user: <instance-user>
    ```

## Examples

### Run core locally

- Using Hatch:

    ```bash
    hatch run dev-core-configurer:run
    ```

- Using the command line:

    ```bash
    python -m main --execute core-configurer
    ```

### Run core remotely

- Using Hatch:

    ```bash
    hatch run dev-core-configurer:run --inventory <path-to-inventory>
    ```

- Using the command line:

    ```bash
    python -m main --execute core-configurer --inventory <path-to-inventory>
    ```
