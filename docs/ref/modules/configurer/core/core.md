# Core Configurer

The `core` module is responsible for configuring all Wazuh components and their certificates. It ensures the virtual machine is fully functional with all services properly started.

## Main functionalities

- Installation of Wazuh components (Wazuh Manager, Wazuh Indexer, Wazuh Dashboard, and Wazuh Agent).
- Certificate generation for each component.
- Configuration of each component's configuration files, including the Wazuh Agent connection settings.
- Starting all necessary services.

> This module assumes that the `provisioner` has already been executed on the machine. That means all required packages and the `certs-tool` must be available beforehand.

## Wazuh Agent enrollment

The core configurer does **not** enroll the pre-installed agent. It installs it, points its `<manager><endpoint>` at `127.0.0.1` and starts the service, but the agent ships with no key, no trust anchor and no enrollment credential. The enrollment happens on the first boot of the deployed VM instead.

Wazuh 5.0 ([wazuh/wazuh#39063](https://github.com/wazuh/wazuh/issues/39063)) replaced the shared Authd registration password with a per-agent `WAZUH_ENROLLMENT_TOKEN`, which the manager mints locally with `wazuh-manager-authd --create-enrollment-token`. Two reasons make the image the wrong place to do that:

- A mint is refused when the agent listener certificate (`remoted.pem`) names loopback only, and at build time it does. The instance's real addresses only reach that certificate's SAN on the first boot of the deployed instance, when the certificates are regenerated (see [#957](https://github.com/wazuh/wazuh-virtual-machines/issues/957)).
- Anything minted here would be baked into the published image, so every instance launched from it would share one enrollment credential and one agent identity. That is exactly the problem the old registration-password rotation existed to avoid, and a token is no better baked than a password was.

The manager ships with `<auth><use_password>yes</use_password>`, so an agent that carries no credential cannot register by accident in the meantime.

> The token is minted, stored and consumed on the first boot of the deployed VM. See the [OVA](../post/ova/post-ova.md) and [AMI](../post/ami/post-ami.md) post-configurer documentation for details.

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
