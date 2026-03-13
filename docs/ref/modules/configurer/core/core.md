# Core Configurer

The `core` module is responsible for configuring all Wazuh components and their certificates. It ensures the virtual machine is fully functional with all services properly started.

## Main functionalities

- Installation of Wazuh components (Wazuh Manager, Wazuh Indexer, Wazuh Dashboard, and Wazuh Agent).
- Certificate generation for each component.
- Configuration of each component's configuration files, including the Wazuh Agent connection settings.
- Starting all necessary services.

> This module assumes that the `provisioner` has already been executed on the machine. That means all required packages and the `certs-tool` must be available beforehand.

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
