# Provisioner

The `provisioner` module is responsible for preparing a target machine with the following:

- **certs-tool**: Script from the `certs-tool` project used to generate certificates for Wazuh components. Along with the script, the `config.yml` file is also copied, which contains the IP addresses and node names to generate the appropriate certificates.

- **Component packages**: In addition to the `certs-tool`, the provisioner is also responsible for downloading Wazuh component packages from the specified URLs and copying them to the target machine.

This ensures that the target machine contains both the necessary certificate generation tools and the Wazuh packages ready for installation.

## Parameters

The provisioner module accepts the following options:

- `--inventory`: Path to the inventory file.
- `--packages-url-path`: Path to the file containing the package URLs.
- `--package-type`: Type of package to provision (`rpm`, `deb`).
- `--arch`: Target architecture (`x86_64`, `amd64`, `arm64`, `aarch64`).
- `--dependencies`: Path to the dependencies file.
- `--component`: Component to provision (`wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`, `all`).

### Required Parameters

To run the provisioner module, the following are required:

- A running machine where the provisioner will operate. This can be a local machine or a remote VM.
- If the machine is not local, you will need Ansible-compatible inventory details (passed via `--inventory`). For local execution, this is not needed:

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

- A file with the URLs for the components to be installed (`--packages-url-path` parameter).

## Examples

> By default, if only the `--packages-url-path` parameter is provided, the provisioning will be done locally, with the following default values:
>
> - `--package-type`: `rpm`
> - `--arch`: `x86_64`
> - `--dependencies`: `provisioner/static/wazuh_dependencies.yaml`
> - `--component`: `all` (Wazuh Server, Wazuh Indexer, and Wazuh Dashboard)

### Provision locally with default options

- Using Hatch:

    ```bash
    hatch run dev-provisioner:run --packages-url-path <path-to-file>
    ```

- Using the command line:

    ```bash
    python -m main --execute provisioner --packages-url-path <path-to-file>
    ```

### Provision remotely for `arm64` architecture and `deb` packages

- Using Hatch:

    ``` bash
    hatch run dev-provisioner:run --inventory <path-to-inventory> --packages-url-path <path-to-file> --arch arm64 --package-type deb
    ```

- Using the command line:

    ``` bash
    python -m main --execute provisioner --inventory <path-to-inventory> --packages-url-path <path-to-file> --arch arm64 --package-type deb
    ```

### Provision only the Wazuh Dashboard remotely

- Using Hatch:

    ``` bash
    hatch run dev-provisioner:run --inventory <path-to-inventory> --packages-url-path <path-to-file> --component wazuh-dashboard
    ```

- Using the command line:

    ``` bash
    python -m main --execute provisioner --inventory <path-to-inventory> --packages-url-path <path-to-file> --component wazuh-dashboard
    ```
