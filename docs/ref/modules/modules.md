# Modules

To create and configure the AMI and OVA, two fundamental modules are used:

- **Provisioner** ([provisioner.md](provisioner/provisioner.md)): Responsible for provisioning the certs-tool and the Wazuh component packages specified.
- **Configurer** ([configurer.md](configurer/configurer.md)): Once the necessary files have been provisioned, this module handles the creation of certificates for each component, the installation of the components, and their configuration. The configuration is divided into three main parts:
  - **Core** ([core.md](configurer/core/core.md)): Manages the shared configuration between the AMI and OVA. This includes generating certificates for each component, installing the components, and configuring their configuration files.
  - **Pre Configurer** ([pre.md](configurer/pre/pre.md)): Responsible for applying the initial configuration steps required before running the core module.
  - **Post Configurer** ([post.md](configurer/post/post.md)): Runs after the core configuration has completed. It finalizes the setup by preparing the AMI or OVA to be exported and distributed as a ready-to-use virtual machine.

These modules are executed through a single CLI. The available CLI options are:

| Parameter | Required | Description | Accepted Values| Default |
|------------|----------|-------------|----------------|---------|
| `--inventory`          | Required for `ami-pre-configurer`, `ami-post-configurer`, `all-ami`  | Path to the inventory file | - | - |
| `--packages-url-path`  | Required for `provisioner`, `ova-post-configurer`, `all-ami` | Path to the packages URL file | - | - |
| `--package-type`       | No  | Type of package to install | `rpm`, `deb` | `rpm` |
| `--execute`            | Yes | Module to execute | `provisioner`, `core-configurer`, `ova-pre-configurer`, `ova-post-configurer`, `ami-pre-configurer`, `ami-post-configurer`, `all-ami` | - |
| `--arch`               | No | Architecture to use | `x86_64`, `amd64`, `arm64`, `aarch64` | `x86_64` |
| `--dependencies`       | No | Path to the dependencies file | - | `provisioner/static/wazuh_dependencies.yaml` |
| `--component`          | No | Component to provision | `wazuh_indexer`, `wazuh_server`, `wazuh_dashboard`, `all` | `all` |

> This CLI can be executed using **Hatch** or by creating a **venv**. For more information on how to configure it, you can check the setup of the toolchain [here](../../dev/setup.md).
