# Local OVA installation

In this section, we describe how to create a virtual machine (VM) in Open Virtual Appliance (OVA) format with the Wazuh manager, dashboard, and indexer components pre-installed. To build it locally, we will use the `wazuh_local_ova` module from the [Wazuh Virtual Machines](https://github.com/wazuh/wazuh-virtual-machines/tree/main/wazuh_local_ova) repository.

You need a system with a minimum of 8 CPU cores and 16 GB of RAM to build the virtual machine. Ensure that these dependencies are installed on the system:

- Virtual Box
- Vagrant
- Git
- Python
  - Make sure `pip` and `hatch` are installed for Python

## Create the Wazuh VM

To create the Wazuh OVA locally, we will use the `wazuh_local_ova` module. This module is written in Python and has the following options:

| Option | Short | Description | Required | Default |
| -------- | ------- | ------------- | ---------- | --------- |
| `--name` | `-n` | Name of the generated `.ova` file | No | `wazuh-local-ova` |
| `--output` | `-o` | Directory where the `.ova` file will be stored | No | Current directory |
| `--environment` | `-e` | Environment to use for fetching Wazuh packages (`release`, `pre-release`, `dev`) | No | `release` |
| `--packages-url-path` | `-p` | Path to the local artifact URLs file. Only used when `--environment` is `dev` | No | `./artifact_urls.yaml` |
| `--checksum` | `-c` | Generate a `.sha512` file for the OVA | No | `False` |

### Environments

The `--environment` option determines how the artifact URLs file is obtained:

- **`release`** (default): Downloads the artifact URLs file automatically from the official Wazuh packages server based on the version defined in `VERSION.json`.
- **`pre-release`**: Downloads the artifact URLs file automatically from the Wazuh pre-release packages server.
- **`dev`**: Uses a local artifact URLs file. The path to this file must be provided via `--packages-url-path`.

### Artifact URLs file (dev environment)

When using the `dev` environment, the file specified in `--packages-url-path` must contain the Vagrant base box URL and the download URLs of the Wazuh core component packages. Below is an example of the expected file content:

```yaml
wazuh_ova_base_box: "http://example.com/wazuh-base-box.box"
wazuh_manager_amd64_deb: "http://example.com/wazuh-manager-amd64.deb"
wazuh_manager_arm64_deb: "http://example.com/wazuh-manager-arm64.deb"
wazuh_manager_amd64_rpm: "http://example.com/wazuh-manager-amd64.rpm"
wazuh_manager_arm64_rpm: "http://example.com/wazuh-manager-arm64.rpm"
wazuh_agent_amd64_deb: "http://example.com/wazuh-agent-amd64.deb"
wazuh_agent_arm64_deb: "http://example.com/wazuh-agent-arm64.deb"
wazuh_agent_amd64_rpm: "http://example.com/wazuh-agent-amd64.rpm"
wazuh_agent_arm64_rpm: "http://example.com/wazuh-agent-arm64.rpm"
wazuh_indexer_amd64_deb: "http://example.com/wazuh-indexer-amd64.deb"
wazuh_indexer_arm64_deb: "http://example.com/wazuh-indexer-arm64.deb"
wazuh_indexer_amd64_rpm: "http://example.com/wazuh-indexer-amd64.rpm"
wazuh_indexer_arm64_rpm: "http://example.com/wazuh-indexer-arm64.rpm"
wazuh_dashboard_amd64_deb: "http://example.com/wazuh-dashboard-amd64.deb"
wazuh_dashboard_arm64_deb: "http://example.com/wazuh-dashboard-arm64.deb"
wazuh_dashboard_amd64_rpm: "http://example.com/wazuh-dashboard-amd64.rpm"
wazuh_dashboard_arm64_rpm: "http://example.com/wazuh-dashboard-arm64.rpm"
...
```

The `wazuh_ova_base_box` key is required. Its value must be a URL pointing to the Vagrant `.box` file. The build process downloads this file and registers it as a Vagrant box (using `vagrant box add --name`) before starting the VM. The Vagrantfile itself only references the box by name.

Follow the steps below to create the Wazuh virtual machine:

1. Clone the Wazuh Virtual Machines repository and select the Wazuh version you want to install in the OVA, in this case `5.0.0`:

   ```bash
   git clone https://github.com/wazuh/wazuh-virtual-machines && cd wazuh-virtual-machines/ && git checkout v5.0.0
   ```

2. Execute the following command to build the OVA image. The command to use depends on the environment:

   - **Release** (default): fetches the artifact URLs automatically from the official packages server.

     ```bash
     hatch run local-ova:create
     ```

   - **Pre-release**: fetches the artifact URLs automatically from the pre-release packages server.

     ```bash
     hatch run local-ova:create -e pre-release
     ```

   - **Dev**: uses a local artifact URLs file. Provide the path with `--packages-url-path`.

     ```bash
     hatch run local-ova:create -e dev -p \<path to the urls file\>
     ```

   All three commands will set up the execution environment, configure the Vagrant VM, and export the OVA image.

   You can also customize the name and output directory of the OVA file using the `--name` and `--output` options. For example:

    ```bash
    hatch run local-ova:create -e dev -p \<path to the urls file\> -n custom-wazuh-ova -o /path/to/output/directory
    ```

    To see all available options, you can use the `-h` or `--help` flag:

    ```bash
    hatch run local-ova:create --help
    ```
