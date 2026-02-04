# Local OVA installation

In this section, we describe how to create a virtual machine (VM) in Open Virtual Appliance (OVA) format with the Wazuh server, dashboard, and indexer components pre-installed. To build it locally, we will use the `wazuh_local_ova` module from the [Wazuh Virtual Machines](https://github.com/wazuh/wazuh-virtual-machines/tree/main/wazuh_local_ova) repository.

You need a system with a minimum of 4 CPU cores and 8 GB of RAM to build the virtual machine. Ensure that these dependencies are installed on the system:

- Virtual Box
- Vagrant
- Git
- Python
    - Make sure `pip` and `hatch` are installed for Python


## Create the Wazuh VM

To create the Wazuh OVA locally, we will use the `wazuh_local_ova` module. This module is written in Python and has the following options:

| Option | Short | Description | Required | Default |
|--------|-------|-------------|----------|---------|
| `--name` | `-n` | Name of the generated `.ova` file | No | `wazuh-local-ova` |
| `--output` | `-o` | Directory where the `.ova` file will be stored | No | Current directory |
| `--packages_url_path` | `-p` | Path to the file containing the package download URLs | **Yes** | - |
| `--checksum` | `-c` | Generate a `.sha512` file for the OVA | No | `False` |

The file specified in `--packages_url_path` must contain the URLs of the Wazuh core component packages. Below is an example of the file content with the different supported package nomenclatures:

```yaml
wazuh_manager_amd64_deb: "http://example.com/wazuh-manager-amd64.deb"
wazuh_manager_arm64_deb: "http://example.com/wazuh-manager-arm"
wazuh_manager_amd64_rpm: "http://example.com/wazuh-manager-amd64.rpm"
wazuh_manager_arm64_rpm: "http://example.com/wazuh-manager-arm.rpm"
wazuh_indexer_amd64_deb: "http://example.com/wazuh-indexer-amd64.deb"
wazuh_indexer_arm64_deb: "http://example.com/wazuh-indexer-arm"
wazuh_indexer_amd64_rpm: "http://example.com/wazuh-indexer-amd64.rpm"
wazuh_indexer_arm64_rpm: "http://example.com/wazuh-indexer-arm.rpm"
wazuh_dashboard_amd64_deb: "http://example.com/wazuh-dashboard-amd64.deb"
wazuh_dashboard_arm64_deb: "http://example.com/wazuh-dashboard-arm"
wazuh_dashboard_amd64_rpm: "http://example.com/wazuh-dashboard-amd64.rpm"
wazuh_dashboard_arm64_rpm: "http://example.com/wazuh-dashboard-arm.rpm"
...
```

Follow the steps below to create the Wazuh virtual machine:

1. Clone the Wazuh Virtual Machines repository and select the Wazuh version you want to install in the OVA, in this case `5.0.0`:

   ```bash
   git clone https://github.com/wazuh/wazuh-virtual-machines && cd wazuh-virtual-machines/ && git checkout v5.0.0
   ```

2. Execute the following command to build the OVA image:

   ```bash
   hatch run local-ova:create -p \<path to the urls file\>
   ```

    This command will set up the execution environment, configure the Vagrant VM and export the OVA image.

    You can also customize the name and output directory of the OVA file using the `--name` and `--output` options. For example:
    
    ```bash
    hatch run local-ova:create -p \<path to the urls file\> -n custom-wazuh-ova -o /path/to/output/directory
    ```

    To see all available options, you can use the `-h` or `--help` flag:
    
    ```bash
    hatch run local-ova:create --help
    ```
