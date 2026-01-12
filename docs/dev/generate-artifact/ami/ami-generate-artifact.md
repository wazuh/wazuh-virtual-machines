# Generate AMI artifact

You can generate the AMI artifact in two different ways:

- **Manually**, by running the code yourself and exporting the AMI from a pre-configured instance.
- **Automatically**, using the GitHub Actions workflow.

> 📦 This AMI is the one that will eventually be published and made available for users to deploy an All-in-one environment easily.

## Manual Execution

To generate the AMI manually, you will need two things:

1. An **inventory file** in Ansible inventory format, like the following:

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

2. A **file containing the URLs** to the Wazuh component packages.

Once you have both files ready, you can configure the AMI using either **Hatch** or the **command line**:

- **Using Hatch**

  ```bash
  hatch run dev-ami-configurer:run --inventory <inventory path> --packages-url-path <urls file path>
  ```

- **Using the Command Line**

  ```bash
  python -m main --execute all-ami --inventory <inventory path> --packages-url-path <urls file path>
  ```

- **Build ARM Wazuh AMI**

  ```bash
  hatch run dev-ami-configurer:run --inventory <inventory path> --packages-url-path <urls file path> --arch aarch64
  ```

This command will configure the AMI on the instance specified in your inventory.
Once the execution is complete, **you must export the AMI manually from the AWS Console**.

## Automatic Execution with GitHub Actions

To automate the process, you can use the `packages_builder_ami.yaml` workflow from the **Actions** section in GitHub.

This workflow accepts the following inputs:

- `id`: Unique identifier for the workflow run.
- `wazuh_virtual_machines_reference`: Branch or tag of the `wazuh-virtual-machines` repository.
- `wazuh_automation_reference`: Branch or tag of the `wazuh-automation` repository.
- `ami_revision`: Suffix for the AMI name.
  For AMI candidates, this must be a number (e.g., `-1`).
  For development AMIs, you can use a different format (e.g., `-dev`).
- `wazuh_package_type`: Package type used for the AMI: `release`, `pre-release`, or `dev`.
- `architecture`: Determine the architecture. It must be a string list (JSON format). E.g: ["amd64", "arm64"]
- `commit_list`: Wazuh components revisions (comma-separated string list) ["indexer-revision", "server-revision", "dashboard-revision"]'
          (Only needed if the Wazuh package type is dev-latest or dev-commit)
- `customizer_debug`: Enable debug mode in the AMI customizer
- `destroy`: If set, the EC2 instance used for building the AMI will be destroyed once complete.

The resulting AMI will be stored in **AWS**.
If you need information about where it's stored or how to access it, please contact the **DevOps team**.
