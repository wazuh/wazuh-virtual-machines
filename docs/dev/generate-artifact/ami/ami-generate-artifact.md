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

This command will configure the AMI on the instance specified in your inventory.  
Once the execution is complete, **you must export the AMI manually from the AWS Console**.

## Automatic Execution with GitHub Actions

To automate the process, you can use the `packages_builder_ami.yaml` workflow from the **Actions** section in GitHub.

This workflow accepts the following inputs:

- `id`: Unique identifier for the workflow run.
- `wazuh virtual machines reference`: Branch or tag of the `wazuh-virtual-machines` repository.
- `wazuh automation reference`: Branch or tag of the `wazuh-automation` repository.
- `ami revision`: Suffix for the AMI name.  
  For AMI candidates, this must be a number (e.g., `-1`).  
  For development AMIs, you can use a different format (e.g., `-dev`).
- `package type`: Package type used for the AMI: `release`, `pre-release`, or `dev`.
- `dev packages revision`: If using `dev` as package type, this should be a list of revisions (e.g., `latest` or the commit hash for each package).
- `destroy`: If set, the EC2 instance used for building the AMI will be destroyed once complete.

The resulting AMI will be stored in **AWS**.  
If you need information about where it's stored or how to access it, please contact the **DevOps team**.
