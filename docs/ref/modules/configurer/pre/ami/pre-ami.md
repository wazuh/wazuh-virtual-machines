# AMI Pre Configurer

The AMI pre-configuration step includes several system-level tasks to prepare the virtual machine before installing and configuring Wazuh components. These tasks include:

- Updating the Message of the Day (MOTD) with the Wazuh logo.
- Creating the `wazuh-user` user.
- Remove remote default user.
- Changing the machine’s hostname.
- Modifying various files from the base image.
- Creating necessary directories for the post-configurer to run.

These changes prepare the AMI environment to continue with the full configuration process.

## Considerations

The AMI pre-configurer is designed to be executed on a **remote machine only**, since it involves deleting and creating users. Running it locally is not allowed, as active sessions with users being removed would interfere.

This remote machine must be an **AWS instance**, since the resulting image will be exported once configuration is completed.

## Parameters

- `--inventory`: Must point to an Ansible-compatible inventory file. This is a required parameter to run this module.

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

## Execution

This module is designed to run alongside the `post-configurer`, not individually. Therefore, no Hatch command is available for running it directly.

However, if you need to execute it manually, you can do so via command line:

```bash
python -m main --execute ami-pre-configurer --inventory <path-to-inventory>
```
