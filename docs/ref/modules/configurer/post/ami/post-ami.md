# AMI Post Configurer

The **AMI Post-configurer** is responsible for preparing the AMI to be exported as an artifact once the Wazuh components are configured and the pre-configuration steps are completed. This post-configuration process includes:

- Pausing all services.
- Deleting any Wazuh indices created in the indexer during the configuration process.
- Clearing all log files that may have been generated during the configuration.
- Removing the base directory created in the provisioner step that contains the certs tool and component packages.

These steps ensure that when a user launches an instance from the base AMI image, they will find a clean Wazuh environment.

## Creation of Custom Certificate Service

In the **core-configurer**, certificates are created for each Wazuh component. When creating the AMI, every instance launched from this image will have the same certificates, which could pose a security issue.

To address this, a custom systemd service is created that, when the instance starts for the first time, generates new certificates for each Wazuh component and restarts the services. This ensures that each instance has unique certificates.

For this service, a Python virtual environment is set up with the necessary dependencies to run the corresponding Python scripts. This virtual environment is created during the post-configurer process, so that when the service runs and generates the new certificates, the service files and the virtual environment used for execution are deleted. This ensures that any unnecessary files and dependencies are removed from the system.

## Considerations

Just like the pre-configurer, this module is designed to be executed on a remote machine, meaning the `--inventory` option must be provided.

The remote machine must be an AWS instance, as this will be the one exported after the configuration process is complete.

## Execution

This module is intended to be executed along with the pre-configurer and not individually. Therefore, there is no Hatch command available for this specific module.

If you need to execute it individually, you can do so via the command line:

```bash
python -m main --execute ami-post-configurer --inventory <path-to-inventory>
```

### Global Execution

A global option has been created for the CLI: `--execute all-ami`. This command allows you to run the entire process of creating and configuring the AMI, which includes:

1. AMI Pre-configurer
2. Provisioner
3. Core-configurer
4. AMI Post-configurer

To run this option, the following required parameters must be specified:

- `--inventory`: Points to an Ansible-compatible inventory file.
- `--packages-url-path`: A file containing the URLs for the components to be installed.

You can execute it in two ways:

- Using Hatch:

    ```bash
    hatch run dev-ami-configurer:run --inventory <path-to-inventory> --packages-url-path <path-to-file>
    ```

- Using the command line:

    ```bash
    python -m main --execute all-ami --inventory <path-to-inventory> --packages-url-path <path-to-file>
    ```
