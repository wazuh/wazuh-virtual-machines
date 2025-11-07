# Generate OVA artifact

You can generate the OVA artifact automatically by using the GitHub Actions workflow.

> 📦 This OVA is the one that will eventually be published and made available for users to download and deploy an All-in-one environment easily.

## Automatic execution with GitHub Actions

This process is fully automatic. It can be used from the **Actions** page of the wazuh-virtual-machines repository. The name of the workflow is `builder_OVA.yaml` or **Build OVA** in the web browser.

This workflow accepts the following inputs:

- `id`: Unique identifier for the workflow run.
- `checksum`: If set to true, it will generate package checksum file `.sha512`. Defaults to false.
- `wazuh virtual machines reference`: Branch or tag of the `wazuh-virtual-machines` repository.
- `wazuh automation reference`: Branch or tag of the `wazuh-automation` repository.
- `is_stage`: If set to false, it will add the last commit hash to the final filename of the OVA. Otherwise, the name will remain with the version and stage of the branch. Defaults to false.
- `ova_revision`: Revision of the OVA file.
  For AMI candidates, this must be a number (e.g., `-1`).  
  For development AMIs, you can use a different format (e.g., `-0`).
- `wazuh_package_type`: Package type used for the AMI: `release`, `pre-release`, or `dev`.
- `commit_list`: If using `dev` as `wazuh_package_type`, this should be a list of revisions (e.g., `latest` or the commit hash for each package). Defaults to `latest` for each Wazuh package.
- `destroy`: If set, the EC2 instance used for building the OVA will be destroyed once complete. Defaults to true.

The resulted OVA will be stored in an **AWS S3 bucket**.
If you need information about where it's stored or how to access it, please contact the **DevOps team**.
