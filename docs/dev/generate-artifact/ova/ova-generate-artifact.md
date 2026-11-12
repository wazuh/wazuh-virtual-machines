# Generate OVA artifact

You can generate the OVA artifact automatically by using the GitHub Actions workflow.

> 📦 This OVA is the one that will eventually be published and made available for users to download and deploy an All-in-one environment easily.

## Automatic execution with GitHub Actions

This process is fully automatic. It can be used from the **Actions** page of the wazuh-virtual-machines repository. The name of the workflow is `5_OVA_builder.yaml` or **(5.x) OVA Builder** in the web browser.

This workflow accepts the following inputs:

- `id`: Unique identifier for the workflow run.
- `checksum`: If set to true, it will generate package checksum file `.sha512`. Defaults to false.
- `wazuh_virtual_machines_reference`: Branch or tag of the `wazuh-virtual-machines` repository.
- `wazuh_automation_reference`: Branch or tag of the `wazuh-automation` repository.
- `is_stage`: If set to false, it will add the last commit hash to the final filename of the OVA. Otherwise, the name will remain with the version and stage of the branch. Defaults to false.
- `ova_revision`: Revision of the OVA file, appended to the file name after the version (`wazuh-<version>-<ova_revision>.ova`).
  For OVA candidates, this must be a number (e.g., `1`).
  For development OVAs, use `0`. Defaults to `0`.
- `wazuh_package_type`: Package type used for the OVA: `prod`, `pre-prod`, or `dev`. Defaults to `dev`.
- `commit_list`: Wazuh components revisions (JSON list) `["indexer-revision", "manager-revision", "dashboard-revision", "agent-revision", "assistant-revision"]`, where each revision is `latest` or a commit hash.
  Only needed if `wazuh_package_type` is `dev`. Defaults to `latest` for each Wazuh package.
- `skip_signature_check`: Install the Wazuh packages without checking their signature. Only for unsigned development packages, such as a commit hash in `commit_list`. Defaults to false.
- `destroy`: If set, the EC2 instance used for building the OVA will be destroyed once complete. Defaults to true.

The resulted OVA will be stored in an **AWS S3 bucket**.
If you need information about where it's stored or how to access it, please contact the **DevOps team**.
