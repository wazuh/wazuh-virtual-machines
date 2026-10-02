# OVA Security

## Security considerations about SSH

- The `root` user cannot be identified by SSH and the instance can only be accessed through the `wazuh-user` user. This retains `sudo` privileges.
- SSH authentication is done with user and password.
- Federal Information Processing Standards (FIPS) is enabled on the system.
- SSH is configured to use modern and secure cryptographic algorithms, in accordance with FIPS activation.

## Wazuh credentials

There is no default password for any Wazuh account. On its first boot the VM generates unique passwords and stores them in `/etc/wazuh/credentials.env` (readable by root only):

| Key | Account |
|---|---|
| `WAZUH_INDEXER_ADMIN_PASSWORD` | `admin` (indexer and dashboard login) |
| `WAZUH_INDEXER_KIBANASERVER_PASSWORD` | `kibanaserver` (dashboard to indexer) |
| `WAZUH_INDEXER_MANAGER_PASSWORD` | `wazuh-manager` (manager to indexer) |
| `WAZUH_MANAGER_API_PASSWORD` | `wazuh` (Wazuh server API) |
| `WAZUH_MANAGER_WUI_PASSWORD` | `wazuh-wui` (dashboard to the Wazuh server API) |

- Read one with `sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-`.
- No two VMs imported from the OVA share a password, a certificate or a CA: the image ships none of them, and each VM creates its own on first boot.
- Save the passwords somewhere safe and then delete the file (`sudo rm /etc/wazuh/credentials.env`). The services keep working without it; the console banner reminds you of this.
- To change a password later, use `wazuh-passwords-tool.sh`.
- This VM's root CA, including its private key, is kept in `/etc/wazuh/ca/` (root only) to reissue certificates later.
