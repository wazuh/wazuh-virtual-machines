# OVA Security

## Security considerations about SSH

- The `root` user cannot be identified by SSH and the instance can only be accessed through the `wazuh-user` user. This retains `sudo` privileges.
- SSH authentication is done with user and password. The documented `wazuh-user` / `wazuh` password is expired and must be changed on the first login, on the console or over SSH.
- The `root` password is locked, so `root` cannot log in with a password on the console either.
- No SSH key is authorized for any user, and the build's Vagrant key is removed.
- Each VM generates its own SSH host keys and `/etc/machine-id` on its first boot, so two VMs imported from the same OVA do not share them.
- Federal Information Processing Standards (FIPS) is enabled on the system.
- SSH is configured to use modern and secure cryptographic algorithms, in accordance with FIPS activation.

## Wazuh credentials

There is no default password for any Wazuh account. On its first boot the VM generates unique passwords. Each package stores the ones it owns in its own `export/credentials.env` (readable by root only):

| Key | Account | File |
|---|---|---|
| `WAZUH_INDEXER_ADMIN_PASSWORD` | `admin` (indexer and dashboard login) | `/etc/wazuh-indexer/export/credentials.env` |
| `WAZUH_INDEXER_KIBANASERVER_PASSWORD` | `kibanaserver` (dashboard to indexer) | `/etc/wazuh-indexer/export/credentials.env` |
| `WAZUH_INDEXER_MANAGER_PASSWORD` | `wazuh-manager` (manager to indexer) | `/etc/wazuh-indexer/export/credentials.env` |
| `WAZUH_MANAGER_API_PASSWORD` | `wazuh` (Wazuh server API) | `/etc/wazuh-manager/export/credentials.env` |
| `WAZUH_MANAGER_WUI_PASSWORD` | `wazuh-internal-client` (dashboard to the Wazuh server API) | `/etc/wazuh-manager/export/credentials.env` |

- Read one with `sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2-`.
- No two VMs imported from the OVA share a password, a certificate or a CA: the image ships none of them, and each VM creates its own on first boot.
- Keep both files: each one is part of its package's state, and the other packages read it. They are readable by root only. The console banner names both.
- To change a password later, use `wazuh-passwords-tool.sh`. The tool is not included in the image: see [Password management](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html) to download and run it.
- Each package keeps the CA it minted for this VM, including its private key, in its own `ca/` directory (`/etc/wazuh-indexer/ca/`, `/etc/wazuh-manager/ca/`, `/etc/wazuh-dashboard/ca/`, root only), to reissue certificates later.
