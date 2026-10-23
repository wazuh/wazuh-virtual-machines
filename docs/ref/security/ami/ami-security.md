# AMI Security

## Security considerations about SSH

- The `root` user cannot be identified by SSH and the instance can only be accessed through the `wazuh-user` user.
- SSH authentication through passwords is disabled and the instance can only be accessed through a key pair. This means that only the user with the key pair has access to the instance.
- To access the instance with a key pair, you need to download the key generated or stored in AWS. Then, run the following command to connect with the instance.

    ```bash
    ssh -i "<KEY_PAIR_NAME>" wazuh-user@<YOUR_INSTANCE_IP>
    ```

## Access the Wazuh dashboard

To access the Wazuh dashboard through a browser, you must use the public IP address provided by AWS, or the private IP address if you are within a VPC without internet access. Log in with the username `admin`.

The password is no longer the instance ID. On its first boot each instance generates unique passwords for every Wazuh account. Each package stores the ones it owns in its own `export/credentials.env` (readable by root only). Connect with SSH and read the `admin` password with:

```bash
sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2-
```

## Wazuh credentials

Every password generated for this instance, and the file that holds it:

| Key | Account | File |
|---|---|---|
| `WAZUH_INDEXER_ADMIN_PASSWORD` | `admin` (indexer and dashboard login) | `/etc/wazuh-indexer/export/credentials.env` |
| `WAZUH_INDEXER_KIBANASERVER_PASSWORD` | `kibanaserver` (dashboard to indexer) | `/etc/wazuh-indexer/export/credentials.env` |
| `WAZUH_INDEXER_MANAGER_PASSWORD` | `wazuh-manager` (manager to indexer) | `/etc/wazuh-indexer/export/credentials.env` |
| `WAZUH_MANAGER_API_PASSWORD` | `wazuh` (Wazuh server API) | `/etc/wazuh-manager/export/credentials.env` |
| `WAZUH_MANAGER_WUI_PASSWORD` | `wazuh-internal-client` (dashboard to the Wazuh server API) | `/etc/wazuh-manager/export/credentials.env` |

- No two instances launched from the AMI share a password, a certificate or a CA: the image ships none of them, and each instance creates its own on first boot.
- Keep both files: each one is part of its package's state, and the other packages read it. They are readable by root only. The SSH login banner names both.
- To change a password later, use the passwords tool the indexer package ships: `sudo /usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh`. It publishes the new value in the owner's `export/credentials.env`.
- Each package keeps the CA it minted for this instance, including its private key, in its own `ca/` directory (`/etc/wazuh-indexer/ca/`, `/etc/wazuh-manager/ca/`, `/etc/wazuh-dashboard/ca/`, root only), to reissue certificates later.
