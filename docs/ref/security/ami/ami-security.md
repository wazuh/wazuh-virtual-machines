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

The password is no longer the instance ID. On its first boot each instance generates unique passwords for every Wazuh account and stores them in `/etc/wazuh/credentials.env` (readable by root only). Connect with SSH and read the `admin` password with:

```bash
sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-
```

## Wazuh credentials

`/etc/wazuh/credentials.env` holds every password generated for this instance:

| Key | Account |
|---|---|
| `WAZUH_INDEXER_ADMIN_PASSWORD` | `admin` (indexer and dashboard login) |
| `WAZUH_INDEXER_KIBANASERVER_PASSWORD` | `kibanaserver` (dashboard to indexer) |
| `WAZUH_INDEXER_MANAGER_PASSWORD` | `wazuh-manager` (manager to indexer) |
| `WAZUH_MANAGER_API_PASSWORD` | `wazuh` (Wazuh server API) |
| `WAZUH_MANAGER_WUI_PASSWORD` | `wazuh-internal-client` (dashboard to the Wazuh server API) |

- No two instances launched from the AMI share a password, a certificate or a CA: the image ships none of them, and each instance creates its own on first boot.
- Save the passwords somewhere safe and then delete the file (`sudo rm /etc/wazuh/credentials.env`). The services keep working without it; the SSH login banner reminds you of this.
- To change a password later, use `wazuh-passwords-tool.sh`. The tool is not included in the image: see [Password management](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html) to download and run it.
- This instance's root CA, including its private key, is kept in `/etc/wazuh/ca/` (root only) to reissue certificates later.
