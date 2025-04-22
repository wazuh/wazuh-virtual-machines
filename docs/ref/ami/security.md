# Security

## Security considerations about SSH

- The `root` user cannot be identified by SSH and the instance can only be accessed through the `wazuh-user` user.
- SSH authentication through passwords is disabled and the instance can only be accessed through a key pair. This means that only the user with the key pair has access to the instance.
- To access the instance with a key pair, you need to download the key generated or stored in AWS. Then, run the following command to connect with the instance.

    ```bash
    ssh -i "<KEY_PAIR_NAME>" wazuh-user@<YOUR_INSTANCE_IP>
    ```

## Access the Wazuh dashboard

> 🚧 Details on how to access to the Wazuh Dashboard UI will be provided later.
