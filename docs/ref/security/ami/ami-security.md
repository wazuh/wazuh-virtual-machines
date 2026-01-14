# AMI Security

## Security considerations about SSH

- The `root` user cannot be identified by SSH and the instance can only be accessed through the `wazuh-user` user.
- SSH authentication through passwords is disabled and the instance can only be accessed through a key pair. This means that only the user with the key pair has access to the instance.
- To access the instance with a key pair, you need to download the key generated or stored in AWS. Then, run the following command to connect with the instance.

    ```bash
    ssh -i "<KEY_PAIR_NAME>" wazuh-user@<YOUR_INSTANCE_IP>
    ```

## Access the Wazuh dashboard

To access the Wazuh dashboard through a browser, you must use the public IP address provided by AWS, or the private IP address if you are within a VPC without internet access. To log in to the Wazuh dashboard, use the username `admin` and the password will be the instance ID, replacing the `i` with an `I`, for example: `I-09b7e3e4b5e89b0a0`
