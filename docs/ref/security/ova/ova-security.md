# OVA Security

## Security considerations about SSH

- The `root` user cannot be identified by SSH and the instance can only be accessed through the `wazuh-user` user. This retains `sudo` privileges.
- SSH authentication is done with user and password.
- Federal Information Processing Standards (FIPS) is enabled on the system.
- SSH is configured to use modern and secure cryptographic algorithms, in accordance with FIPS activation.
