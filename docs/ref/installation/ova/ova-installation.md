# OVA Installation

The OVA can be deployed by downloading the `.ova` file from the official Wazuh documentation.
You can do this by running the following command:

```bash
curl -sO https://packages.wazuh.com/production/5.x/vm/wazuh-5.1.0.ova
```

To use `pre-release` packages instead, use the following command:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/vm/wazuh-5.1.0-<STAGE>.ova
```

## Import and access the virtual machine

1. Import the OVA to the virtualization platform.
2. If you're using VirtualBox, set the **VMSVGA** graphic controller. Setting another graphic controller freezes the VM window.
   1. Select the imported VM.
   2. Click Settings > Display
   3. In Graphic controller, select the **VMSVGA** option.
3. Start the machine.
4. Access the virtual machine using the following user and password. You can use the virtualization platform or access it via **SSH**.

   ```bash
   user: wazuh-user
   password: wazuh
   ```

   The password is expired: on the first login, on the console or over SSH, you must enter `wazuh` again and then choose a new password. Only the new password is accepted afterwards. There is no SSH key access, and the `root` password is locked.

   SSH root user login has been deactivated; nevertheless, the wazuh-user retains sudo privileges. Root privilege escalation can be achieved by executing the following command:

   ```bash
   sudo -i
   ```

## Access the Wazuh dashboard

Shortly after starting the VM, the Wazuh dashboard can be accessed from the web interface:

```bash
URL: https://<wazuh_manager_ip>
user: admin
```

There is no default password. On its first boot the VM generates unique passwords for every Wazuh account. The indexer and dashboard ones are in `/etc/wazuh-indexer/export/credentials.env` and the Server API ones in `/etc/wazuh-manager/export/credentials.env` (readable by root only). Log in as `wazuh-user` and read the `admin` password with:

```bash
sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2-
```

Keep both files: each one is part of its package's state, and the other packages read it. The console login banner names both. See [OVA security](../../security/ova/ova-security.md#wazuh-credentials) for the rest of the accounts.

You can find `<wazuh_manager_ip>` by typing the following command in the VM:

```bash
ip a
```

## Enroll agents

Agents enroll with a token the manager mints for the address they will connect to. As root on the VM:

```bash
/var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <wazuh_manager_ip>
```

Pass the token to the agent installer as `WAZUH_ENROLLMENT_TOKEN`, with the same address as the manager. Agents connect on TCP 1517 (1514 for legacy agents): with a NAT network, forward those ports to the VM.

The address must be one the manager's certificate names: the VM's host name and the addresses it had at first boot. Otherwise the mint fails with `ERROR 9025: Enrollment token refused: address not in certificate SAN`. If the address changed after the first boot, reissue the manager certificates first (see [Certificate lifecycle after first boot](../../modules/configurer/post/ova/post-ova.md#certificate-lifecycle-after-first-boot)).

## VirtualBox time configuration

In case of using VirtualBox, once the virtual machine is imported it may run into issues caused by time skew when VirtualBox synchronizes the time of the guest machine. To avoid this situation, enable the **Hardware Clock in UTC Time** option in the **System** tab of the virtual machine configuration.

> **Note:** By default, the network interface type is set to Bridged Adapter. The VM will attempt to obtain an IP address from the network DHCP server. Alternatively, a static IP address can be set by configuring the appropriate network files in the Amazon Linux 2023 operating system on which the VM is based.
