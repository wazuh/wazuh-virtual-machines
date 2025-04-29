# OVA Installation

The OVA can be deployed by downloading the `.ova` file from the official Wazuh documentation.

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

   SSH root user login has been deactivated; nevertheless, the wazuh-user retains sudo privileges. Root privilege escalation can be achieved by executing the following command:

   ```bash
   sudo -i
   ```

## Access the Wazuh dashboard

Shortly after starting the VM, the Wazuh dashboard can be accessed from the web interface by using the following credentials:

```bash
URL: https://<wazuh_server_ip>
user: admin
password: admin
```

You can find `<wazuh_server_ip>` by typing the following command in the VM:

```bash
ip a
```

## VirtualBox time configuration

In case of using VirtualBox, once the virtual machine is imported it may run into issues caused by time skew when VirtualBox synchronizes the time of the guest machine. To avoid this situation, enable the **Hardware Clock in UTC Time** option in the **System** tab of the virtual machine configuration.

> **Note:** By default, the network interface type is set to Bridged Adapter. The VM will attempt to obtain an IP address from the network DHCP server. Alternatively, a static IP address can be set by configuring the appropriate network files in the Amazon Linux operating system on which the VM is based.
