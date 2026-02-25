# Introduction to Wazuh OVA

Wazuh provides a pre-built **Open Virtual Appliance (OVA)**.
An `.ova` file contains a descriptor file (`.ovf`), which describes the structure and configuration of the virtual machine, as well as the virtual disks (`.vmdk`) required for its operation.

The latest Wazuh OVA includes all the Wazuh components:

- Wazuh Server  
- Wazuh Indexer  
- Wazuh Dashboard
- Wazuh Agent

It is designed to be deployed in an **All-in-One** configuration, which means that all components are installed on a single instance. The Wazuh Agent is pre-installed and configured to connect to the local Wazuh Server.

## Compatibility

- **Operating System**: Amazon Linux 2023  
- **Architecture**: 64-bit  
- **VM Format**: OVA
