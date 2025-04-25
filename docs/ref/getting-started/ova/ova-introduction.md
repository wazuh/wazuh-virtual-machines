# Introduction to Wazuh OVA

Wazuh provides a pre-built **Open Virtual Appliance (OVA)**.
An `.ova` file contains a descriptor file (`.ovf`), which describes the structure and configuration of the virtual machine, as well as the virtual disks (`.vmdk`) required for its operation.

The latest Wazuh OVA includes the Wazuh central components:

- Wazuh Server  
- Wazuh Indexer  
- Wazuh Dashboard

It is designed to be deployed in an **All-in-One** configuration, which means that all components are installed on a single instance.

> This OVA does not include the Wazuh agent. If you need to deploy Wazuh agents, you can do so separately on your desired hosts.

## Compatibility

- **Operating System**: Amazon Linux 2023  
- **Architecture**: 64-bit  
- **VM Format**: AWS OVA
