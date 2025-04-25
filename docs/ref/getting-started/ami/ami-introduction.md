# Introduction to Wazuh AMI

Wazuh provides a pre-built **Amazon Machine Image (AMI)**. An AMI is a ready-to-use template for creating virtual computing environments in **Amazon Elastic Compute Cloud (Amazon EC2)**.

The latest Wazuh AMI includes the Wazuh central components:

- Wazuh Server  
- Wazuh Indexer  
- Wazuh Dashboard

It is designed to be deployed in an **All-in-One** configuration, which means that all components are installed on a single instance.

> This AMI does not include the Wazuh agent. If you need to deploy Wazuh agents, you can do so separately on your desired hosts.

## Compatibility

- **Operating System**: Amazon Linux 2023  
- **Architecture**: 64-bit  
- **VM Format**: AWS AMI
