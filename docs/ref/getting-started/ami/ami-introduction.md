# Introduction to Wazuh AMI

Wazuh provides a pre-built **Amazon Machine Image (AMI)**. An AMI is a ready-to-use template for creating virtual computing environments in **Amazon Elastic Compute Cloud (Amazon EC2)**.

The latest Wazuh AMI includes all the Wazuh components:

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Wazuh Agent

It is designed to be deployed in an **All-in-One** configuration, which means that all components are installed on a single instance. The Wazuh Agent is pre-installed and configured to connect to the local Wazuh Manager.

## Compatibility

- **Operating System**: Amazon Linux 2023
- **Architecture**: x86_64/aarch64
- **VM Format**: AWS AMI
