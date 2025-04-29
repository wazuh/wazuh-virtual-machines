# Introduction

This section introduces the two deployment options developed in the Wazuh Virtual Machines repository.

Wazuh provides the option to deploy two types of virtual machines with a base all-in-one (AIO) installation that includes the main Wazuh components. This allows us to have a ready-to-use virtual machine without needing to configure any components, making it completely transparent to the user.

We can deploy two types of virtual machines:

- AMI ([ami-introduction.md](ami/ami-introduction.md)): An AWS image ready to be used as the image for an EC2 instance.
- OVA ([ova-introduction.md](ova/ova-introduction.md)): A `.ova` VM compatible with VirtualBox. We can import it into VirtualBox and have a VM ready to use.
