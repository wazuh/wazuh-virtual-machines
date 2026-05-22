# Post Configurer

The **Post-configurer** runs after the `core` configuration has completed. It finalizes the setup by preparing the AMI or OVA to be exported and distributed as a ready-to-use virtual machine.

Each deployment type has its own post-configuration logic:

- **AMI Post-configuration**: [post-ami.md](ami/post-ami.md)
- **OVA Post-configuration**: [post-ova.md](ova/post-ova.md)
