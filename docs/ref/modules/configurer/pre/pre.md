# Pre Configurer

The `pre-configurer` submodule is responsible for applying the initial configuration steps required before running the `core` module. This step is essential for preparing the AMI or OVA environments properly before the Wazuh components are installed and configured.

Each deployment type has its own pre-configuration logic:

- **AMI Pre-configuration**: [pre-ami.md](ami/pre-ami.md)
- **OVA Pre-configuration**: [pre-ova.md](ova/pre-ova.md)
