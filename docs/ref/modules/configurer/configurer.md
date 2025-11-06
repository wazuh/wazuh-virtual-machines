# Configurer

The `configurer` module is responsible for all the required configuration tasks, including both the setup of Wazuh components and the specific adjustments needed for AMI and OVA environments.

This module is divided into three main submodules:

- **Core** ([core.md](core/core.md)): Handles the general Wazuh configuration. It generates certificates for each component, installs them, and applies their respective configurations. Once this module is executed, the machine is ready to be used.

- **Pre-configurer**([pre.md](pre/pre.md)): Performs the preliminary setup required before executing the core module. Each deployment type (AMI or OVA) uses this submodule to prepare the environment with deployment-specific settings.

- **Post-configurer** ([post.md](post/post.md)): Runs after the `core` configuration has completed. It finalizes the setup by preparing the AMI or OVA to be exported and distributed as a ready-to-use virtual machine.
