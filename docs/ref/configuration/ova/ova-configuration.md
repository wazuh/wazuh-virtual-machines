# OVA Configuration

All components included in this virtual image are configured to work out-of-the-box, without the need to modify any settings. However, **all components can be fully customized.**

You can replicate any configuration to the Wazuh components included in the OVA as done for every component by itself.

This means that if you need to make adjustments or customizations, you can simply refer to the official documentation for each Wazuh component in the [Wazuh documentation](https://documentation.wazuh.com) for your version.

> The OVA does not alter the standard behavior or configuration mechanisms of any Wazuh component. The only OVA-specific step is the Wazuh indexer heap, set to a quarter of the RAM on the first boot; after that, `/etc/wazuh-indexer/jvm.options` is yours to change.
