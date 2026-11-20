# OVA Configuration

All components included in this virtual image are configured to work out-of-the-box, without the need to modify any settings. However, **all components can be fully customized.**

You can replicate any configuration to the Wazuh components included in the OVA as done for every component by itself.

This means that if you need to make adjustments or customizations, you can simply refer to the official documentation for each Wazuh component in the [Wazuh documentation](https://documentation.wazuh.com) for your version.

> The OVA does not alter the standard behavior or configuration mechanisms of any Wazuh component. The only OVA-specific step is the Wazuh indexer heap, set to a quarter of the RAM on the first boot; after that, `/etc/wazuh-indexer/jvm.options` is yours to change.

## Wazuh indexer setup configuration

The Wazuh indexer package installs `/etc/wazuh-indexer/wazuh-indexer-setup/setup.yml`, which tunes the settings of the index templates (shards, replicas, refresh interval, codec, translog durability) and selects editable copies of the ISM retention policies, stored as `<policy-id>.json` in the same directory. As installed, every key is commented out and the packaged defaults apply, which are the ones designed for an all-in-one deployment such as this OVA. The OVA does not modify these files.

To change a setting, edit the file and restart the Wazuh indexer:

```bash
sudo systemctl restart wazuh-indexer
```

A change applies only to the indices created after the restart; the indices that already exist keep their settings. The indices are created on the first boot of the OVA, so they keep the packaged settings until they are replaced:

- A data stream, such as `wazuh-events-v5-<category>`, takes the new settings at its next rollover.
- A changed retention policy is used by the indices created afterwards; the existing ones keep the policy version they run.

The keys, their valid values and how to apply a change to the indices that already exist are described in the [Setup plugin customization](https://github.com/wazuh/wazuh-indexer-plugins/blob/v5.0.0/docs/ref/modules/setup/customization.md) reference.
