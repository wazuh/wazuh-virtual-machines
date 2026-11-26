# Upgrade

The AMI and the OVA are all-in-one deployments: the Wazuh indexer, server and dashboard run on the same node and must be upgraded to the same version. Upgrading them follows the **same procedure as an all-in-one installation of the packages**; the images do not change it.

This page covers upgrades between 5.x releases. A 4.x AMI or OVA cannot be upgraded to 5.0: it is migrated, as [Migrating from Wazuh 4.x](migration.md) describes.

## Between 5.x releases

Follow the all-in-one upgrade guide of the Wazuh installation assistant, [All in one](https://github.com/wazuh/wazuh-installation-assistant/blob/v5.0.0/docs/guide/step-by-step-upgrades/all-in-one.md), and the Wazuh manager's own [upgrade documentation](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/ref/upgrade.md). The image does not ship the Wazuh package repository, so adding it is required.

When the indexer steps ask for `<USERNAME>` and `<PASSWORD>`, use `admin` and the password stored in `/etc/wazuh-indexer/export/credentials.env` (see [AMI security](security/ami/ami-security.md#wazuh-credentials) or [OVA security](security/ova/ova-security.md#wazuh-credentials)). On these images the indexer listens on `127.0.0.1`, and the passwords are in each package's `export/credentials.env`.

An edited `/etc/wazuh-indexer/wazuh-indexer-setup/setup.yml`, or an edited policy file in the same directory, is kept by the upgrade. If the new package also changes that file, the new version is saved beside it as `<file>.rpmnew`: compare both to bring in the new defaults. See [Package upgrades](https://github.com/wazuh/wazuh-indexer-plugins/blob/v5.0.0/docs/ref/modules/setup/customization.md#package-upgrades).
