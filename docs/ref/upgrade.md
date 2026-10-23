# Upgrade

The AMI and the OVA are all-in-one deployments: the Wazuh indexer, server and dashboard run on the same node and must be upgraded to the same version. Upgrading them follows the **same procedure as an all-in-one installation of the packages**; the images do not change it.

## Between 5.x releases

Follow the all-in-one upgrade guide of the Wazuh installation assistant, [All in one](https://github.com/wazuh/wazuh-installation-assistant/blob/5.0.0/docs/guide/step-by-step-upgrades/all-in-one.md), and the Wazuh manager's own [upgrade documentation](https://github.com/wazuh/wazuh/blob/5.0.0/docs/ref/upgrade.md). The image does not ship the Wazuh package repository, so adding it is required.

When the indexer steps ask for `<USERNAME>` and `<PASSWORD>`, use `admin` and the password stored in `/etc/wazuh-indexer/export/credentials.env` (see [AMI security](security/ami/ami-security.md#wazuh-credentials) or [OVA security](security/ova/ova-security.md#wazuh-credentials)). On these images the indexer listens on `127.0.0.1`, and the passwords are in each package's `export/credentials.env`.

## From 4.x and from 5.0.0 pre-releases

A 4.x AMI or OVA cannot be upgraded in place to 5.0, and neither can an image of 5.0.0 RC 1 or an earlier pre-release ([wazuh/wazuh#40338](https://github.com/wazuh/wazuh/issues/40338)). Launch a 5.0 image as a new deployment instead, and carry the agents across with the Wazuh manager migration procedure: [Migrating a Wazuh manager from 4.x to 5.0](https://github.com/wazuh/wazuh/blob/5.0.0/docs/guide/migration/manager-4x-to-5x.md). Its [`wazuh-migrate-identity.py`](https://github.com/wazuh/wazuh/blob/5.0.0/tools/migration/wazuh-migrate-identity.py) tool exports the agent keys, registry and groups from the stopped 4.x manager and imports them into the 5.0 manager through its API, so enrolled agents reconnect without enrolling again. The configuration, the ruleset and the agent upgrade are covered by the same guide.
