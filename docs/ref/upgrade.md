# Upgrade

Upgrading the Wazuh components included in the AMI and the OVA follows the **same procedure as when upgrading them individually**.

If you need to update any component (Wazuh server, Wazuh indexer, or Wazuh dashboard), follow the official [Wazuh upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/index.html). The AMI and the OVA are all-in-one deployments, so all three components run on the same node and must be upgraded to the same version:

1. [Preparing the upgrade](https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html#preparing-the-upgrade). The image does not ship the Wazuh package repository, so the first step, adding it, is required.
2. [Upgrading the Wazuh indexer](https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html#upgrading-the-wazuh-indexer).
3. [Upgrading the Wazuh server](https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html#upgrading-the-wazuh-server).
4. [Upgrading the Wazuh dashboard](https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html#upgrading-the-wazuh-dashboard).

The indexer steps ask for `<USERNAME>` and `<PASSWORD>`: use `admin` and the password stored in `/etc/wazuh-indexer/export/credentials.env` (see [AMI security](security/ami/ami-security.md#wazuh-credentials) or [OVA security](security/ova/ova-security.md#wazuh-credentials)).

> The AMI and the OVA do not modify the standard upgrade process of any Wazuh component. On these images the indexer listens on `127.0.0.1`, and the passwords are in each package's `export/credentials.env`.
