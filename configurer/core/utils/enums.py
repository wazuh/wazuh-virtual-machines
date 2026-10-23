# The manager's configuration directory since wazuh/wazuh#40346. It used to be
# /var/wazuh-manager/etc, which is gone (no symlink is left behind). Binaries, logs and
# VERSION.json stay under /var/wazuh-manager.
WAZUH_MANAGER_CONF_DIR = "/etc/wazuh-manager"

