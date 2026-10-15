#!/bin/sh

DEBUG=$1
WAZUH_VERSION=$2
SYSTEM_USER=$3

[[ ${DEBUG} = "yes" ]] && set -ex || set -e

# OVA Welcome message
cat > /etc/issue <<EOF

Welcome to the Wazuh OVA version ${WAZUH_VERSION}
Login credentials:
  User: ${SYSTEM_USER}
  Password: wazuh (you must change it on the first login)

Wazuh dashboard: https://<this VM's IP address>   User: admin
The passwords generated for this VM are stored in
/etc/wazuh-indexer/export/credentials.env (dashboard and indexer users) and
/etc/wazuh-manager/export/credentials.env (Server API users).
Print the admin password with:
  sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2-

EOF

# User Welcome message. The version is written at build time: unlike the AMI's update-motd.d
# script, pam_motd only prints this file, and /etc/issue cannot run anything either
rm -f /usr/lib/motd.d/30-banner
cat > /usr/lib/motd.d/40-wazuh-banner <<EOF

    Welcome to the Wazuh OVA version ${WAZUH_VERSION}

wwwwww.           wwwwwww.          wwwwwww.
wwwwwww.          wwwwwww.          wwwwwww.
 wwwwww.         wwwwwwwww.        wwwwwww.
 wwwwwww.        wwwwwwwww.        wwwwwww.
  wwwwww.       wwwwwwwwwww.      wwwwwww.
  wwwwwww.      wwwwwwwwwww.      wwwwwww.
   wwwwww.     wwwwww.wwwwww.    wwwwwww.
   wwwwwww.    wwwww. wwwwww.    wwwwwww.
    wwwwww.   wwwwww.  wwwwww.  wwwwwww.
    wwwwwww.  wwwww.   wwwwww.  wwwwwww.
     wwwwww. wwwwww.    wwwwww.wwwwwww.
     wwwwwww.wwwww.     wwwwww.wwwwwww.
      wwwwwwwwwwww.      wwwwwwwwwwww.
      wwwwwwwwwww.       wwwwwwwwwwww.      oooooo
       wwwwwwwwww.        wwwwwwwwww.      oooooooo
       wwwwwwwww.         wwwwwwwwww.     oooooooooo
        wwwwwwww.          wwwwwwww.      oooooooooo
        wwwwwww.           wwwwwwww.       oooooooo
         wwwwww.            wwwwww.         oooooo


         WAZUH Open Source Security Platform
                  https://wazuh.com
EOF

# Show the Wazuh banner once in SSH
echo -e "\nif [[ \"\$(tty)\" == /dev/tty* ]]; then\n    cat /usr/lib/motd.d/40-wazuh-banner\nfi" | sudo tee -a /etc/profile
