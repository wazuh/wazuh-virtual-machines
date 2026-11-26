# Migrating from Wazuh 4.x

A 4.x AMI or OVA cannot be upgraded in place to 5.0: the 5.0 packages refuse to install over 4.x, and the 5.0 manager is a fresh installation with a new layout, a new configuration format and a new agent protocol. The deployment is migrated instead. The Wazuh manager procedure, [Migrating a Wazuh manager from 4.x to 5.0](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md), carries the agent IDs, names and keys, their groups and the API users across, so the enrolled agents reconnect without enrolling again. This page follows that guide and covers what the AMI and the OVA change in it. Read its [What is kept and what is not](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#what-is-kept-and-what-is-not) first: the configuration, the rules, the decoders and the CDB lists are rewritten by hand on any path. [Configuration and content](#configuration-and-content) says where each 4.x file is on the image and where 5.0 takes it, and [Historical data](#historical-data) how to keep the 4.x alerts.

There are two paths:

| | New VM | Same VM |
|---|---|---|
| What runs 5.0 | A new 5.0 AMI or OVA, beside the 4.x one | The 4.x AMI or OVA, with 4.x removed and the 5.0 packages installed |
| Manager downtime | From the export until the cutover | From the export until the agent listeners are reopened |
| Rollback | The 4.x VM is kept | None: going back means reinstalling 4.x and restoring your own backups |
| 4.x alerts | Stay in the 4.x VM's indexer | Kept only through a snapshot taken before 4.x is removed |
| Result | A 5.0 image | The 4.x image with the 5.0 packages, see [What differs from a 5.0 image](#what-differs-from-a-50-image) |

## Before you start

- **Migration tool.** Both paths use [`wazuh-migrate-identity.py`](https://github.com/wazuh/wazuh/blob/v5.0.0/tools/migration/wazuh-migrate-identity.py) for steps 1, 3 and 5 of the manager guide. Download it to both VMs:

    ```bash
    curl -sO https://raw.githubusercontent.com/wazuh/wazuh/v5.0.0/tools/migration/wazuh-migrate-identity.py
    ```

    Run it with `sudo`: `wazuh-user` cannot read the manager's directories. On the 4.x VM the system `python3` runs `export`. On the 5.0 side run `import` and `check` with the Python the manager bundles, `/var/wazuh-manager/framework/python/bin/python3`. The `sqlite3` command-line tool is not needed. Run `export` with `--dry-run` first and read its **Review before going on** list.
- **API users.** The commands below carry the 4.x API users, roles and policies with `--with-rbac`. The 4.x `rbac.db` also brings back the 4.x passwords of `wazuh` and `wazuh-internal-client`, and the image's dashboard reads `wazuh-internal-client` from `/etc/wazuh-manager/export/credentials.env`. After the import, set both back to the published values, as [API users, roles and policies](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#api-users-roles-and-policies) describes, or the dashboard cannot reach the API:

    ```bash
    sudo sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env \
        | sudo /var/wazuh-manager/bin/rbac_control change-password -u wazuh -p -
    sudo sed -n 's/^WAZUH_MANAGER_WUI_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env \
        | sudo /var/wazuh-manager/bin/rbac_control change-password -u wazuh-internal-client -p -
    ```

- **Dashboard.** The image's dashboard has its own migration: [Migration guide: Wazuh dashboard 4.x to 5.x](https://github.com/wazuh/wazuh-dashboard-plugins/blob/v5.0.0/docs/guide/migration/README.md). Its [Before you begin](https://github.com/wazuh/wazuh-dashboard-plugins/blob/v5.0.0/docs/guide/migration/README.md#before-you-begin) steps (backing up the dashboard files and the PDF reports, and exporting your own dashboards and visualizations) need the 4.x dashboard running: on the same VM path, do them before step 3. Once 5.0 runs, import the saved objects as its [Custom dashboards and visualizations](https://github.com/wazuh/wazuh-dashboard-plugins/blob/v5.0.0/docs/guide/migration/dashboards.md) page describes.
- **Manager address.** Every 4.x agent dials the address in its `<client><server><address>`. Plan for the 5.0 manager to answer on that address at the cutover, or to edit it on every agent.

## New VM

1. **Deploy a 5.0 image** following [AMI Installation](installation/ami/ami-installation.md) or [OVA Installation](installation/ova/ova-installation.md), on an address the 4.x agents do not dial: for the OVA, any IP but the 4.x VM's; for the AMI, a new instance without the 4.x Elastic IP or DNS name. The image's first boot starts the manager with the agent listeners open, so the installation variables of [Install it out of the fleet's reach](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#install-it-out-of-the-fleets-reach) do not apply: the address is what keeps the fleet away until the cutover.

2. **Remove the pre-installed agent from the manager.** The 5.0 image enrolls its own agent on the first boot, and it takes the first free ID, `001`, which every 4.x fleet already uses for its first agent. The import refuses an agent whose ID is taken (`There is an agent with the same ID: 001`). On the 5.0 VM, stop the local agent, delete it through the Server API and clear its identity:

    ```bash
    sudo systemctl stop wazuh-agent
    AGENT_ID=$(sudo awk 'NR == 1 { print $1 }' /var/ossec/etc/client.keys)
    API_PASSWORD=$(sudo sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env)
    TOKEN=$(curl -sk -u "wazuh:${API_PASSWORD}" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
    curl -sk -X DELETE "https://localhost:55000/agents?agents_list=${AGENT_ID}&status=all&older_than=0s&purge=true" \
        -H "Authorization: Bearer ${TOKEN}"
    sudo sh -c ': > /var/ossec/etc/client.keys'
    sudo rm -f /var/ossec/etc/certs/root-ca.pem /var/ossec/etc/certs/.anchor-committed /var/ossec/etc/reenroll.secret
    ```

    Wait about two minutes before the import in step 4; doing this before the export keeps that wait out of the downtime. The manager does not hand out a deleted agent's ID again until the indexer purge of its documents has run (`authd.purge_delay`, 120 seconds by default), and until then the import reports `The agent ID cannot be reused yet`. If it does, wait and run the import again with `--force`. The documents the local agent indexed before it was deleted stay in the 5.0 indices under its ID, beside those of the 4.x agent that takes it.

3. **Back up and export the 4.x manager** as in [step 1](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#1-back-up-the-4x-manager) of the manager guide, on the 4.x VM:

    ```bash
    sudo systemctl stop wazuh-manager
    sudo systemctl disable wazuh-manager
    sudo python3 wazuh-migrate-identity.py export --with-rbac /root/wazuh-4x-bundle
    ```

    Copy `/root/wazuh-4x-bundle` to the 5.0 VM and keep it readable by root only: it carries every agent key. From here the 4.x agents retry against a stopped manager and buffer their events.

4. **Import the identity** ([step 3](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#3-restore-the-identity-data) of the manager guide), restart the manager and restore the published API passwords as described in [Before you start](#before-you-start):

    ```bash
    sudo /var/wazuh-manager/framework/python/bin/python3 wazuh-migrate-identity.py import --with-rbac /root/wazuh-4x-bundle
    sudo systemctl restart wazuh-manager
    ```

    Compare the manager with the bundle before the local agent is enrolled again in step 5:

    ```bash
    sudo /var/wazuh-manager/framework/python/bin/python3 wazuh-migrate-identity.py check /root/wazuh-4x-bundle
    ```

    Expected: `The target matches the bundle.`

    Then migrate the configuration as [Configuration and content](#configuration-and-content) describes. The image's listeners already accept agents on every interface, so the listener change of [step 5](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#5-start-the-manager-open-it-to-the-fleet-and-verify-the-registry) of the manager guide is not needed.

5. **Enroll the local agent again**, now that the import holds the 4.x IDs. Mint a token for it the way the first boot does and start it; it takes the next free ID:

    ```bash
    sudo sh -c 'umask 077; /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address 127.0.0.1 --embed-ca --max-uses 1 > /var/ossec/etc/enrollment_token'
    sudo systemctl start wazuh-agent
    ```

    From here `check` reports this agent as one that was not in the bundle and exits with `1`: it is the only expected problem.

6. **Cut over.** Give the 5.0 VM the address the agents dial: for the OVA, move the 4.x VM to another IP and assign its IP to the 5.0 VM; for the AMI, reassign the Elastic IP or update the DNS name. Otherwise edit the address on every agent, as [step 6](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#6-reconnect-the-4x-agents) of the manager guide describes. The 4.x agents reconnect over the legacy channel with their 4.x IDs and keys. Then reissue the manager's certificates for the new address, as [AMI](modules/configurer/post/ami/post-ami.md#certificate-lifecycle-after-first-boot) or [OVA](modules/configurer/post/ova/post-ova.md#certificate-lifecycle-after-first-boot) post-configurer describes: 5.0 agents verify it against the manager's certificate, and the manager refuses to mint enrollment tokens for an address the certificate does not carry.

7. **Historical data.** The 4.x alerts stay in the 4.x VM's indexer, and its dashboard keeps serving them with the 4.x manager stopped. Keep that VM for as long as you need to consult them, or move them into the 5.0 indexer as [Historical data](#historical-data) describes.

Continue with [step 7](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#7-upgrade-the-agents-to-50) of the manager guide to upgrade the agents to 5.0.

## Same VM

The 4.x AMI and OVA run Amazon Linux 2023 from 4.11 onwards, which 5.0 supports, so the 4.x packages can be replaced on the same VM. Images up to 4.10 run Amazon Linux 2, where this path does not apply: use the [new VM](#new-vm) path. Check it before starting, since step 3 cannot be undone:

```bash
grep PRETTY_NAME /etc/os-release
```

Expected: `PRETTY_NAME="Amazon Linux 2023..."`. This path keeps the VM's address, so the agents need no change, at these costs:

- **Downtime.** The manager is down from the export until the agent listeners are reopened. The agents buffer their events and retry meanwhile.
- **No rollback.** Once 4.x is removed, going back means reinstalling it and restoring your own backups. Take a hypervisor snapshot of the OVA, or an AMI or EBS snapshot of the instance, before starting.
- **The 4.x alerts survive only through a snapshot** of the 4.x indices, taken while 4.x is still running, to a folder that is not removed with 4.x.

Run every step on the 4.x VM:

1. **Snapshot the 4.x indices**, with 4.x still running, as step 1 of [Historical data](#historical-data) describes. On this path it is the only copy of the 4.x alerts: the indexer data is removed in step 3.

2. **Back up and export the 4.x manager** as in [step 1](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#1-back-up-the-4x-manager) of the manager guide, to folders outside `/var/ossec`. The export keeps `ossec.conf`, `local_internal_options.conf` and `api.yaml` in the bundle's `reference/` folder, but not your rules, decoders and CDB lists, the group files it reports as not migrated, the indexer and dashboard configuration, or the rest of `/var/ossec`: the logs and archives under `/var/ossec/logs`, your own integrations, active response scripts and SCA policies. Save them too, since step 3 removes them.

    ```bash
    sudo systemctl stop wazuh-manager
    sudo python3 wazuh-migrate-identity.py export --with-rbac /root/wazuh-4x-bundle
    sudo mkdir -p /root/wazuh-4x-backup
    sudo tar -czf /root/wazuh-4x-backup/ruleset.tar.gz -C /var/ossec/etc rules decoders lists
    sudo tar -czf /root/wazuh-4x-backup/shared.tar.gz -C /var/ossec/etc shared
    sudo tar -czf /root/wazuh-4x-backup/ossec.tar.gz -C /var ossec
    sudo cp /etc/wazuh-indexer/opensearch.yml /root/wazuh-4x-backup/opensearch-4x.yml
    sudo cp /etc/wazuh-dashboard/opensearch_dashboards.yml /root/wazuh-4x-backup/opensearch_dashboards-4x.yml
    sudo cp /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml /root/wazuh-4x-backup/wazuh-4x.yml
    ```

    `ossec.tar.gz` holds all of `/var/ossec`, including the 4.x logs: it can be large.

3. **Remove 4.x and what its packages leave behind.** Take the dashboard backup of [Before you start](#before-you-start) first: this step removes the 4.x dashboard. `dnf remove` keeps the 4.x indexer data and configuration, the dashboard configuration and `/var/ossec`. A 5.0 indexer installed over them starts on the 4.x cluster and serves its indices, which is an in-place upgrade of the indexer, so remove them too. Remove Filebeat as well: 5.0 does not use it, and it is a package of its own that removing the manager does not take with it ([Remove Filebeat](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/filebeat-to-indexer-connector.md#6-remove-filebeat)):

    ```bash
    sudo systemctl stop wazuh-dashboard wazuh-indexer filebeat
    sudo dnf remove -y wazuh-dashboard wazuh-manager wazuh-indexer filebeat
    sudo rm -rf /var/lib/wazuh-indexer /etc/wazuh-indexer /etc/wazuh-dashboard /var/ossec /etc/filebeat /var/log/filebeat
    ```

4. **Install the 5.0 packages** following the installation assistant's [All in one](https://github.com/wazuh/wazuh-installation-assistant/blob/v5.0.0/docs/guide/step-by-step-deployments/all-in-one.md) step-by-step guide, which adds the Wazuh repository, installs the indexer, keeps it on `127.0.0.1` and sets its heap to a quarter of the RAM as the 5.0 image does, runs `indexer-security-init.sh` and installs the manager and the dashboard. Two changes:
    - Install the manager with the agent listeners on loopback ([Install it out of the fleet's reach](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#install-it-out-of-the-fleets-reach)): this VM keeps the address the agents dial.

        ```bash
        sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='127.0.0.1' WAZUH_REMOTE_LEGACY_ENABLED='no' dnf install -y wazuh-manager
        sudo systemctl start wazuh-manager
        ```

    - Disable the 4.x heap service, which would set the indexer heap back to half the RAM on every boot:

        ```bash
        sudo systemctl disable updateIndexerHeap.service
        ```

5. **Import the identity and open the manager to the fleet** ([steps 3 and 5](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#3-restore-the-identity-data) of the manager guide). This VM has no pre-installed agent, so no ID is taken:

    ```bash
    sudo /var/wazuh-manager/framework/python/bin/python3 wazuh-migrate-identity.py import --with-rbac /root/wazuh-4x-bundle
    ```

    Migrate the configuration as [Configuration and content](#configuration-and-content) describes, and set `<remote><https><bind_addr>` back to `0.0.0.0` and `<remote><legacy><enabled>` back to `yes` in `/etc/wazuh-manager/wazuh-manager.conf` ([step 5](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#5-start-the-manager-open-it-to-the-fleet-and-verify-the-registry)). Then validate it, and enable and restart the manager:

    ```bash
    sudo /var/wazuh-manager/bin/wazuh-manager-conf validate
    sudo systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard
    sudo systemctl restart wazuh-manager
    ```

    Restore the published API passwords as described in [Before you start](#before-you-start), then restart the dashboard and compare the manager with the bundle:

    ```bash
    sudo systemctl restart wazuh-dashboard
    sudo /var/wazuh-manager/framework/python/bin/python3 wazuh-migrate-identity.py check /root/wazuh-4x-bundle
    ```

    The agents reconnect on their own: the address did not change.

6. **Restore the 4.x indices** into the 5.0 indexer, as step 2 of [Historical data](#historical-data) describes.

7. **Install an agent on the VM.** 5.0 has no agent `000`, so nothing monitors the server host until an agent runs on it ([Monitoring the server host](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/ref/getting-started/installation.md#monitoring-the-server-host)). The 5.0 image ships one, enrolled with a token on the first boot; do the same here, from the Wazuh repository added in step 4:

    ```bash
    sudo dnf install -y wazuh-agent
    sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address 127.0.0.1 --embed-ca --max-uses 1 \
        | sudo /var/ossec/bin/wazuh-agent-auth
    sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
    ```

    The token goes through the pipe, so it never appears on a command line. The agent takes the host name and the next free ID after the migrated agents.

Continue with [step 7](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#7-upgrade-the-agents-to-50) of the manager guide to upgrade the agents to 5.0.

### What differs from a 5.0 image

The VM keeps the 4.x image around the 5.0 packages:

| | 5.0 AMI or OVA | 4.x AMI or OVA with the 5.0 packages |
|---|---|---|
| Indexer address | `127.0.0.1:9200` | `127.0.0.1:9200`, set by the all-in-one guide in step 4 |
| Indexer heap | A quarter of the RAM, set on the first boot | A quarter of the RAM, set by the all-in-one guide in step 4, once the 4.x heap service is disabled |
| Agent on the server host | Pre-installed and enrolled on the first boot | Installed and enrolled by hand in step 7 |
| Certificates and credentials | Issued per VM on the first boot | Issued by the packages at installation, for the VM's addresses |
| Services | Enabled by the image | Enabled by hand in step 5 |
| Hostname, login banner and boot screen | The 5.0 image's | The 4.x image's |

## Configuration and content

5.0 does not read any 4.x configuration file. Each one is rewritten on the 5.0 file, as [step 4](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#4-migrate-the-configuration) of the manager guide says: do not copy the 4.x files over the 5.0 ones. On the same VM, read them from the backup taken in step 2 once 4.x is removed: `ossec.conf`, `local_internal_options.conf` and `api.yaml` in `/root/wazuh-4x-bundle/reference/`, and the rules, decoders, lists, group files, the rest of `/var/ossec` and the 4.x `opensearch.yml`, `opensearch_dashboards.yml` and `wazuh.yml` in `/root/wazuh-4x-backup/`.

| 4.x file on the image | 5.0 destination |
|---|---|
| `/var/ossec/etc/ossec.conf`, `local_internal_options.conf` | `/etc/wazuh-manager/wazuh-manager.conf` and `/etc/wazuh-manager/wazuh-manager-internal-options.conf`, rewritten as [Manager configuration migration](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-configuration-migration.md) says |
| `/var/ossec/etc/rules`, `decoders`, `lists` | Rewritten as detection rules, engine decoders and KVDBs: [rules](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/rules-4x-to-5x.md), [decoders](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/xml-decoders-migration.md), [CDB lists](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/cdb-to-kvdb-migration.md) |
| `/var/ossec/etc/shared/<group>/` | Carried by `wazuh-migrate-identity.py`. Each `agent.conf` must be valid for 5.0 |
| `/var/ossec/api/configuration/api.yaml` | `/var/wazuh-manager/api/configuration/api.yaml`, as the [`api.yaml`](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-configuration-migration.md#apiyaml) section of the same guide says |
| `/etc/wazuh-indexer/opensearch.yml` | Not reused: it names the 4.x certificates. Keep the 5.0 file and set only your own settings in it |
| `/etc/wazuh-dashboard/opensearch_dashboards.yml` | Not reused. Keep the 5.0 file and set only your own settings in it |
| `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` | `/etc/wazuh-dashboard/opensearch_dashboards.yml` and the dashboard's Advanced settings, as its [Configuration migration](https://github.com/wazuh/wazuh-dashboard-plugins/blob/v5.0.0/docs/guide/migration/configuration.md) says. Keep the manager connection the image or the installation wrote |

Keep the settings the image or the installation wrote to the 5.0 files: in `wazuh-manager.conf`, the indexer address (`https://127.0.0.1:9200`) and the agent listeners; in `opensearch.yml`, `network.host: "127.0.0.1"`. Validate the manager configuration before restarting the manager:

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-conf validate
```

## Historical data

The 5.0 indexer does not read the 4.x indices. On the new VM path they stay in the 4.x VM, whose indexer and dashboard keep serving them. To consult them from 5.0, on either path, take a snapshot of them while 4.x is still running and restore it into the 5.0 indexer.

1. **On the 4.x VM**, while its indexer still runs (on the same VM path, before step 3 removes it), add `path.repo` to the indexer configuration and take the snapshot to a folder outside the indexer's data path, with the 4.x `admin` password:

    ```bash
    sudo install -d -o wazuh-indexer -g wazuh-indexer /var/backups/wazuh-4x-snapshots
    echo 'path.repo: ["/var/backups/wazuh-4x-snapshots"]' | sudo tee -a /etc/wazuh-indexer/opensearch.yml
    sudo systemctl restart wazuh-indexer
    until curl -sk -u admin:<4.x admin password> "https://127.0.0.1:9200/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do sleep 5; done
    curl -sk -u admin:<4.x admin password> -X PUT "https://127.0.0.1:9200/_snapshot/wazuh-4x" \
        -H 'Content-Type: application/json' \
        -d '{"type": "fs", "settings": {"location": "/var/backups/wazuh-4x-snapshots"}}'
    curl -sk -u admin:<4.x admin password> -X PUT "https://127.0.0.1:9200/_snapshot/wazuh-4x/4x?wait_for_completion=true" \
        -H 'Content-Type: application/json' \
        -d '{"indices": "wazuh-alerts-4.x-*,wazuh-archives-4.x-*,wazuh-states-*", "include_global_state": false}'
    ```

    Expected: `"state":"SUCCESS"` and `"failed":0`. On the new VM path, copy `/var/backups/wazuh-4x-snapshots` to `/var/lib/wazuh-indexer/backup/wazuh-4x` on the 5.0 VM, owned by `wazuh-indexer`.

2. **On the 5.0 VM**, once the migration is done, register the snapshot read-only and restore it under another name, so the 4.x indices do not mix with the 5.0 ones. The 5.0 indexer already ships `path.repo: ["/var/lib/wazuh-indexer/backup"]`: do not add another `path.repo` line, or the indexer does not start (`Duplicate field 'path.repo'`), and no restart is needed. On the same VM path, first move the snapshot under that directory:

    ```bash
    sudo mv /var/backups/wazuh-4x-snapshots /var/lib/wazuh-indexer/backup/wazuh-4x
    sudo chown -R wazuh-indexer:wazuh-indexer /var/lib/wazuh-indexer/backup/wazuh-4x
    ```

    Then, with the 5.0 `admin` password from `/etc/wazuh-indexer/export/credentials.env`:

    ```bash
    curl -sk -u admin:<admin password> -X PUT "https://127.0.0.1:9200/_snapshot/wazuh-4x" \
        -H 'Content-Type: application/json' \
        -d '{"type": "fs", "settings": {"location": "/var/lib/wazuh-indexer/backup/wazuh-4x", "readonly": true}}'
    curl -sk -u admin:<admin password> -X POST "https://127.0.0.1:9200/_snapshot/wazuh-4x/4x/_restore?wait_for_completion=true" \
        -H 'Content-Type: application/json' \
        -d '{"indices": "wazuh-alerts-4.x-*,wazuh-archives-4.x-*,wazuh-states-*", "include_global_state": false, "rename_pattern": "(.+)", "rename_replacement": "restored-$1"}'
    ```

    The 4.x alerts are then in `restored-wazuh-alerts-4.x-*`, and the archives, if the 4.x indexer had them, in `restored-wazuh-archives-4.x-*`, and the restored indices stay in the 5.0 indexer. 5.0 does not read them: consult them with an index pattern of their own, as [Historical data](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md#historical-data) in the manager guide describes.
