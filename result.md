# Wazuh VM Test Results

## Summary

**Status**: FAIL :red_circle:

| Metric | Count |
|--------|-------|
| Total Tests | 23 |
| Passed | 2 |
| Failed | 15|
| Warnings | 0 |
| Skipped | 6 |

## Failed Tests :red_circle:

### Certificates

**Certificates: Certificates exist** :red_circle:

Error: 

```
  - Certificate: /etc/wazuh-indexer/certs/root-ca.pem does NOT exist
  - Certificate: /etc/wazuh-indexer/certs/indexer-1.pem does NOT exist
  - Certificate: /etc/wazuh-indexer/certs/admin.pem does NOT exist
  - Certificate: /etc/wazuh-dashboard/certs/root-ca.pem does NOT exist
  - Certificate: /etc/wazuh-dashboard/certs/dashboard.pem does NOT exist
  - Certificate: /etc/wazuh-server/certs/server-1.pem does NOT exist
  - Certificate: /etc/wazuh-server/certs/root-ca.pem does NOT exist
  - Certificate: /etc/wazuh-server/certs/admin.pem does NOT exist
  - Certificate: /etc/wazuh-server/certs/root-ca-merged.pem does NOT exist
```

### Connectivity

**Connectivity: Wazuh api connectivity** :red_circle:

Error: 

```
  - Endpoint: https://localhost:55000/?pretty=true (attempting to get token from https://localhost:55000/security/user/authenticate?raw=true) - failed to obtain token:  - attempting access - access failed: 
```

### Logs

**Logs: Log files exist** :red_circle:

Error: 

```
  - Log file: /var/log/wazuh-indexer/wazuh-cluster.log (for wazuh-indexer) does NOT exist
```

### Ova

**Ova: 1** :red_circle:

Error: 

```
assert (1 == 0)
```

**Ova: 2** :red_circle:

Error: 

```
assert (1 == 0)
```

**Ova: 3** :red_circle:

Error: 

```
assert (1 == 0)
```

**Ova: 4** :red_circle:

Error: 

```
assert (1 == 0)
```

### Services

**Services: Services active** :red_circle:

Error: 

```
  - Service: wazuh-server is NOT active. Output: inactive
  - Service: wazuh-indexer is NOT active. Output: inactive
  - Service: wazuh-dashboard is NOT active. Output: inactive
```

**Services: Services running** :red_circle:

Error: 

```
  - Service: wazuh-server is NOT running. Status: 
  - Service: wazuh-indexer is NOT running. Status: 
  - Service: wazuh-dashboard is NOT running. Status: 
```

**Services: Required directories** :red_circle:

Error: 

```
  - Directory: /etc/wazuh-server (for wazuh-server) does NOT exist
  - Directory: /usr/share/wazuh-server (for wazuh-server) does NOT exist
  - Directory: /usr/share/wazuh-server/bin (for wazuh-server) does NOT exist
  - Directory: /etc/wazuh-indexer (for wazuh-indexer) does NOT exist
  - Directory: /etc/wazuh-dashboard (for wazuh-dashboard) does NOT exist
```

**Services: Required files** :red_circle:

Error: 

```
  - File: /etc/wazuh-server/wazuh-server.yml (for wazuh-server) does NOT exist
```

**Services: Ports listening** :red_circle:

Error: 

```
  - Port: 27000 (for wazuh-server) is NOT listening
  - Port: 55000 (for wazuh-server) is NOT listening
  - Port: 9200 (for wazuh-indexer) is NOT listening
  - Port: 443 (for wazuh-dashboard) is NOT listening
```

**Services: Health endpoints** :red_circle:

Error: 

```
  - Endpoint: https://localhost:9200/_cluster/health?pretty (for wazuh-indexer) failed with status 000 (expected: 200). Error: 
  - Endpoint: https://localhost/status (for wazuh-dashboard) failed with status 000 (expected: 200). Error: 
```

### Version

**Version: Services versions** :red_circle:

Error: 

```
  - Command: /usr/share/wazuh-server/bin/wazuh-server-management-apid -v failed with error: sudo: /usr/share/wazuh-server/bin/wazuh-server-management-apid: command not found
  - Command: cat /usr/share/wazuh-server/VERSION.json failed with error: cat: /usr/share/wazuh-server/VERSION.json: No such file or directory
  - Command: rpm -q wazuh-indexer 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null failed with error: 
  - Command: cat /usr/share/wazuh-indexer/VERSION.json failed with error: cat: /usr/share/wazuh-indexer/VERSION.json: No such file or directory
  - Command: rpm -q wazuh-dashboard 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null failed with error: 
  - Command: cat /usr/share/wazuh-dashboard/VERSION.json failed with error: cat: /usr/share/wazuh-dashboard/VERSION.json: No such file or directory
```

**Version: Services revisions** :red_circle:

Error: 

```
  - Command: rpm -q wazuh-server --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-server 2>/dev/null | cut -d '-' -f2 found revision: package wazuh-server is not installed (does NOT match expected: 1)
  - Command: rpm -q wazuh-indexer --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null | cut -d '-' -f2 found revision: package wazuh-indexer is not installed (does NOT match expected: 2)
  - Command: rpm -q wazuh-dashboard --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null | cut -d '-' -f2 found revision: package wazuh-dashboard is not installed (does NOT match expected: 1)
```


## Passed Tests 

### Connectivity

- Connectivity: Service connectivity :green_circle:

### Ova

- Ova: Ova virtualbox specific :green_circle:


## Skipped Tests :large_blue_circle:

### Certificates

**Certificates: Certificates validity** :large_blue_circle:

Reason: 

```
('/home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_certificates.py', 142, 'Skipped: Some certificates were skipped. Certificate validity check results:\n\nSkipped certificates:\n- Certificate: /etc/wazuh-indexer/certs/root-ca.pem does not exist - skipping validity check\n- Certificate: /etc/wazuh-indexer/certs/indexer-1.pem does not exist - skipping validity check\n- Certificate: /etc/wazuh-indexer/certs/admin.pem does not exist - skipping validity check\n- Certificate: /etc/wazuh-dashboard/certs/root-ca.pem does not exist - skipping validity check\n- Certificate: /etc/wazuh-dashboard/certs/dashboard.pem does not exist - skipping validity check\n- Certificate: /etc/wazuh-server/certs/server-1.pem does not exist - skipping validity check\n- Certificate: /etc/wazuh-server/certs/root-ca.pem does not exist - skipping validity check\n- Certificate: /etc/wazuh-server/certs/admin.pem does not exist - skipping validity check\n- Certificate: /etc/wazuh-server/certs/root-ca-merged.pem does not exist - skipping validity check')
```

**Certificates: Certificate subjects** :large_blue_circle:

Reason: 

```
('/home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_certificates.py', 212, 'Skipped: Some certificates were skipped. Certificate subject check results:\n\nSkipped certificates:\n- Certificate: /etc/wazuh-indexer/certs/root-ca.pem (expected subject pattern: OU=Wazuh) - certificate does not exist, skipping subject check\n- Certificate: /etc/wazuh-indexer/certs/indexer-1.pem (expected subject pattern: CN=wazuh_indexer) - certificate does not exist, skipping subject check\n- Certificate: /etc/wazuh-indexer/certs/admin.pem (expected subject pattern: CN=admin) - certificate does not exist, skipping subject check\n- Certificate: /etc/wazuh-dashboard/certs/root-ca.pem (expected subject pattern: OU=Wazuh) - certificate does not exist, skipping subject check\n- Certificate: /etc/wazuh-dashboard/certs/dashboard.pem (expected subject pattern: CN=wazuh_dashboard) - certificate does not exist, skipping subject check\n- Certificate: /etc/wazuh-server/certs/server-1.pem (expected subject pattern: CN=wazuh_server) - certificate does not exist, skipping subject check\n- Certificate: /etc/wazuh-server/certs/root-ca.pem (expected subject pattern: OU=Wazuh) - certificate does not exist, skipping subject check\n- Certificate: /etc/wazuh-server/certs/admin.pem (expected subject pattern: CN=admin) - certificate does not exist, skipping subject check\n- Certificate: /etc/wazuh-server/certs/root-ca-merged.pem (expected subject pattern: OU=Wazuh) - certificate does not exist, skipping subject check')
```

**Certificates: Certificate issuers** :large_blue_circle:

Reason: 

```
('/home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_certificates.py', 283, 'Skipped: Some certificates were skipped. Certificate issuer check results:\n\nSkipped certificates:\n- Certificate: /etc/wazuh-indexer/certs/root-ca.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check\n- Certificate: /etc/wazuh-indexer/certs/indexer-1.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check\n- Certificate: /etc/wazuh-indexer/certs/admin.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check\n- Certificate: /etc/wazuh-dashboard/certs/root-ca.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check\n- Certificate: /etc/wazuh-dashboard/certs/dashboard.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check\n- Certificate: /etc/wazuh-server/certs/server-1.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check\n- Certificate: /etc/wazuh-server/certs/root-ca.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check\n- Certificate: /etc/wazuh-server/certs/admin.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check\n- Certificate: /etc/wazuh-server/certs/root-ca-merged.pem (expected issuer pattern: OU=Wazuh) - certificate does not exist, skipping issuer check')
```

**Certificates: Certificate permissions** :large_blue_circle:

Reason: 

```
('/home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_certificates.py', 347, 'Skipped: Some certificates were skipped. Certificate permissions check results:\n\nSkipped certificates:\n- Certificate: /etc/wazuh-indexer/certs/root-ca.pem (expected permissions: 256) - certificate file not found\n- Certificate: /etc/wazuh-indexer/certs/indexer-1.pem (expected permissions: 256) - certificate file not found\n- Certificate: /etc/wazuh-indexer/certs/admin.pem (expected permissions: 256) - certificate file not found\n- Certificate: /etc/wazuh-dashboard/certs/root-ca.pem (expected permissions: 256) - certificate file not found\n- Certificate: /etc/wazuh-dashboard/certs/dashboard.pem (expected permissions: 256) - certificate file not found\n- Certificate: /etc/wazuh-server/certs/server-1.pem (expected permissions: 256) - certificate file not found\n- Certificate: /etc/wazuh-server/certs/root-ca.pem (expected permissions: 256) - certificate file not found\n- Certificate: /etc/wazuh-server/certs/admin.pem (expected permissions: 256) - certificate file not found\n- Certificate: /etc/wazuh-server/certs/root-ca-merged.pem (expected permissions: 256) - certificate file not found')
```

### Logs

**Logs: Logs for errors** :large_blue_circle:

Reason: 

```
('/home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_logs.py', 172, 'Skipped: Some log files were skipped. \n\nResults:\n\nClean logs (no errors):\n- Log command: journalctl -u wazuh-server -n 100 (for wazuh-server) contains no errors\n- Log command: journalctl -u wazuh-dashboard -n 100 (for wazuh-dashboard) contains no errors\n\nSkipped logs:\n- Log file: /var/log/wazuh-indexer/wazuh-cluster.log (for wazuh-indexer) does not exist - skipping error check')
```

**Logs: Recent logs** :large_blue_circle:

Reason: 

```
('/home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_logs.py', 310, "Skipped: Some log files were skipped. \n\nResults:\n\nClean recent logs (no errors):\n- Recent log command: journalctl --since '24 hours ago' -u wazuh-server -n 100 (for wazuh-server) contains no recent errors\n- Recent log command: journalctl --since '24 hours ago' -u wazuh-dashboard -n 100 (for wazuh-dashboard) contains no recent errors\n\nSkipped logs:\n- Recent log file: /var/log/wazuh-indexer/wazuh-cluster.log (for wazuh-indexer) does not exist - skipping recent error check")
```

