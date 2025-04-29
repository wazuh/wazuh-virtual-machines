# Wazuh VM Test Results

## Summary

**Status**: FAIL :red_circle:

| Metric | Count |
|--------|-------|
| Total Tests | 14 |
| Passed | 13 |
| Failed | 1|
| Warnings | 0 |
| Skipped | 0 |

## Failed Tests :red_circle:

### Certificates

**Certificates: Certificate permissions** :red_circle:

Error: 

```
  - Certificate: /etc/wazuh-indexer/certs/root-ca.pem (expected permissions: 400) - actual permissions: 744 - NO MATCH
  - Certificate: /etc/wazuh-indexer/certs/indexer-1.pem (expected permissions: 400) - actual permissions: 744 - NO MATCH
  - Certificate: /etc/wazuh-indexer/certs/admin.pem (expected permissions: 400) - actual permissions: 744 - NO MATCH
  - Certificate: /etc/wazuh-dashboard/certs/root-ca.pem (expected permissions: 400) - actual permissions: 744 - NO MATCH
  - Certificate: /etc/wazuh-dashboard/certs/dashboard.pem (expected permissions: 400) - actual permissions: 744 - NO MATCH
  - Certificate: /etc/wazuh-server/certs/server-1.pem (expected permissions: 400) - actual permissions: 744 - NO MATCH
  - Certificate: /etc/wazuh-server/certs/root-ca.pem (expected permissions: 400) - actual permissions: 744 - NO MATCH
  - Certificate: /etc/wazuh-server/certs/admin.pem (expected permissions: 400) - actual permissions: 744 - NO MATCH
  - Certificate: /etc/wazuh-server/certs/root-ca-merged.pem (expected permissions: 400) - actual permissions: 644 - NO MATCH
```


## Passed Tests 

### Connectivity

- Connectivity: Service connectivity :green_circle:

- Connectivity: Wazuh api connectivity :green_circle:

### Logs

- Logs: Log files exist :green_circle:

- Logs: Logs for errors :green_circle:

- Logs: Recent logs :green_circle:

### Services

- Services: Services active :green_circle:

- Services: Services running :green_circle:

- Services: Required directories :green_circle:

- Services: Required files :green_circle:

- Services: Ports listening :green_circle:

- Services: Health endpoints :green_circle:

### Version

- Version: Services versions :green_circle:

- Version: Services revisions :green_circle:

