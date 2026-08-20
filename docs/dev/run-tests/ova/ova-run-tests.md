# Run OVA Tests

There are two types of tests designed to ensure the OVA works as expected:

## Unit Tests

These are standard unit tests that verify the internal logic of the code related to the OVA, ensuring it behaves correctly and without errors.

You can run the unit tests for the OVA using **Hatch** or directly from the **command line**. There are two Hatch environments: PreConfigurer and PostConfigurer. You can run the tests for each one of the environments:

### 1. PreConfigurer

- Using Hatch

  ```bash
  hatch run dev-ova-pre-configurer:test-cov
  ```

- Using the Command Line

  ```bash
  FORCE_COLOR=1 pytest -n 4 \
    --cov=configurer/ova/ova_pre_configurer \
    --cov-report term-missing:skip-covered \
    tests/test_configurer/test_ova/test_ova_pre_configurer \
    --cov-report=xml
  ```

### 2. PostConfigurer

- Using Hatch

  ```bash
  hatch run dev-ova-post-configurer:test-cov
  ```

- Using the Command Line

  ```bash
  FORCE_COLOR=1 pytest -n 4 \
    --cov=configurer/ova/ova_post_configurer \
    --cov-report term-missing:skip-covered \
    tests/test_configurer/test_ova/test_ova_post_configurer \
    --cov-report=xml
  ```

## PR Checks

Unit tests also run automatically as part of the PR validation process.

### Automatic Execution

Unit tests run automatically when:
- A PR is marked as "ready for review" (from draft)
- New commits are pushed to a non-draft PR

### Check Results

Results are posted as a PR comment and in the GitHub Actions summary:

```
## 🧪 Unit Tests Results

✅ All tests passed!

### Summary
- Result: 358 passed in 1.60s
- Coverage: 99%
- Workflow: [View Details](...)

### 📊 Coverage Details
Name                                                    Stmts   Miss  Cover
---------------------------------------------------------------------------
configurer/ami/ami_post_configurer.py                    177      1    99%
...
TOTAL                                                   1697     13    99%
```

- ✅ **Pass**: All tests passed
- ❌ **Fail**: One or more tests failed

### Troubleshooting

If the unit test check fails:
1. Click "View Details" in the PR comment
2. Review the failed test names
3. Run tests locally and fix the failures
4. Push changes — checks will rerun automatically

## Integration Tests

Integration tests validate the correct behavior of the OVA itself by building the artifact and running a full test cycle against it.

### Manual Trigger

Trigger OVA integration tests by commenting on the PR:

| Command | Triggers |
|---------|----------|
| `/test-integration` | OVA + AMI tests |
| `/test-ova` | OVA only |

### What it does

1. **Build OVA**
   - Creates an EC2 metal instance on AWS
   - Installs VirtualBox and dependencies
   - Builds the OVA with the latest Wazuh packages (dev)
   - Uploads the OVA to S3
   - Cleans up the build instance

2. **Test OVA**
   - Downloads the OVA from S3
   - Imports it into VirtualBox on a test instance
   - Runs integration tests:
     - Certificates validation
     - Service status checks
     - Version verification
     - Connectivity tests
     - Log validation
   - Posts test results as a PR comment
   - Terminates test resources

### Resources

| Resource | Cleanup |
|----------|---------|
| EC2 metal instance | ✅ Auto-terminated |
| VirtualBox VM | ✅ Auto-deleted |
| OVA file in S3 (`development/wazuh/5.x/secondary/ova/`) | ⚠️ Manual cleanup if needed |

### Check Results

Results are posted as a PR comment, in the GitHub Actions summary, and in the PR Checks tab. The comment is edited in place on subsequent runs.

```
## Wazuh VM Test Results

✅/❌/⚠️ Status

Test Summary:
- Passed: X
- Failed: Y
- Warnings: Z
- Skipped: N

[Detailed test results table]
```

- ✅ **PASS**: All tests passed
- ⚠️ **WARNING**: Tests passed with warnings
- ❌ **FAIL**: One or more tests failed

### Troubleshooting

If an integration test fails:
1. Click the workflow link in the PR comment
2. Expand the failed test step and review the output
3. Common causes:
   - **Service not running**: Check service startup in configurer code
   - **Version mismatch**: Update `VERSION.json` or version detection logic
   - **Certificate error**: Check certificate generation in configurer
   - **Connectivity failed**: Review network configuration changes
