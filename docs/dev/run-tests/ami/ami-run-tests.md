# Run AMI Tests

There are two types of tests designed to ensure the AMI works as expected:

## Unit Tests

These are standard unit tests that verify the internal logic of the code related to the AMI, ensuring it behaves correctly and without errors.

You can run the unit tests for the AMI using **Hatch** or directly from the **command line**:

- **Using Hatch**

  ```bash
  hatch run dev-ami-configurer:test-cov
  ```

- **Using the Command Line**

  ```bash
  FORCE_COLOR=1 pytest -n 4 \
    --cov=configurer/ami \
    --cov-report term-missing:skip-covered \
    tests/test_configurer/test_ami \
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

Integration tests validate the correct behavior of the AMI itself by building the artifact and running a full test cycle against both supported architectures.

### Manual Trigger

Trigger AMI integration tests by commenting on the PR:

| Command | Triggers |
|---------|----------|
| `/test-integration` | OVA + AMI tests |
| `/test-ami` | AMI only (both architectures) |

### What it does

1. **Build AMI**
   - Builds **amd64** and **arm64** AMIs simultaneously
   - Creates EC2 instances (Amazon Linux 2023)
   - Installs Wazuh packages (dev)
   - Creates AMI snapshots
   - Tags AMIs with PR number, linked issue URL, and workflow run link
   - Cleans up build instances

2. **Test AMI**
   - Launches a `c5ad.xlarge` instance for amd64
   - Launches a `c6g.xlarge` instance for arm64
   - Runs integration tests on both:
     - Certificates validation
     - Service status checks
     - Version verification
     - Connectivity tests
     - Log validation
   - Posts results as a PR comment
   - Terminates test instances

### Architecture Support

| Architecture | Instance Type | Base AMI |
|--------------|---------------|----------|
| amd64 (x86_64) | c5ad.xlarge | Amazon Linux 2023 x86_64 |
| arm64 (aarch64) | c6g.xlarge | Amazon Linux 2023 ARM64 |

### Resources

| Resource | Cleanup |
|----------|---------|
| AMIs (amd64 + arm64) | ✅ Auto-deregistered |
| EBS snapshots | ✅ Auto-deleted |
| EC2 instances (2 build + 2 test) | ✅ Auto-terminated |
| SSH keys | ✅ Auto-removed |

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
