# Pull Request Checks Documentation

This document describes the automated PR validation system for the Wazuh Virtual Machines repository.

## Overview

The PR check system automatically validates code changes through three types of tests:
1. **Unit Tests** - Fast validation of code quality and test coverage
2. **OVA Integration Tests** - Full build and test cycle for OVA artifacts
3. **AMI Integration Tests** - Full build and test cycle for AMI artifacts (amd64 + arm64)

## Available PR Checks

### 1. Unit Tests (`check_unit_test.yaml`)

**Purpose**: Validates code quality, runs unit tests, and reports coverage

**Triggers**:
- ✅ PR marked as "ready for review"
- ✅ New commits pushed to non-draft PR
- ✅ Changes in: `configurer/`, `generic/`, `provisioner/`, `models/`, `utils/`, `tests/`

**Duration**: ~1-2 minutes

**What it does**:
1. Sets up Python 3.12 environment
2. Installs hatch and dependencies
3. Runs `hatch run dev:test-cov`
4. Parses test results and coverage
5. Posts comment on PR with results
6. Creates GitHub summary

**Output Example**:
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

**Check Status**:
- ✅ **Pass**: All tests passed
- ❌ **Fail**: One or more tests failed

---

### 2. OVA Integration Tests (`check_integration_ova.yaml`)

**Purpose**: Builds and tests a complete OVA artifact

**Triggers** (via comment):
- `/test-integration` - Runs both OVA and AMI tests
- `/test-ova` - Runs only OVA test

**What it does**:
1. **Build OVA**
   - Creates EC2 metal instance on AWS
   - Installs VirtualBox and dependencies
   - Builds OVA with latest Wazuh packages (dev)
   - Uploads OVA to S3
   - Cleans up build instance

2. **Test OVA**
   - Downloads OVA from S3
   - Imports into VirtualBox on test instance
   - Runs comprehensive integration tests:
     - ✓ Certificates validation
     - ✓ Service status checks
     - ✓ Version verification
     - ✓ Connectivity tests
     - ✓ Log validation
   - Posts test results as PR comment
   - Terminates test resources

**Resources Created**:
- EC2 metal instance (temporary)
- VirtualBox VM (temporary)
- OVA file in S3 (`development/wazuh/5.x/secondary/ova/`)

**Cleanup**:
- EC2 instances: ✅ Auto-terminated
- VMs: ✅ Auto-deleted
- OVA files: ⚠️ Remain in S3 (manual cleanup if needed)

**Result**:
The test results will be displayed in:
- PR Check
- Action Summary
- A single comment in the PR (which will be edited if we have new test runs) with the test summary
---

### 3. AMI Integration Tests (`check_integration_ami.yaml`)

**Purpose**: Builds and tests AMI artifacts for both architectures

**Manual Triggers** (via comment):
- `/test-integration` - Runs both OVA and AMI tests
- `/test-ami` - Runs only AMI test

**What it does**:

1. **Get PR Info**
   - Extracts PR metadata
   - Finds linked issue (if any)

2. **Build AMI**
   - Builds **amd64** and **arm64** AMIs simultaneously
   - Creates EC2 instances (Amazon Linux 2023)
   - Installs Wazuh packages (dev)
   - Creates AMI snapshots
   - Tags AMIs with:
     - PR number (`pr-check-{NUMBER}`)
     - Linked issue URL
     - Workflow run link
   - Cleans up build instances

3. **Test AMI**
   - **amd64 test**: Launches `c5ad.xlarge` instance
   - **arm64 test**: Launches `c6g.xlarge` instance
   - Runs integration tests on both:
     - ✓ Certificates validation
     - ✓ Service status checks
     - ✓ Version verification
     - ✓ Connectivity tests
     - ✓ Log validation
   - Posts results as PR comment
   - Terminates test instances

4. **Cleanup**
   - Deregisters both AMIs
   - Deletes EBS snapshots
   - Removes SSH keys

**Resources Created**:
- 2 AMIs (amd64 + arm64) - temporary
- 4 EC2 instances (2 build + 2 test) - temporary
- EBS snapshots - temporary

**Cleanup**:
- AMIs: ✅ Auto-deregistered after tests
- EBS Snapshots: ✅ Auto-deleted
- EC2 instances: ✅ Auto-terminated
- SSH keys: ✅ Auto-removed

**Architecture Support**:
| Architecture | Instance Type | Base AMI |
|--------------|---------------|----------|
| amd64 (x86_64) | c5ad.xlarge | Amazon Linux 2023 x86_64 |
| arm64 (aarch64) | c6g.xlarge | Amazon Linux 2023 ARM64 |

**Result**:
The test results will be displayed in:
- PR Check
- Action Summary
- A single comment in the PR (which will be edited if we have new test runs) with the test summary

---

## How to Use PR Checks

### Automatic Execution

PR checks run automatically when (Only for unit test):
1. You mark a PR as "ready for review" (from draft)
2. You push new commits to a non-draft PR
3. Your changes affect relevant paths (see each check's triggers)

**Example Workflow**:
```bash
# 1. Create feature branch
git checkout -b feature/my-changes

# 2. Make changes to code
vim configurer/ami/main.py

# 3. Commit and push
git add .
git commit -m "Add new feature"
git push origin feature/my-changes

# 4. Create PR (as draft initially)
gh pr create --draft

# 5. When ready, mark as ready for review
gh pr ready

# ✨ PR checks automatically start!
```

### Manual Execution via Comments

You can manually trigger integration tests by commenting on your PR (Only for integration test):

| Command | Triggers |
|---------|----------|
| `/test-integration` | OVA + AMI (both architectures) |
| `/test-ova` | OVA only |
| `/test-ami` | AMI only (both architectures) |

**Example**:
1. Go to your PR page
2. Add a comment: `/test-integration`
3. Wait a few seconds
4. Checks will appear in the "Checks" tab

**When to use manual triggers**:
- 🔄 Re-run tests after infrastructure changes (not code changes)
- 🐛 Debug test failures
- ✅ Verify fixes without pushing new commits
- 🎯 Run specific tests (OVA vs AMI) to save time/cost

---

## Understanding Check Results

### Unit Tests Results

**PR Comment Format**:
```markdown
## 🧪 Unit Tests Results

✅/❌ Status

### Summary
- Result: X failed, Y passed in Z.XXs
- Coverage: XX%
- Workflow: [Link]

### 📊 Coverage Details
[Coverage table]

### ❌ Failed Tests (if any)
[List of failed tests]
```

**What to look for**:
- ✅ All tests passed + high coverage (>95%) = Good to merge
- ❌ Failed tests = Review failures, fix code
- ⚠️ Decreased coverage = Add tests for new code

### Integration Tests Results

**PR Comment Format**:
```markdown
## Wazuh VM Test Results

✅/❌/⚠️ Status

Test Summary:
- Passed: X
- Failed: Y
- Warnings: Z
- Skipped: N

[Detailed test results table]
```

**Status Meanings**:
- ✅ **PASS**: All tests passed
- ⚠️ **WARNING**: Tests passed but with warnings
- ❌ **FAIL**: One or more tests failed

**Common Test Categories**:
- **CERTIFICATES**: SSL/TLS certificate validation
- **CONNECTIVITY**: Network and service connectivity
- **LOGS**: Log file validation and parsing
- **SERVICE**: Systemd service status checks
- **VERSION**: Component version verification
- **UPDATES**: Update mechanism validation

---

## Troubleshooting

### Unit Tests Failed

**Symptom**: ❌ Unit test check failed

**Steps**:
1. Click "View Details" in PR comment
2. Review failed test names
3. Run tests locally:
   ```bash
   hatch run dev:test-cov
   ```
4. Fix failing tests
5. Push changes (checks auto-rerun)

### Integration Tests Failed

**Symptom**: ❌ OVA or AMI test check failed

**Steps**:
1. Click workflow link in PR comment
2. Expand failed test step
3. Review test output for specific failures
4. Common issues:
   - **Service not running**: Check service startup in configurer code
   - **Version mismatch**: Update VERSION.json or version detection logic
   - **Certificate error**: Check certificate generation in configurer
   - **Connectivity failed**: Review network configuration changes

---

## Best Practices

### 1. Run Unit Tests Locally First
```bash
# Before pushing:
hatch run dev:test-cov

# Ensure all tests pass and coverage is high
```

### 2. Use Draft PRs for WIP
```bash
# Create as draft while developing
gh pr create --draft

# Mark ready when done
gh pr ready
```
This prevents triggering expensive integration tests prematurely.

### 3. Monitor Resource Usage

Integration tests consume AWS resources:
- **OVA test**: ~1-2 metal instance hours
- **AMI test**: ~2-4 instance hours

💡 Use manual triggers (`/test-{type}`) to avoid unnecessary reruns.

### 4. Fix Tests Promptly

Failed tests block merging:
- Unit tests = quick feedback, fix immediately
- Integration tests = expensive, investigate thoroughly

### 5. Review Test Output

Don't just check ✅/❌:
- Read warning messages
- Check coverage changes
- Review new test scenarios

---

## Check Configuration

### Build Parameters

**Development Builds** (PR checks):
```yaml
wazuh_package_type: dev
is_stage: false
destroy: true          # Clean up resources
wazuh_automation_reference: main
```

**Production Builds** (releases):
```yaml
wazuh_package_type: prod
is_stage: true
destroy: true         # Keep artifacts
```

---

## Workflow Files Reference

| Workflow | File | Purpose |
|----------|------|---------|
| Unit Tests | `check_unit_test.yaml` | Run hatch tests |
| OVA Tests | `check_integration_ova.yaml` | Build + test OVA |
| AMI Tests | `check_integration_ami.yaml` | Build + test AMI |
| OVA Builder | `builder_OVA.yaml` | OVA build logic |
| AMI Builder | `packages_builder_ami.yaml` | AMI build logic |
| Test Runner | `test-vm.yaml` | Integration test execution |

---

## Support

**Documentation**:
- Technical implementation: `PR_CHECKS_IMPLEMENTATION.md`
- Workflow source: `.github/workflows/check_*.yaml`
- Test module: `wazuh-automation/integration-test-module/`

---
