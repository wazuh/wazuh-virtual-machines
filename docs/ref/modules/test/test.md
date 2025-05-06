# Test module

The `Test` module provides a modular and extensible framework for automated validation of Wazuh virtual machines repository. This tool allows to validate that Wazuh components are correctly installed and functioning in a VM, OVA, or AWS AMI by verifying services, certificates, logs, connectivity, and versions. Tests can be executed against different deployment types, with specific test suites tailored to each environment. And a detailed test reports is generated in multiple formats types.

## Features

- Automated validation of Wazuh components with extensive tests
- Support for multiple test types:
  - AWS AMI testing
  - OVA image testing
  - Direct SSH testing
- Detailed test reports in multiple formats (console, JSON, Markdown, GitHub Actions)

## Requirements

- Python 3.8+
- Specific requirements depending on the test type:
  - For AMI testing: AWS access with specific permissions
  - For OVA testing: AWS access (if using allocator), VirtualBox
  - For SSH testing: SSH key or password for the target host
  - For local testing: Wazuh installation on the local machine

## Installation

### From the repository

```bash
git clone https://github.com/wazuh/wazuh-virtual-machines.git
cd wazuh-vm-tester
pip install -e .
```

## Usage

The tool provides a comprehensive CLI for running tests with various parameters:

```bash
wazuh-vm-test --test-type TYPE [CONNECTION PARAMETERS] [TEST OPTIONS]
```

### Common Parameters

| Parameter | Description |
|-----------|-------------|
| `--test-type` | Type of test to run (`ami`, `ova`) |
| `--version` | Expected Wazuh version |
| `--revision` | Expected revision |
| `--output` | Output format (`json`, `markdown`, `console`, `github`) |
| `--output-file` | File where to save the results |
| `--log-level` | Set logging level (`DEBUG`, `INFO`, `TRACE`) |
| `--test-pattern` | Test pattern to run (e.g. 'services*' or 'test_connectivity.py') |
| `--pytest-args` | Additional arguments to pass to pytest |

### Connection Methods

At least one of these connection methods must be specified:

| Parameter | Description |
|-----------|-------------|
| `--ami-id` | ID of the AMI to validate by launching a new EC2 instance |
| `--ova-s3-path` | S3 path to the OVA file to import and test |
| `--inventory` | Path to Ansible inventory file to use for connection details |
| `--ssh-host` | SSH host to connect to (direct SSH mode) |
| `--use-local` | Use local machine for testing |

### SSH Connection Options

| Parameter | Description |
|-----------|-------------|
| `--ssh-username` | SSH username (default: wazuh-user) |
| `--ssh-key-path` | Path to the SSH private key |
| `--ssh-password` | Password for SSH connection |
| `--ssh-port` | SSH port (default: 22) |

### Ansible Inventory Options

| Parameter | Description |
|-----------|-------------|
| `--host` | Host ID in the Ansible inventory to use |

### AWS Options

| Parameter | Description |
|-----------|-------------|
| `--aws-region` | AWS region (default: us-east-1) |
| `--instance-type` | EC2 instance type (default: c5ad.xlarge) |
| `--subnet-id` | ID of the subnet where to launch the instance |
| `--instance-profile` | IAM instance profile name |
| `--no-terminate` | Do not terminate the instance after tests |
| `--security-group-ids` | Security group IDs (overrides default security groups) |
| `--aws-role` | AWS role to assume (choices: qa, dev, default) |

### OVA Options

| Parameter | Description |
|-----------|-------------|
| `--allocator-instance-type` | EC2 instance type for the allocator |
| `--vm-memory` | Memory to allocate to the VM in MB (default: 4096) |
| `--vm-cpus` | Number of CPUs to allocate to the VM (default: 2) |
| `--import-only` | Only import the OVA, don't run tests |
| `--vm-username` | VM username (default: wazuh-user) |
| `--vm-password` | VM password (default: wazuh) |

### Example

```bash
# Test with verbose output for debugging
wazuh-vm-test --test-type ami --ami-id ami-12345 --ssh-key-path ~/.ssh/my-key.pem --log-level DEBUG
```

### Using Pytest Directly

You can also run the tests using pytest directly:

```bash
# Run tests on a remote host via SSH
pytest -v --ssh-host=1.2.3.4 --ssh-username=wazuh-user --ssh-key=~/.ssh/my-key.pem
```

## Core Test Types

The framework includes the following core tests that run for all test types:

### Service Validation

**Service tests** verify the proper functioning of Wazuh services:

- Verifies that all Wazuh services are running (wazuh-server, wazuh-indexer, wazuh-dashboard)
- Verifies that service ports are listening
- Verifies that required directories and files exist
- Tests health endpoints for each service

### Certificate Validation

**Certificate tests** ensure the security and integrity of SSL/TLS certificates:

- Verifies that certificates exist in the expected locations
- Validates that certificates are not expired
- Checks that certificate subjects and issuers match expected values
- Verifies certificate permissions

### Log Analysis

**Log tests** identify potential issues by analyzing log files:

- Searches for errors in service logs
- Detects known error patterns
- Filters false positives
- Checks for recent errors (last 24 hours)

### Connectivity Tests

**Connectivity tests** verify proper communication between components:

- Verifies connectivity between Wazuh components
- Tests Wazuh API connectivity and authentication
- Validates network configuration

### Version Verification

**Version tests** ensure correct software versions are installed:

- Verifies that the installed version of each component matches the expected version
- Validates revisions match the expected values

## Test Types and Their Specific Tests

The framework supports different test types, each with specific test patterns:

- **AMI Testing** - See [Test AMI](ami/ami.md) for detailed information
- **OVA Testing** - See [Test OVA](ova/ova.md) for detailed information

## Connection Types

### SSH Connection with Password Authentication

The framework supports SSH connections using password authentication, particularly useful when key-based authentication is not available.

The SSH connection is implemented using a multi-threaded approach for better handling of timeouts and command execution:

```
┌────────────────────┐      ┌─────────────────┐
│  Main Thread       │      │  SSH process    │
│                    │      │                 │
│ -Process begins    │─────▶│  - Execute the  │
│ -Coordinate threads│      │    command      │
│ -Return            │◀─────│    on the remote│
│    results         │      │    server       │
└─────────┬──────────┘      └────────┬────────┘
          │                          │
          │                          │
┌─────────▼──────────┐      ┌────────▼────────┐
│ Timeout Thread     │      │ Reader Threads  │
│                    │      │                 │
│ - Watch time       │      │ - stdout_thread │
│ - Terminate process│      │ - stderr_thread │
│   if exceeded      │      │ - Capture all   │
│   the limit        │      │    the exit     │
└────────────────────┘      └─────────────────┘
```

This approach provides:
- Reliable command execution
- Better timeout handling
- Concurrent collection of stdout and stderr
- Graceful termination of long-running commands

## Project Structure

```
wazuh-vm-tester/
├── pyproject.toml               # Project configuration
├── README.md                    # Main documentation
├── src/                         # Source code
│   └── vm_tester/               # Main package
│       ├── __init__.py          # Package initialization
│       ├── cli.py               # Command-line interface
│       ├── config.py            # Tester configuration
│       ├── conftest.py          # Pytest fixtures
│       ├── aws/                 # AWS modules
│       ├── connections/         # Connection handling
│       ├── instances/           # Instance management
│       ├── reporting/           # Reporting modules
│       ├── strategies/          # Connection strategies
│       ├── tests/               # Test modules
│       └── utils/               # Utility modules
```

## Core Configuration

The test framework uses a centralized configuration system in `config.py` that handles all test types through Pydantic models. This provides strong typing, validation, and default values for all configuration parameters.

### Configuration Model Hierarchy

The main configuration classes form a hierarchy:

- `BaseTesterConfig`: Core configuration shared by all test types
- `AMITesterConfig`: Extends base config with AMI-specific settings
- `OVATesterConfig`: Extends base config with OVA-specific settings

### Component Configuration Models

The framework uses specialized configuration models for different test components:

```python
class EndpointConfig(BaseModel):
    """Configuration for API/health endpoints."""
    url: str
    token: Optional[str] = None
    method: str = "GET"
    auth: Optional[Dict[str, str]] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    expected_status: List[int] = Field(default_factory=lambda: [200])
    expected_content: Optional[str] = None


class CommandConfig(BaseModel):
    """Configuration for commands to execute."""
    command: str
    expected_output: Optional[str] = None
    expected_regex: Optional[str] = None
    expected_status: int = 0


class WazuhServiceConfig(BaseModel):
    """Configuration for validating a Wazuh service."""
    name: str
    version: Optional[str] = None
    revision: Optional[str] = None
    port: Optional[Union[int, List[Union[int, str]]]] = None
    process_name: Optional[str] = None
    log_files: List[str] = []
    log_commands: List[str] = []
    required_dirs: List[str] = []
    required_files: List[str] = []
    version_commands: List[CommandConfig] = Field(default_factory=list)
    revision_commands: List[CommandConfig] = Field(default_factory=list)
    health_endpoints: List[EndpointConfig] = Field(default_factory=list)
    api_endpoints: List[EndpointConfig] = Field(default_factory=list)


class WazuhCertificateConfig(BaseModel):
    """Configuration for validating Wazuh certificates."""
    path: str
    subject_match: Optional[str] = None
    issuer_match: Optional[str] = None
    days_valid: int = 90
    permissions: Optional[int] = None


class ConnectivityTestConfig(BaseModel):
    """Configuration for connectivity tests between services."""
    source: str
    target: str
    host: str
    port: int
```

These models define all the validation parameters for:

- Wazuh services (server, indexer, dashboard)
- Commands to run and expected outputs/exit codes
- API and health endpoints to test
- Certificate validation requirements
- Connectivity tests between components

### Default Configuration Provider

The configuration system includes utility functions that provide default configurations:

- `get_default_wazuh_services()`: Default service configurations
- `get_default_wazuh_certificates()`: Default certificate validation rules
- `get_default_connectivity_tests()`: Default connectivity tests
- `get_default_log_error_patterns()`: Default log error patterns to check
- `get_default_log_false_positives()`: Default patterns to ignore in logs

This design makes it easy to:
- Add new test types
- Extend existing test configurations
- Validate configuration parameters
- Provide sensible defaults
- Override specific settings when needed

Test-specific configurations for AMI and OVA testing are detailed in their respective sections:


## Extending the Framework

The framework is designed to be extended with new tests:

1. Create a new test file in the `tests` directory
2. Define your test class with pytest markers
3. Implement test methods

Example of a new test:

```python
@pytest.mark.custom_test
class TestCustomFeature:
    """Tests for a custom feature."""

    def test_custom_functionality(self, config: AMITesterConfig):
        """Test some custom functionality."""
        connection = get_connection()

        # Run your test
        exit_code, stdout, stderr = connection.execute_command("your-command")

        # Assert results
        assert exit_code == 0, f"Command failed: {stderr}"
```

## Reporting

The test framework can generate detailed reports in multiple formats, including console output, JSON, Markdown, and GitHub Actions format. These reports provide a comprehensive overview of the test results, including pass/fail status, error messages, and summary statistics.

### Example Markdown Report

Below is an example of a Markdown report generated by the test framework:

```markdown
# Wazuh VM Test Results

## Summary

**Status**: FAIL :red_circle:

| Metric | Count |
|--------|-------|
| Total Tests | 17 |
| Passed | 15 |
| Failed | 2|
| Warnings | 0 |
| Skipped | 0 |

## Failed Tests :red_circle:

### Version

**Version: Services versions** :red_circle:

Error:

```
  - Command: /usr/share/wazuh-server/bin/wazuh-server-management-apid -v found version: 5.0.0 (matches expected: 5.0.0)
  - Command: cat /usr/share/wazuh-server/VERSION.json found version: 5.0.0 (matches expected: 5.0.0)
  - Command: rpm -q wazuh-dashboard 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null found version: 5.0.0 (matches expected: 5.0.0)
  - Command: cat /usr/share/wazuh-dashboard/VERSION.json found version: 5.0.0 (matches expected: 5.0.0)
  - Command: rpm -q wazuh-indexer 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null found version: 5.0.0 (does NOT match expected: 2.19.1)
  - Command: cat /usr/share/wazuh-indexer/VERSION.json found version: 5.0.0 (does NOT match expected: 2.19.1)
```

**Version: Services revisions** :red_circle:

Error:

```
  - Command: rpm -q wazuh-server --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-server 2>/dev/null | cut -d '-' -f2 found revision: latest (does NOT match expected: 1)
  - Command: rpm -q wazuh-indexer --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null | cut -d '-' -f2 found revision: latest (does NOT match expected: 2)
  - Command: rpm -q wazuh-dashboard --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null | cut -d '-' -f2 found revision: latest (does NOT match expected: 1)
```


## Passed Tests

### Certificates

- Certificates: Certificates exist :green_circle:

- Certificates: Certificates validity :green_circle:

- Certificates: Certificate subjects :green_circle:

- Certificates: Certificate issuers :green_circle:

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
```

This report format provides:

- A summary of all test results
- Detailed error information for failed tests
- Grouping of tests by category (Certificates, Connectivity, Logs, Services, Version)
- Visual indicators of test status (green circles for pass, red circles for fail)

### Available Report Formats

The test framework supports multiple output formats:

- **Console**: Colorized terminal output with detailed test information
- **JSON**: Machine-readable format suitable for automated processing
- **Markdown**: Formatted report as shown above
- **GitHub**: Special format for GitHub Actions integration with workflow commands

Reports can be saved to a file using the `--output-file` command-line option, with the format determined by the `--output` option or the file extension.


## License

WAZUH

Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
