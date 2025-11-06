# Wazuh VM Tester

A modular and extensible framework for automated validation of Wazuh virtual machines. This tool allows you to validate that Wazuh components are correctly installed and functioning in a VM, OVA, or AWS AMI by verifying services, certificates, logs, connectivity, and versions.

## Features

- Automated validation of Wazuh VMs with extensive tests
- Support for multiple test types:
  - AWS AMI testing
  - OVA image testing
  - Direct SSH testing
- Verification of services running correctly
- Validation of SSL/TLS certificates
- Analysis of logs to detect errors
- Testing connectivity between different components
- Verification of installed versions and revisions
- Detailed test reports in multiple formats (console, JSON, Markdown, GitHub Actions)
- GitHub Actions integration
- Support for testing VMs in multiple ways:
  - Launch a new instance from an AMI
  - Import an OVA file into a VirtualBox VM
  - Test an existing EC2 instance
  - Direct SSH to a host (with key or password authentication)
  - Using Ansible inventory files
  - Local testing on the current machine

## Requirements

- Python 3.8+
- For AMI testing:
  - AWS access with permissions to:
    - Describe AMIs
    - Launch and terminate EC2 instances
    - Describe EC2 instances
    - Create and delete EC2 key pairs
  - SSH key for connecting to instances
- For OVA testing:
  - AWS access (if using allocator)
  - VirtualBox (automatically installed on the allocator instance)
  - OVA file accessible in S3
- For SSH testing:
  - SSH key or password for the target host
- For local testing:
  - Wazuh installation on the local machine

## Installation

### From the repository

```bash
git clone https://github.com/wazuh/wazuh-virtual-machines.git
cd wazuh-vm-tester
pip install -e .
```

## Usage

### Command Line Interface

The tool provides a CLI for running tests:

```bash
# Test a new instance launched from an AMI
wazuh-vm-test --test-type ami --ami-id ami-12345 --ssh-key-path ~/.ssh/my-key.pem --version 5.0.0

# Test an OVA file by importing it into VirtualBox on an allocator instance
wazuh-vm-test --test-type ova --ova-s3-path s3://bucket-name/path/to/wazuh.ova --vm-memory 4096 --vm-cpus 2

# Test an existing instance via direct SSH with key authentication
wazuh-vm-test --test-type ami --ssh-host 1.2.3.4 --ssh-username wazuh-user --ssh-key-path ~/.ssh/my-key.pem

# Test an existing instance via direct SSH with password authentication
wazuh-vm-test --test-type ami --ssh-host 1.2.3.4 --ssh-username wazuh-user --ssh-password your-password

# Test using an Ansible inventory
wazuh-vm-test --test-type ami --inventory /path/to/inventory.yml --host wazuh-server

# Test on the local machine
wazuh-vm-test --test-type ami --use-local

# Specify output format
wazuh-vm-test --test-type ami --ami-id ami-12345 --output json --output-file results.json

# Specify AWS region
wazuh-vm-test --test-type ami --ami-id ami-12345 --aws-region us-west-2

# Specify specific tests to run (e.g., only services tests)
wazuh-vm-test --test-type ami --ssh-host 1.2.3.4 --test-pattern "services*"

# Specify multiple test types
wazuh-vm-test --test-type ami --ssh-host 1.2.3.4 --test-pattern "services* logs*"

# Verbose output for debugging
wazuh-vm-test --test-type ami --ami-id ami-12345 --ssh-key-path ~/.ssh/my-key.pem --log-level DEBUG
```

### Using Pytest Directly

You can also run the tests using pytest directly:

```bash
# Run tests on a remote host via SSH
pytest -v --ssh-host=1.2.3.4 --ssh-username=wazuh-user --ssh-key=~/.ssh/my-key.pem

# Run tests on the local machine
pytest -v --use-local

# Run specific test modules
pytest -v --use-local -k "services"

# Run tests with expected version
pytest -v --use-local --expected-version=5.0.0
```

## Test Types and Their Specific Tests

The framework supports different test types, each with specific test patterns that run by default:

### AMI Testing (test_type=ami)

Tests for AMI include:
- test_certificates
- test_connectivity
- test_services
- test_logs
- test_version

### OVA Testing (test_type=ova)

Tests for OVA include all AMI tests plus OVA-specific tests:
- test_certificates
- test_connectivity
- test_services
- test_logs
- test_version
- test_ova (OVA-specific tests like boot files, FIPS, banner, etc.)

You can customize which tests run using the `--test-pattern` parameter.

## Connection Types

### SSH Connection with Password Authentication

The framework supports SSH connections using password authentication. This is particularly useful when key-based authentication is not available.

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

### OVA Port Forwarding

For OVA testing, the framework sets up port forwarding between the allocator instance and the imported OVA VM:

1. The allocator instance is launched on AWS
2. VirtualBox is installed on the allocator instance
3. The OVA file is downloaded from S3 and imported into VirtualBox
4. Port forwarding is set up to access the OVA VM:
   - SSH (guest port 22 → host port 2201)
   - Any additional ports specified in configuration

This allows the framework to connect to the OVA VM through the allocator instance using the forwarded ports.

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
│       │   ├── __init__.py
│       │   ├── ec2.py           # EC2 client
│       │   └── credentials.py   # AWS credentials management
│       ├── connections/         # Connection handling
│       │   ├── __init__.py
│       │   ├── base.py          # Connection interface
│       │   ├── ssh.py           # SSH connection (key & password auth)
│       │   ├── local.py         # Local connection
│       │   ├── ansible.py       # Ansible-based connection
│       │   └── pytest_connector.py # Pytest connections
│       ├── instances/           # Instance management
│       │   ├── __init__.py
│       │   ├── base.py          # Instance interface
│       │   ├── ec2_instance.py  # EC2 instance
│       │   ├── local_instance.py # Local instance
│       │   └── factory.py       # Instance factory
│       ├── reporting/           # Reporting modules
│       │   ├── __init__.py
│       │   ├── base.py          # Report base classes
│       │   ├── manager.py       # Report manager
│       │   ├── collectors.py    # Test result collectors
│       │   └── formatters.py    # Report formatters (JSON, Markdown, Console, GitHub)
│       ├── strategies/          # Connection strategies
│       │   ├── __init__.py
│       │   ├── base.py          # Strategy interface
│       │   ├── ami.py           # AMI testing strategy
│       │   ├── ova.py           # OVA testing strategy
│       │   ├── ssh.py           # SSH testing strategy
│       │   ├── local.py         # Local testing strategy
│       │   ├── ansible.py       # Ansible testing strategy
│       │   └── factory.py       # Strategy factory
│       ├── tests/               # Test modules
│       │   ├── __init__.py
│       │   ├── test_connectivity.py # Connectivity tests
│       │   ├── test_services.py    # Service tests
│       │   ├── test_certificates.py # Certificate tests
│       │   ├── test_logs.py        # Log tests
│       │   ├── test_version.py     # Version tests
│       │   └── test_ova.py         # OVA-specific tests
│       └── utils/               # Utility modules
│           ├── __init__.py
│           ├── logger.py         # Logging utilities
│           └── utils.py          # General utilities
```

## Implemented Tests

### Service Validation
- Verifies that all Wazuh services are running:
  - wazuh-server
  - wazuh-indexer
  - wazuh-dashboard
- Verifies that service ports are listening
- Verifies that required directories and files exist

### Certificate Validation
- Verifies that certificates exist
- Verifies that certificates are valid and not expired
- Verifies that certificate subjects and issuers are correct
- Checks certificate permissions

### Log Analysis
- Searches for errors in service logs
- Detects known error patterns
- Filters false positives
- Checks for recent errors (last 24 hours)

### Connectivity Tests
- Verifies connectivity between Wazuh components
- Tests Wazuh API connectivity and authentication

### Version Verification
- Verifies that the installed version of each component matches the expected version
- Validates revisions match the expected values

### OVA-Specific Tests
- Validates boot files presence and configuration
- Verifies FIPS compliance
- Checks for Wazuh branding (banner)
- Validates residual installation files
- Tests DNS resolution

## Configuration

The test framework is highly configurable through the `config.py` file. Configuration includes:

- Test type definitions (AMI, OVA)
- Service definitions with ports, processes, required files, etc.
- Certificate validation settings
- Connectivity test definitions
- Log analysis patterns
- AWS settings (region, instance types, security groups)
- OVA settings (memory, CPUs, port forwarding)

Example of the configuration structure:

```python
# Define service configuration
services = [
    WazuhServiceConfig(
        name="wazuh-server",
        version="5.0.0",
        revision="latest",
        port=[27000, 55000],
        process_name="wazuh-server",
        log_files=[],
        log_commands=["journalctl -u wazuh-server -n 100"],
        required_dirs=["/etc/wazuh-server", "/usr/share/wazuh-server"],
        required_files=["/etc/wazuh-server/wazuh-server.yml"],
        version_commands=[
            CommandConfig(
                command="/usr/share/wazuh-server/bin/wazuh-server-management-apid -v",
                expected_regex=r"Wazuh ([\d.]+)"
            )
        ],
        api_endpoints=[
            EndpointConfig(
                token="https://localhost:55000/security/user/authenticate?raw=true",
                url="https://localhost:55000/?pretty=true",
                auth={"username": "wazuh", "password": "wazuh"},
                headers={"Content-Type": "application/json"},
                expected_status=[200]
            )
        ]
    ),
    # Other services...
]
```

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

## License

WAZUH

Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
