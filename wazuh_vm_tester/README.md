# Wazuh VM Tester

A modular and extensible framework for automated validation of Wazuh virtual machines. This tool allows you to validate that Wazuh components are correctly installed and functioning in a VM or AWS AMI by verifying services, certificates, logs, connectivity, and versions.

## Features

- Automated validation of Wazuh VMs with extensive tests
- Verification of services running correctly
- Validation of SSL/TLS certificates
- Analysis of logs to detect errors
- Testing connectivity between different components
- Verification of installed versions and revisions
- Detailed test reports
- GitHub Actions integration
- Support for testing VMs in multiple ways:
  - Launch a new instance from an AMI
  - Test an existing EC2 instance
  - Direct SSH to a host
  - Using Ansible inventory files
  - Local testing on the current machine

## Requirements

- Python 3.8+
- AWS access (for AMI testing) with permissions to:
  - Describe AMIs
  - Launch and terminate EC2 instances
  - Describe EC2 instances
  - Create and delete EC2 key pairs
- SSH key for connecting to instances (unless testing locally)

## Installation

### From the repository

```bash
git clone https://github.com/your-organization/wazuh-vm-tester.git
cd wazuh-vm-tester
pip install -e .
```

## Usage

### Command Line Interface

The tool provides a CLI for running tests:

```bash
# Test a new instance launched from an AMI
wazuh-vm-test --ami-id ami-12345 --ssh-key-path ~/.ssh/my-key.pem --version 5.0.0

# Test an existing instance via direct SSH
wazuh-vm-test --ssh-host 1.2.3.4 --ssh-username wazuh-user --ssh-key-path ~/.ssh/my-key.pem

# Test using an Ansible inventory
wazuh-vm-test --inventory /path/to/inventory.yml --host wazuh-server

# Test on the local machine
wazuh-vm-test --use-local

# Specify output format
wazuh-vm-test --ami-id ami-12345 --output json --output-file results.json

# Specify which tests to run ex: servies
wazuh-vm-test --ssh-host 1.2.3.4 --test-pattern "services"

# ex: logs and certificates
wazuh-vm-test --ssh-host 1.2.3.4 --test-pattern "logs certificates"

# Verbose output
wazuh-vm-test --ami-id ami-12345 --ssh-key-path ~/.ssh/my-key.pem  --log-level DEBUG
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
│       │   └── ec2.py           # EC2 client
│       ├── connections/         # Connection handling
│       │   ├── __init__.py
│       │   ├── base.py          # Connection interface
│       │   ├── ssh.py           # SSH connection
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
│       │   └── formatters.py    # Report formatters
│       ├── strategies/          # Connection strategies
│       │   ├── __init__.py
│       │   ├── base.py          # Strategy interface
│       │   ├── ami.py           # AMI testing strategy
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
│       │   └── test_version.py     # Version tests
│       └── utils/               # Utility modules
│           ├── __init__.py
│           └── inventory.py     # Ansible inventory utilities
└── examples/                    # Usage examples
    └── simple_test.py           # Simple test example
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

### Log Analysis
- Searches for errors in service logs
- Detects known error patterns
- Filters false positives

### Connectivity Tests
- Verifies connectivity between Wazuh components
- Tests Wazuh API connectivity

### Version Verification
- Verifies that the installed version of each component matches the expected version

## Configuration

The test framework is highly configurable through the `config.py` file. Configuration includes:

- Service definitions with ports, processes, required files, etc.
- Certificate validation settings
- Connectivity test definitions
- Log analysis patterns

Example of the configuration structure:

```python
# Define service configuration
services = [
    WazuhServiceConfig(
        name="wazuh-server",
        port=[1514, 55000],  # Can define multiple ports
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
                url="https://localhost:55000/security/user/authenticate",
                auth={"username": "admin", "password": "admin"},
                headers={"Content-Type": "application/json"},
                expected_status=[200]
            )
        ],
        health_endpoints=[
            EndpointConfig(
                url="https://localhost:9200/_cluster/health?pretty",
                auth={"username": "admin", "password": "admin"},
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

