# Test AMI

The AMI testing type provides specialized tools and configuration for validating AWS AMIs that contain Wazuh components.

## Features

- Launch and test new instances from an AMI
- Test existing EC2 instances via direct SSH or using Ansible inventory files
- Support for various authentication methods
- Execute several test of Wazuh components.

## Requirements

For AMI testing, you'll need:

- AWS access with permissions to:
  - Describe AMIs
  - Launch and terminate EC2 instances
  - Describe EC2 instances
  - Create and delete EC2 key pairs
- SSH key for connecting to instances

## AMI-Specific Parameters

When running tests on an AMI, you can use these specific parameters:

| Parameter | Description |
|-----------|-------------|
| `--ami-id` | ID of the AMI to validate by launching a new EC2 instance |
| `--instance-type` | EC2 instance type (default: t3.medium) |
| `--security-group-ids` | Security group IDs for the launched instance |
| `--no-terminate` | Do not terminate the instance after tests |
| `--aws-region` | AWS region where the AMI is located |
| `--aws-role` | AWS role to assume (choices: qa, dev, default) |
| `--instance-profile` | IAM instance profile to attach to the instance |

## Usage

### Command Line Interface

```bash
# Test a new instance launched from an AMI
wazuh-vm-test --test-type ami --ami-id ami-12345 --ssh-key-path ~/.ssh/my-key.pem --version 5.0.0

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

## AMI Tests

The AMI testing module runs the [core tests](../test.md#core-test-types) which include:

- **test_certificates**: Validates SSL/TLS certificates for security and proper setup
- **test_connectivity**: Ensures proper network connectivity between components
- **test_services**: Verifies that all services are running correctly
- **test_logs**: Analyzes logs to detect errors or anomalies
- **test_version**: Validates that the installed versions match expectations

No additional tests beyond the core tests are implemented specifically for AMI testing.

## AMI Testing Strategy

The AMI testing strategy follows these steps:

1. **Instance Initialization**:
   - If an AMI ID is provided, a new EC2 instance is launched from that AMI
   - If an SSH host is provided, a direct connection to that host is established

2. **Test Execution**:
   - Runs all specified tests against the target instance
   - Collects and analyzes results

3. **Reporting**:
   - Generates detailed reports in the specified format
   - Includes pass/fail status for each test

4. **Cleanup**:
   - If a new instance was launched, it is terminated
   - Temporary resources are cleaned up

## AWS Integration

The AMI testing module integrates with AWS services through:

1. **EC2 Client**: Manages instance lifecycle and status
2. **Credentials Management**: Securely handles AWS authentication

## Configuration

The AMI testing module uses the [core configuration system](../test.md#core-configuration) defined in `config.py`. For AMI-specific testing, the configuration is managed through the `AMITesterConfig` class which extends the base configuration:

```python
class AMITesterConfig(BaseTesterConfig):
    """Main configuration for the AMI tester."""

    # AMI option
    ami_id: Optional[str] = None

    # AWS instance options
    instance_type: str = "t3.medium"
```

This AMI-specific configuration provides:
- AMI identification settings
- AWS instance type configuration
- Validation of required connection parameters

Key configuration aspects for AMI testing include:
- AWS connection details (region, instance type, security groups)
- SSH authentication settings
- Test patterns to execute
- Expected versions of Wazuh components
- Timeout and retry settings

The configuration inherits all the core validation parameters for Wazuh services, certificates, and connectivity testing, while adding AMI-specific options.

## Connection Handling

The AMI testing module supports multiple connection methods:

- **Direct SSH**: Connect directly to an instance with key or password
- **EC2 Instance**: Launch a new instance from an AMI
- **Ansible Inventory**: Use existing Ansible inventory for testing
- **Local Testing**: Test on the local machine

Each connection method provides the same interface for executing commands and transferring files, allowing the tests to run consistently regardless of the connection type.
