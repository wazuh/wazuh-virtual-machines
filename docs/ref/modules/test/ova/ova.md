# Test OVA

The OVA testing type provides specialized tools and configuration for validating OVA (Open Virtual Appliance) files that contain Wazuh components.

## Features

- Import and test OVA files in VirtualBox on an allocator instance
- Comprehensive verification of Wazuh components in the OVA
- OVA-specific tests beyond the standard core tests

## Requirements

For OVA testing, you'll need:

- AWS access (if using allocator)
- VirtualBox (automatically installed on the allocator instance)
- OVA file accessible in S3

## OVA-Specific Parameters

When running tests on an OVA, you can use these specific parameters:

| Parameter | Description |
|-----------|-------------|
| `--ova-s3-path` | S3 path to the OVA file to import and test |
| `--allocator-instance-type` | EC2 instance type for the allocator (default: c5.metal) |
| `--vm-memory` | Memory to allocate to the VM in MB (default: 4096) |
| `--vm-cpus` | Number of CPUs to allocate to the VM (default: 2) |
| `--import-only` | Only import the OVA, don't run tests |
| `--vm-username` | VM username (default: wazuh-user) |
| `--vm-password` | VM password (default: wazuh) |

## Usage

### Command Line Interface

```bash
# Test an OVA file by importing it into VirtualBox on an allocator instance
wazuh-vm-test --test-type ova --ova-s3-path s3://bucket-name/path/to/wazuh.ova --vm-memory 4096 --vm-cpus 2

# Specify output format
wazuh-vm-test --test-type ova --ova-s3-path s3://bucket-name/path/to/wazuh.ova --output json --output-file results.json

# Specify AWS region for the allocator instance
wazuh-vm-test --test-type ova --ova-s3-path s3://bucket-name/path/to/wazuh.ova --aws-region us-west-2

# Specify specific tests to run
wazuh-vm-test --test-type ova --ova-s3-path s3://bucket-name/path/to/wazuh.ova --test-pattern "ova* services*"

# Verbose output for debugging
wazuh-vm-test --test-type ova --ova-s3-path s3://bucket-name/path/to/wazuh.ova --log-level DEBUG
```

## OVA Tests

The OVA testing module runs all [core tests](../test.md#core-test-types) and adds the following OVA-specific tests:

### Boot Files Validation

Verifies the presence and integrity of boot files essential for proper OVA startup:
- `/boot/grub2/wazuh.png`
- `/boot/grub2/grub.cfg`
- `/etc/default/grub`

### FIPS Compliance Verification

Checks if FIPS (Federal Information Processing Standards) mode is correctly enabled:
- Verifies the existence of `/proc/sys/crypto/fips_enabled`
- Confirms that FIPS mode is properly set to "1" (enabled)

### Wazuh Banner Validation

Ensures the correct implementation of the Wazuh banner for login screens:
- Verifies that `/usr/lib/motd.d/40-wazuh-banner` exists
- Confirms it's the only banner file in its directory

### Residual Files Verification

Checks for required installation residual files:
- `/etc/systemd/system/wazuh-starter.service`
- `/usr/local/bin/wazuh-starter.sh`
- `/etc/systemd/system/wazuh-starter.timer`

### DNS Resolution Testing

Verifies that DNS resolution is working correctly:
- Checks the existence of `/etc/resolv.conf`
- Tests connectivity to external domains

## OVA Port Forwarding

For OVA testing, the framework sets up port forwarding between the allocator instance and the imported OVA VM:

1. The allocator instance is launched on AWS
2. VirtualBox is installed on the allocator instance
3. The OVA file is downloaded from S3 and imported into VirtualBox
4. Port forwarding is set up to access the OVA VM:
   - SSH (guest port 22 → host port 2201)
   - Any additional ports specified in configuration

This allows the framework to connect to the OVA VM through the allocator instance using the forwarded ports.

## OVA Testing Strategy

The OVA testing strategy follows these steps:

1. **Allocator Setup**:
   - Launch an EC2 instance to serve as the allocator
   - Install VirtualBox on the allocator

2. **OVA Import**:
   - Download the OVA file from S3
   - Import the OVA into VirtualBox
   - Configure VM settings (memory, CPUs)

3. **Port Forwarding Setup**:
   - Configure port forwarding for SSH and other required ports

4. **Test Execution**:
   - Run all specified tests against the OVA VM
   - Collect and analyze results

5. **Reporting**:
   - Generate detailed reports in the specified format
   - Include pass/fail status for each test

6. **Cleanup**:
   - Stop and remove the imported VM
   - Terminate the allocator instance
   - Clean up temporary resources

## Configuration

The OVA testing module uses the [core configuration system](../test.md#core-configuration) defined in `config.py`. For OVA-specific testing, the configuration is managed through the `OVATesterConfig` class which extends the base configuration:

```python
class OVATesterConfig(BaseTesterConfig):
    """Main configuration for the OVA tester."""

    # OVA-specific options
    import_only: bool = False

    # Allocator options for EC2 instance to run VirtualBox
    allocator_enabled: bool = True
    allocator_instance_type: str = "metal"
    allocator_role: str = "default"

    # VirtualBox options
    virtualbox_version: str = "7.0.12"
    vm_memory: int = 8192  # MB
    vm_cpus: int = 4

    # Network options
    vm_network_mode: str = "nat"
    vm_port_forwards: Dict[int, int] = Field(default_factory=dict)  # guest port -> host port

    # VM access options
    vm_username: str = "wazuh-user"
    vm_password: str = "wazuh"

    # Test-specific OVA options
    ova_test_features: List[str] = Field(default_factory=list)
```

This OVA-specific configuration provides:
- OVA identification and import settings
- AWS allocator configuration for VirtualBox hosting
- VM resource allocation settings
- Network and port forwarding configuration
- VM access credentials

Key configuration aspects for OVA testing include:
- AWS allocator settings (instance type, region, security groups)
- VirtualBox configuration (version, VM resources)
- VM network configuration (port forwarding)
- Test patterns to execute, including OVA-specific tests
- Expected versions of Wazuh components

The configuration is designed to be modular and extensible, making it easy to add new tests or parameters while maintaining backward compatibility and consistent validation.
