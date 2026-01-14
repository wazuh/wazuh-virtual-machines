"""
Configuration module for Wazuh VM Tester.
"""

import os
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, validator


class TestType(str, Enum):
    """Enum representing the types of tests that can be run."""

    AMI = "ami"
    OVA = "ova"


class EndpointConfig(BaseModel):
    """Configuration for API/health endpoints."""

    url: str
    token: str | None = None
    method: str = "GET"
    auth: dict[str, str] | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    expected_status: list[int] = Field(default_factory=lambda: [200])
    expected_content: str | None = None


class CommandConfig(BaseModel):
    """Configuration for commands to execute."""

    command: str
    expected_output: str | None = None
    expected_regex: str | None = None
    expected_status: int = 0


class WazuhServiceConfig(BaseModel):
    """Configuration for validating a Wazuh service."""

    name: str
    version: str | None = None
    revision: str | None = None
    port: int | list[int | str] | None = None
    process_name: str | None = None
    log_files: list[str] = []
    log_commands: list[str] = []
    required_dirs: list[str] = []
    required_files: list[str] = []
    version_commands: list[CommandConfig] = Field(default_factory=list)
    revision_commands: list[CommandConfig] = Field(default_factory=list)
    health_endpoints: list[EndpointConfig] = Field(default_factory=list)
    api_endpoints: list[EndpointConfig] = Field(default_factory=list)


class WazuhCertificateConfig(BaseModel):
    """Configuration for validating Wazuh certificates."""

    path: str
    subject_match: str | None = None
    issuer_match: str | None = None
    days_valid: int = 90
    permissions: int | None = None


class ConnectivityTestConfig(BaseModel):
    """Configuration for connectivity tests between services."""

    source: str
    target: str
    host: str
    port: int


class BaseTesterConfig(BaseModel):
    """Base configuration for all testers."""

    # Test Type
    test_type: TestType = TestType.AMI

    # Define which tests to run based on test type
    test_patterns: dict[str, list[str]] = Field(
        default_factory=lambda: {
            TestType.AMI: ["test_certificates", "test_connectivity", "test_services", "test_logs", "test_version"],
            TestType.OVA: [
                "test_certificates",
                "test_connectivity",
                "test_services",
                "test_logs",
                "test_version",
                "test_ova",
            ],
        }
    )

    # Connection options
    use_local: bool = False
    ssh_host: str | None = None
    existing_instance_id: str | None = None

    # OVA S3 path
    ova_s3_path: str | None = None

    # Ansible inventory options
    ansible_inventory_path: str | None = None
    ansible_host_id: str | None = None

    # AWS options
    aws_region: str = "us-east-1"
    aws_role: str = "default"

    # SSH options
    ssh_username: str = "wazuh-user"
    ssh_password: str | None = "wazuh"
    ssh_key_path: str | None = None
    key_name: str | None = None
    ssh_private_key: str | None = None
    ssh_port: int = 22
    ssh_common_args: str | None = None

    # AWS additional options
    instance_profile: str | None = None
    default_security_group_ids: list[str] = Field(default_factory=lambda: ["sg-0471247ce289c863c"])
    security_group_ids: list[str] = []
    tags: dict[str, str] = Field(default_factory=dict)
    terminate_on_completion: bool = True
    temp_key_name: str | None = None
    existing_instance: Any = None

    # Wazuh expected versions
    expected_version: str | None = None
    expected_revision: str | None = None

    # Timeouts in seconds
    launch_timeout: int = 300
    ssh_connect_timeout: int = 420
    service_check_timeout: int = 60
    max_retries: int = 5
    retry_delay: int = 30

    # Service configuration
    services: list[WazuhServiceConfig] = Field(default_factory=list)
    certificates: list[WazuhCertificateConfig] = Field(default_factory=list)
    connectivity_tests: list[ConnectivityTestConfig] = Field(default_factory=list)

    # Error patterns for log checks
    log_error_patterns: list[str] = Field(default_factory=list)
    log_false_positives: list[str] = Field(default_factory=list)

    class Config:
        """Pydantic model configuration."""

        validate_assignment = True
        extra = "forbid"

    @validator("security_group_ids", pre=True, always=True)
    def set_security_groups(cls, v, values):
        """Use default security groups if none are provided."""
        if not v and "default_security_group_ids" in values:
            return values["default_security_group_ids"]
        return v

    @validator("test_type", pre=True)
    def validate_test_type(cls, v):
        """Validate that a test type is explicitly specified."""
        if not v:
            raise ValueError("Must specify a test type (ami, ova, kubernetes, puppet)")
        return v

    def __init__(self, **data):
        """Initialize with default Wazuh configuration if not provided."""
        if "services" not in data:
            data["services"] = get_default_wazuh_services()
        if "certificates" not in data:
            data["certificates"] = get_default_wazuh_certificates()
        if "connectivity_tests" not in data:
            data["connectivity_tests"] = get_default_connectivity_tests()
        if "log_error_patterns" not in data:
            data["log_error_patterns"] = get_default_log_error_patterns()
        if "log_false_positives" not in data:
            data["log_false_positives"] = get_default_log_false_positives()
        super().__init__(**data)


class AMITesterConfig(BaseTesterConfig):
    """Main configuration for the AMI tester."""

    # AMI option
    ami_id: str | None = None

    # AWS instance options
    instance_type: str = "t3.medium"

    @validator("ami_id", "existing_instance_id", "ssh_host", "ansible_inventory_path", pre=True)
    def validate_required_fields(cls, v, values):
        """Validate that at least one way to connect is specified."""
        if "use_local" in values and values["use_local"]:
            return v

        if (
            not v
            and not values.get("ami_id")
            and not values.get("existing_instance_id")
            and not values.get("ssh_host")
            and not values.get("ansible_inventory_path")
        ):
            raise ValueError(
                "At least one of 'ami_id', 'existing_instance_id', 'ssh_host', "
                "'ansible_inventory_path', or 'use_local' must be specified"
            )
        return v


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
    vm_port_forwards: dict[int, int] = Field(default_factory=dict)  # guest port -> host port

    # VM access options
    vm_username: str = "wazuh-user"
    vm_password: str = "wazuh"

    # Test-specific OVA options
    ova_test_features: list[str] = Field(default_factory=list)

    @validator("ova_s3_path")
    def validate_ova_path(cls, v, values):
        """Validate if OVA S3 path is provided."""
        # If other connection methods are specified, OVA path is not required
        if (
            values.get("ssh_host")
            or values.get("existing_instance_id")
            or values.get("use_local")
            or values.get("ansible_inventory_path")
        ):
            return v

        # Otherwise, OVA S3 path is required for OVA testing
        if not v and values.get("test_type") == TestType.OVA:
            raise ValueError("OVA S3 path is required for OVA testing")
        return v


def parse_version_with_revision(version_string: str) -> tuple[str, str | None]:
    """Parse version string with optional revision

    Args:
        version_string: Version string, potentially with revision (e.g. "MAYOR.MINOR.PATCH-REVISION")

    Returns:
        Tuple of (version, revision)
    """
    if not version_string:
        return None, None

    parts = version_string.split("-", 1)
    version = parts[0]
    revision = parts[1] if len(parts) > 1 else None

    return version, revision


def get_default_wazuh_services() -> list[WazuhServiceConfig]:
    """Get default configuration for Wazuh services."""

    server_version, server_revision = parse_version_with_revision(
        os.getenv("WAZUH_SERVER_EXPECTED_VERSION", default="5.0.0-latest")
    )
    indexer_version, indexer_revision = parse_version_with_revision(
        os.getenv("WAZUH_INDEXER_EXPECTED_VERSION", default="5.0.0-latest")
    )
    dashboard_version, dashboard_revision = parse_version_with_revision(
        os.getenv("WAZUH_DASHBOARD_EXPECTED_VERSION", default="5.0.0-latest")
    )

    return [
        WazuhServiceConfig(
            name="wazuh-server",
            version=server_version,
            revision=server_revision,
            port=[27000, 55000],
            process_name="wazuh-server",
            log_files=[],
            log_commands=["journalctl -u wazuh-server -n 100"],
            required_dirs=["/etc/wazuh-server", "/usr/share/wazuh-server", "/usr/share/wazuh-server/bin"],
            required_files=["/etc/wazuh-server/wazuh-server.yml"],
            version_commands=[
                CommandConfig(
                    command="/usr/share/wazuh-server/bin/wazuh-server-management-apid -v",
                    expected_regex=r"Wazuh ([\d.]+)",
                ),
                CommandConfig(
                    command="cat /usr/share/wazuh-server/VERSION.json", expected_regex=r'"version":\s*"([\d.]+)"'
                ),
            ],
            revision_commands=[
                CommandConfig(
                    command="rpm -q wazuh-server --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-server 2>/dev/null | cut -d '-' -f2",
                    expected_regex=r"(.+)",
                )
            ],
            api_endpoints=[
                EndpointConfig(
                    token="https://localhost:55000/security/user/authenticate?raw=true",
                    url="https://localhost:55000/?pretty=true",
                    auth={"username": "wazuh", "password": "wazuh"},
                    headers={"Content-Type": "application/json"},
                    expected_status=[200],
                ),
            ],
        ),
        WazuhServiceConfig(
            name="wazuh-indexer",
            version=indexer_version,
            revision=indexer_revision,
            port=9200,
            process_name="wazuh-indexer",
            log_files=["/var/log/wazuh-indexer/wazuh-cluster.log"],
            log_commands=[],
            required_dirs=["/etc/wazuh-indexer"],
            version_commands=[
                CommandConfig(
                    command="rpm -q wazuh-indexer 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null",
                    expected_regex=r"([\d.]+)",
                ),
                CommandConfig(
                    command="cat /usr/share/wazuh-indexer/VERSION.json", expected_regex=r'"version":\s*"([\d.]+)"'
                ),
            ],
            revision_commands=[
                CommandConfig(
                    command="rpm -q wazuh-indexer --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null | cut -d '-' -f2",
                    expected_regex=r"(.+)",
                )
            ],
            health_endpoints=[
                EndpointConfig(
                    url="https://localhost:9200/_cluster/health?pretty",
                    auth={"username": "admin", "password": "admin"},
                    expected_status=[200],
                )
            ],
        ),
        WazuhServiceConfig(
            name="wazuh-dashboard",
            version=dashboard_version,
            revision=dashboard_revision,
            port=443,
            process_name="wazuh-dashboard",
            log_files=[],
            log_commands=["journalctl -u wazuh-dashboard -n 100"],
            required_dirs=["/etc/wazuh-dashboard"],
            version_commands=[
                CommandConfig(
                    command="rpm -q wazuh-dashboard 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null",
                    expected_regex=r"([\d.]+)",
                ),
                CommandConfig(
                    command="cat /usr/share/wazuh-dashboard/VERSION.json", expected_regex=r'"version":\s*"([\d.]+)"'
                ),
            ],
            revision_commands=[
                CommandConfig(
                    command="rpm -q wazuh-dashboard --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null | cut -d '-' -f2",
                    expected_regex=r"(.+)",
                ),
            ],
            health_endpoints=[
                EndpointConfig(
                    url="https://localhost/status",
                    auth={"username": "admin", "password": "admin"},
                    expected_status=[200],
                )
            ],
        ),
    ]


def get_default_wazuh_certificates() -> list[WazuhCertificateConfig]:
    """Get default configuration for Wazuh certificates."""
    return [
        # Wazuh indexer
        WazuhCertificateConfig(
            path="/etc/wazuh-indexer/certs/root-ca.pem",
            subject_match="OU=Wazuh",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-indexer/certs/indexer-1.pem",
            subject_match="CN=wazuh_indexer",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-indexer/certs/admin.pem",
            subject_match="CN=admin",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
        # Wazuh dashboard
        WazuhCertificateConfig(
            path="/etc/wazuh-dashboard/certs/root-ca.pem",
            subject_match="OU=Wazuh",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-dashboard/certs/dashboard.pem",
            subject_match="CN=wazuh_dashboard",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
        # Wazuh server
        WazuhCertificateConfig(
            path="/etc/wazuh-server/certs/server-1.pem",
            subject_match="CN=wazuh_server",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-server/certs/root-ca.pem",
            subject_match="OU=Wazuh",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-server/certs/admin.pem",
            subject_match="CN=admin",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-server/certs/root-ca-merged.pem",
            subject_match="OU=Wazuh",
            days_valid=365,
            issuer_match="OU=Wazuh",
            permissions=400,
        ),
    ]


def get_default_connectivity_tests() -> list[ConnectivityTestConfig]:
    """Get default configuration for connectivity tests."""
    return [
        # It is commented to skip the test, because telnet is not enabled for curl, the ports are tested in port test, test is maintained in case connectivity testing between services is required in the future.
        # ConnectivityTestConfig(
        #    source="wazuh-server",
        #    target="wazuh-indexer",
        #    host="localhost",
        #    port=9200,
        # ),
        # ConnectivityTestConfig(
        #    source="wazuh-server",
        #    target="wazuh-dashboard",
        #    host="localhost",
        #    port=50000,
        # ),
    ]


def get_default_log_error_patterns() -> list[str]:
    """Get default error patterns to search for in logs."""
    return [
        r"ERROR:",
        r"CRITICAL:",
        r"FATAL:",
        r"Failed to",
        r"Error:",
        r"Could not",
        r"Couldn't",
        r"Exception",
        r"error:",
        r"panic:",
    ]


def get_default_log_false_positives() -> list[str]:
    """Get default patterns that might be false positives in logs."""
    return [
        r"ErrorDocument",
        r"is not an error",
        r"recovering from error",
        r"fixing error",
        r"error resolved",
    ]
