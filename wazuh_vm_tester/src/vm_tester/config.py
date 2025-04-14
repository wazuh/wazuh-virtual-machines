"""
Archivo actualizado de config.py con configuraciones extraídas de los tests
"""

import logging
import logging.config
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml

from pydantic import BaseModel, Field, validator


def setup_logging(
    default_level: str = "INFO",
    config_file: Optional[Union[str, Path]] = None,
    log_file: Optional[Union[str, Path]] = None,
    verbose: bool = False
) -> None:
    """Configure the logging system.

    Args:
        default_level: Default logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', or 'TRACE')
        config_file: Path to a YAML configuration file for logging
        log_file: Path to a file where logs will be written
        verbose: If True, sets default_level to 'DEBUG' if not already more verbose
    """

    if config_file and isinstance(config_file, str):
        config_file = Path(config_file)
    if log_file and isinstance(log_file, str):
        log_file = Path(log_file)

    if verbose and default_level not in ['DEBUG', 'TRACE']:
        default_level = 'DEBUG'

    if config_file and config_file.exists():
        try:
            with open(config_file) as f:
                config = yaml.safe_load(f)
            logging.config.dictConfig(config)
            return
        except Exception as e:
            print(f"Error loading logging config from {config_file}: {e}")

    # TRACE level - completely verbose logging (shows all libraries)
    trace_mode = default_level == 'TRACE'
    if trace_mode:
        default_level = "DEBUG"
    else:
        # Disable detailed logs for external libraries
        loggers_to_disable = [
            'boto3',
            'botocore',
            'urllib3',
            'paramiko',
            's3transfer',
            'filelock',
            'asyncio',
        ]

        for logger_name in loggers_to_disable:
            logging.getLogger(logger_name).setLevel(logging.WARNING)

    handlers = {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
            'level': default_level
        }
    }

    if log_file:
        log_file_path = Path(log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

        handlers['file'] = {
            'class': 'logging.FileHandler',
            'filename': str(log_file),
            'formatter': 'detailed',
            'level': 'DEBUG'
        }

    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'detailed': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
            }
        },
        'handlers': handlers,
        'loggers': {
            '': {
                'handlers': list(handlers.keys()),
                'level': 'DEBUG',
                'propagate': True
            },
            'vm_tester': {
                'handlers': list(handlers.keys()),
                'level': 'DEBUG',
                'propagate': False
            }
        }
    }

    # Apply config
    logging.config.dictConfig(config)

    # Log initial message
    logger = logging.getLogger("vm_tester")
    logger.info(f"Logging initialized with level {default_level}")
    if log_file:
        logger.info(f"Logs will also be written to {log_file}")

    if trace_mode:
        logger.debug("TRACE mode activated - all library logs will be shown")


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name.

    Args:
        name: Name of the logger, typically __name__ of the module

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


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
    version: str = None
    port: Optional[Union[int, List[Union[int, str]]]] = None
    process_name: Optional[str] = None
    log_files: List[str] = []
    log_commands: List[str] = []
    required_dirs: List[str] = []
    required_files: List[str] = []
    version_commands: List[CommandConfig] = Field(default_factory=list)
    health_endpoints: List[EndpointConfig] = Field(default_factory=list)
    api_endpoints: List[EndpointConfig] = Field(default_factory=list)


class WazuhCertificateConfig(BaseModel):
    """Configuration for validating Wazuh certificates."""
    path: str
    subject_match: Optional[str] = None
    issuer_match: Optional[str] = None
    days_valid: int = 90


class ConnectivityTestConfig(BaseModel):
    """Configuration for connectivity tests between services."""
    source: str
    target: str
    host: str
    port: int


class AMITesterConfig(BaseModel):
    """Main configuration for the AMI tester."""
    # AMI option
    ami_id: Optional[str] = None
    existing_instance_id: Optional[str] = None
    use_local: bool = False

    # Ansible inventory option
    ansible_inventory_path: Optional[str] = None
    ansible_host_id: Optional[str] = None

    # AWS options
    aws_region: str = "us-east-1"
    aws_role: str = "default"
    instance_type: str = "t3.medium"

    # SSH options
    ssh_username: str = "wazuh-user"
    ssh_key_path: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ssh_host: Optional[str] = None
    ssh_port: int = 22
    ssh_common_args: Optional[str] = None

    # AWS additional options
    instance_profile: Optional[str] = None
    default_security_group_ids: List[str] = Field(default_factory=lambda: ["sg-005cff996b335d497","sg-0471247ce289c863c"])
    security_group_ids: List[str] = []
    tags: Dict[str, str] = Field(default_factory=dict)
    terminate_on_completion: bool = True
    temp_key_name: Optional[str] = None
    existing_instance: Any = None

    # Wazuh expected versions
    expected_version: Optional[str] = None
    expected_revision: Optional[str] = None

    # Timeouts in seconds
    launch_timeout: int = 300
    ssh_connect_timeout: int = 420
    service_check_timeout: int = 60
    max_retries: int = 5
    retry_delay: int = 30

    # Service configuration
    services: List[WazuhServiceConfig] = Field(default_factory=list)
    certificates: List[WazuhCertificateConfig] = Field(default_factory=list)
    connectivity_tests: List[ConnectivityTestConfig] = Field(default_factory=list)

    # Error patterns for log checks
    log_error_patterns: List[str] = Field(default_factory=list)
    log_false_positives: List[str] = Field(default_factory=list)

    class Config:
        """Pydantic model configuration."""
        validate_assignment = True
        extra = "forbid"

    @validator('ami_id', 'existing_instance_id', 'ssh_host', 'ansible_inventory_path', pre=True)
    def validate_required_fields(cls, v, values):
        """Validate that at least one way to connect is specified."""
        if 'use_local' in values and values['use_local']:
            return v

        if (not v and not values.get('ami_id') and not values.get('existing_instance_id')
            and not values.get('ssh_host') and not values.get('ansible_inventory_path')):
            raise ValueError(
                "At least one of 'ami_id', 'existing_instance_id', 'ssh_host', "
                "'ansible_inventory_path', or 'use_local' must be specified"
            )
        return v

    @validator('security_group_ids', pre=True, always=True)
    def set_security_groups(cls, v, values):
        """Use default security groups if none are provided."""
        if not v and 'default_security_group_ids' in values:
            return values['default_security_group_ids']
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


def get_default_wazuh_services() -> List[WazuhServiceConfig]:
    """Get default configuration for Wazuh services."""
    return [
        WazuhServiceConfig(
            name="wazuh-server",
            version=os.getenv("WAZUH_SERVER_EXPECTED_VERSION", default="5.0.0"),
            port=[27000, 55000],
            process_name="wazuh-server",
            log_files=[],
            log_commands=["journalctl -u wazuh-server -n 100"],
            required_dirs=["/etc/wazuh-server", "/usr/share/wazuh-server", "/usr/share/wazuh-server/bin"],
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
                ),
                # Could no test, only registering an agent
                #EndpointConfig(
                #    token="https://localhost:27000/api/v1/authentication?raw=true",
                #    url="https://localhost:55000/?pretty=true",
                #    auth={"username": "wazuh", "password": "wazuh"},
                #    headers={"Content-Type": "application/json"},
                #    expected_status=[200]
                #),
            ]
        ),
        WazuhServiceConfig(
            name="wazuh-indexer",
            version=os.getenv("WAZUH_INDEXER_EXPECTED_VERSION", default="2.19.1"),
            port=9200,
            process_name="wazuh-indexer",
            log_files=["/var/log/wazuh-indexer/wazuh-cluster.log"],
            log_commands=[],
            required_dirs=["/etc/wazuh-indexer"],
            version_commands=[
                CommandConfig(
                    command="curl -s -k -u admin:admin https://localhost:9200/",
                    expected_regex=r'"number"\s*:\s*"([\d.]+)"'
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
        WazuhServiceConfig(
            name="wazuh-dashboard",
            version=os.getenv("WAZUH_DASHBOARD_EXPECTED_VERSION", default="5.0.0"),
            port=443,
            process_name="wazuh-dashboard",
            log_files=[],
            log_commands=["journalctl -u wazuh-dashboard -n 100"],
            required_dirs=["/etc/wazuh-dashboard"],
            version_commands=[
                CommandConfig(
                    command="rpm -q wazuh-dashboard 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null",
                    expected_regex=r"([\d.]+)"
                ),
            ],
            health_endpoints=[
                EndpointConfig(
                    url="https://localhost/status",
                    auth={"username": "admin", "password": "admin"},
                    expected_status=[200]
                )
            ]
        ),
    ]


def get_default_wazuh_certificates() -> List[WazuhCertificateConfig]:
    """Get default configuration for Wazuh certificates."""
    return [
        # Wazuh indexer
        WazuhCertificateConfig(
            path="/etc/wazuh-indexer/certs/root-ca.pem",
            subject_match="OU=Wazuh",
            days_valid=365,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-indexer/certs/indexer-1.pem",
            subject_match="CN=wazuh_indexer",
            days_valid=365,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-indexer/certs/admin.pem",
            subject_match="CN=admin",
            days_valid=365,
        ),
        # Wazuh dashboard
        WazuhCertificateConfig(
            path="/etc/wazuh-dashboard/certs/root-ca.pem",
            subject_match="OU=Wazuh",
            days_valid=365,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-dashboard/certs/dashboard.pem",
            subject_match="CN=wazuh_dashboard",
            days_valid=365,
        ),
        # Wazuh server
        WazuhCertificateConfig(
            path="/etc/wazuh-server/certs/server-1.pem",
            subject_match="CN=wazuh_server",
            days_valid=365,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-server/certs/root-ca.pem",
            subject_match="OU=Wazuh",
            days_valid=365,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-server/certs/admin.pem",
            subject_match="CN=admin",
            days_valid=365,
        ),
        WazuhCertificateConfig(
            path="/etc/wazuh-server/certs/root-ca-merged.pem",
            subject_match="OU=Wazuh",
            days_valid=365,
        ),
    ]


def get_default_connectivity_tests() -> List[ConnectivityTestConfig]:
    """Get default configuration for connectivity tests."""
    return [
        # It is commented to skip the test, because telnet is not enabled for curl, the ports are tested in port test, test is maintained in case connectivity testing between services is required in the future.
        #ConnectivityTestConfig(
        #    source="wazuh-server",
        #    target="wazuh-indexer",
        #    host="localhost",
        #    port=9200,
        #),
        #ConnectivityTestConfig(
        #    source="wazuh-server",
        #    target="wazuh-dashboard",
        #    host="localhost",
        #    port=50000,
        #),
    ]


def get_default_log_error_patterns() -> List[str]:
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


def get_default_log_false_positives() -> List[str]:
    """Get default patterns that might be false positives in logs."""
    return [
        r"ErrorDocument",
        r"is not an error",
        r"recovering from error",
        r"fixing error",
        r"error resolved",
    ]
