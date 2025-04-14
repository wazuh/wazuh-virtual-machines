
#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/config.py
#==================================================

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

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/conftest.py
#==================================================

"""
Pytest configuration and fixtures for wazuh_vm_tester.
"""

import os
import pytest
import sys
from pathlib import Path
from typing import Any

src_dir = Path(__file__).parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from .config import AMITesterConfig, get_logger
from .connections.pytest_connector import get_connection

logger = get_logger(__name__)


def pytest_addoption(parser):
    """Add custom command-line options to pytest."""

    parser.addoption(
        "--ssh-host",
        action="store",
        help="Host to connect to via SSH"
    )
    parser.addoption(
        "--ssh-username",
        action="store",
        default="wazuh-user",
        help="SSH username (default: wazuh-user)"
    )
    parser.addoption(
        "--ssh-key",
        action="store",
        help="Path to SSH private key"
    )
    parser.addoption(
        "--ssh-port",
        action="store",
        default="22",
        help="SSH port (default: 22)"
    )

    parser.addoption(
        "--use-local",
        action="store_true",
        help="Use local machine for testing"
    )

    parser.addoption(
        "--expected-version",
        action="store",
        help="Expected Wazuh version"
    )
    parser.addoption(
        "--expected-revision",
        action="store",
        help="Expected revision"
    )

    parser.addoption(
        "--json",
        action="store",
        help="Path to save JSON output"
    )
    parser.addoption(
        "--github",
        action="store",
        help="Path to save GitHub-compatible output"
    )


@pytest.fixture(scope="session")
def config(request) -> AMITesterConfig:
    """Create test configuration from command-line arguments.

    Args:
        request: Pytest request object

    Returns:
        AMITesterConfig object
    """
    ssh_host = request.config.getoption("--ssh-host")
    ssh_username = request.config.getoption("--ssh-username")
    ssh_key = request.config.getoption("--ssh-key")
    ssh_port = int(request.config.getoption("--ssh-port"))
    use_local = request.config.getoption("--use-local")
    expected_version = request.config.getoption("--expected-version")
    expected_revision = request.config.getoption("--expected-revision")

    if not ssh_host and not use_local:
        expected_version = expected_version or os.environ.get("WAZUH_EXPECTED_VERSION")
        expected_revision = expected_revision or os.environ.get("WAZUH_EXPECTED_REVISION")

    if use_local:
        return AMITesterConfig(
            use_local=True,
            expected_version=expected_version,
            expected_revision=expected_revision
        )
    elif ssh_host:
        return AMITesterConfig(
            ssh_host=ssh_host,
            ssh_username=ssh_username,
            ssh_key_path=ssh_key,
            ssh_port=ssh_port,
            expected_version=expected_version,
            expected_revision=expected_revision
        )
    else:
        return AMITesterConfig(
            expected_version=expected_version,
            expected_revision=expected_revision
        )


@pytest.fixture(scope="session")
def instance() -> Any:
    """Use active connection for testing.

    Returns:
        Connected instance for testing
    """
    return get_connection()

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/cli.py
#==================================================

"""
Command Line Interface for Wazuh VM Tester.
"""

import argparse
import io
import os
import sys
import contextlib
from pathlib import Path

import pytest

from .config import AMITesterConfig, setup_logging, get_logger
from .strategies import StrategyFactory
from .connections.pytest_connector import ConnectionRegistry
from .reporting.manager import ReportManager
from .reporting.base import TestResult, TestStatus

# Configure logging
logger = get_logger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Namespace with the parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Tool for validating Wazuh VMs"
    )

    # Define execution type ami, shh, inventory or local (one required)
    connection_group = parser.add_mutually_exclusive_group(required=True)
    connection_group.add_argument(
        "--ami-id", help="ID of the AMI to validate by launching a new EC2 instance"
    )
    connection_group.add_argument(
        "--inventory",
        help="Path to Ansible inventory file to use for connection details"
    )
    connection_group.add_argument(
        "--ssh-host",
        help="SSH host to connect to (direct SSH mode)"
    )
    connection_group.add_argument(
        "--use-local", action="store_true",
        help="Use local machine for testing"
    )

    # For ssh connection
    ssh_group = parser.add_argument_group('Direct SSH Options')
    ssh_group.add_argument(
        "--ssh-username", default="wazuh-user",
        help="SSH username (default: wazuh-user)"
    )
    ssh_group.add_argument(
        "--ssh-key-path",
        help="Path to the SSH private key"
    )
    ssh_group.add_argument(
        "--ssh-port", type=int, default=22,
        help="SSH port (default: 22)"
    )

    # For inventory
    ansible_group = parser.add_argument_group('Ansible Inventory Options')
    ansible_group.add_argument(
        "--host",
        help="Host ID in the Ansible inventory to use (defaults to first host if not specified)"
    )

    # For AMI creation
    aws_group = parser.add_argument_group('AWS Options')
    aws_group.add_argument(
        "--aws-region", default="us-east-1", help="AWS region (default: us-east-1)"
    )
    aws_group.add_argument(
        "--instance-type", default="t3.medium", help="EC2 instance type (default: t3.medium)"
    )
    aws_group.add_argument(
        "--subnet-id", help="ID of the subnet where to launch the instance"
    )
    aws_group.add_argument(
        "--instance-profile", help="IAM instance profile name"
    )
    aws_group.add_argument(
        "--no-terminate", action="store_true", help="Do not terminate the instance after tests"
    )
    aws_group.add_argument(
        "--security-group-ids",
        nargs="+",
        help="Security group IDs (overrides default security groups)"
    )
    aws_group.add_argument(
        "--aws-role",
        choices=["qa", "dev", "default"],
        default="default",
        help="AWS role to assume (default: default)"
    )

    # Validation parameters
    validation_group = parser.add_argument_group('Validation Options')
    validation_group.add_argument(
        "--version", help="Expected Wazuh version"
    )
    validation_group.add_argument(
        "--revision", help="Expected AMI revision"
    )

    # Logging options
    logging_group = parser.add_argument_group('Logging Options')
    logging_group.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "TRACE"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )

    # Output parameters
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        "--output", choices=["json", "markdown", "console", "github"],
    )
    output_group.add_argument(
        "--output-file", help="File where to save the results"
    )

    # Pytest extra arguments
    pytest_group = parser.add_argument_group('Pytest Options')
    pytest_group.add_argument(
        "--test-pattern", default="*",
        help="Test pattern to run (e.g. 'services*' or 'test_connectivity.py')"
    )
    pytest_group.add_argument(
        "--pytest-args",
        help="Additional arguments to pass to pytest"
    )

    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    """Validate command-line arguments.

    Args:
        args: Parsed arguments

    Raises:
        ValueError: If required arguments are missing
    """
    # Validate direct SSH mode arguments
    if args.ssh_host:
        if not args.ssh_key_path and "SSH_PRIVATE_KEY" not in os.environ:
            raise ValueError("SSH key path is required for direct SSH mode. Use --ssh-key-path.")

    # Validate Ansible inventory mode arguments
    elif args.inventory:
        # Check if inventory file exists
        if not os.path.exists(args.inventory):
            raise ValueError(f"Ansible inventory file not found: {args.inventory}")


def load_config_from_args(args: argparse.Namespace) -> AMITesterConfig:
    """Load configuration from command-line arguments.

    Args:
        args: Parsed arguments

    Returns:
        Configuration for the tester
    """
    # Check environment variables for SSH keys
    ssh_private_key = os.environ.get("SSH_PRIVATE_KEY")

    # Configure tags for AWS instances
    tags = {
        "Name": f"wazuh-vm-test-{args.ami_id if args.ami_id else 'remote-host'}",
        "CreatedBy": "wazuh-vm-tester",
        "AutoTerminate": "true" if not getattr(args, 'no_terminate', False) else "false",
    }

    # Create configuration based on connection mode
    if args.ami_id:
        # AMI mode - launching a new instance
        config = AMITesterConfig(
            ami_id=args.ami_id,
            aws_region=args.aws_region,
            aws_role=args.aws_role,
            instance_type=args.instance_type,
            ssh_username=args.ssh_username,
            ssh_key_path=args.ssh_key_path,
            ssh_private_key=ssh_private_key,
            ssh_port=args.ssh_port,
            expected_version=args.version,
            expected_revision=args.revision,
            subnet_id=args.subnet_id,
            security_group_ids=args.security_group_ids or [],
            instance_profile=args.instance_profile,
            tags=tags,
            terminate_on_completion=not getattr(args, 'no_terminate', False)
        )
    elif args.inventory:
        # Ansible inventory mode
        config = AMITesterConfig(
            ansible_inventory_path=args.inventory,
            ansible_host_id=args.host,
            expected_version=args.version,
            expected_revision=args.revision,
            aws_region=args.aws_region
        )
    elif args.use_local:
        # Local testing mode
        config = AMITesterConfig(
            use_local=True,
            expected_version=args.version,
            expected_revision=args.revision,
        )
    else:
        # Direct SSH mode
        config = AMITesterConfig(
            ssh_host=args.ssh_host,
            ssh_username=args.ssh_username,
            ssh_key_path=args.ssh_key_path,
            ssh_private_key=ssh_private_key,
            ssh_port=args.ssh_port,
            expected_version=args.version,
            expected_revision=args.revision,
            aws_region=args.aws_region
        )

    return config


class ResultCollector:
    def __init__(self, log_level="INFO"):
        """Inicializa el colector de resultados.

        Args:
            log_level: Nivel de logging para controlar el detalle
        """
        self.results = []
        self.log_level = log_level
        self.debug_mode = log_level in ["DEBUG", "TRACE"]
        self.all_test_items = []

    def pytest_collection_modifyitems(self, session, config, items):
        """Captura todos los items de test disponibles.

        Args:
            session: Sesión de pytest
            config: Configuración de pytest
            items: Lista de items de test
        """
        self.all_test_items = items

    def pytest_runtest_protocol(self, item, nextitem):
        """Método llamado antes de ejecutar cada test.

        Args:
            item: Item de test que se va a ejecutar
            nextitem: Siguiente item que se ejecutará
        """
        if self.debug_mode:
            logger.debug(f"Running test: {item.nodeid}")

        return None

    def pytest_runtest_logreport(self, report):
        """Método llamado para cada reporte de test.

        Args:
            report: Reporte de pytest
        """
        if report.when == "call" or (report.when == "setup" and report.failed):
            nodeid = report.nodeid
            status = TestStatus.PASS if report.passed else TestStatus.FAIL if report.failed else TestStatus.SKIPPED

            # Extract module name
            module_name = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
            module_name = module_name.replace("test_", "").capitalize()

            # Extract test name
            test_name = nodeid.split("::")[-1].replace("test_", "").replace("_", " ").capitalize()

            message = ""
            if hasattr(report, "longrepr") and report.longrepr:
                if hasattr(report.longrepr, "reprcrash") and report.longrepr.reprcrash:
                    message = str(report.longrepr)
                    crash_message = report.longrepr.reprcrash.message

                    if "AssertionError:" in crash_message and "\n" in crash_message:
                        logger.debug(f"Mensaje completo encontrado en aserción: {crash_message}")
                else:
                    message = str(report.longrepr)

            test_result = TestResult(
                test_id=nodeid,
                name=f"{module_name}: {test_name}",
                status=status,
                message=message,
                duration=getattr(report, "duration", 0),
                module=module_name
            )
            self.results.append(test_result)

            status_colors = {
                TestStatus.PASS: "\033[92m",     # Green
                TestStatus.FAIL: "\033[91m",     # Red
                TestStatus.WARNING: "\033[93m",  # Yellow
                TestStatus.SKIPPED: "\033[94m",  # Blue
                TestStatus.ERROR: "\033[91m",    # Red
            }

            color = status_colors.get(status, "")
            reset = "\033[0m"

            if status == TestStatus.FAIL:
                if self.debug_mode:
                    logger.info(f"{color}{status.value}{reset} - {test_name}")
                    for line in message.split("\n"):
                        logger.debug(f"  {line}")
                else:
                    logger.info(f"{color}{status.value}{reset} - {test_name}")
            else:
                logger.info(f"{color}{status.value}{reset} - {test_name}")


def run_tests(config: AMITesterConfig, args: argparse.Namespace) -> int:
    """Run tests using the appropriate strategy.

    Args:
        config: Tester configuration
        args: Command-line arguments

    Returns:
        Exit code (0 for success, 1 for error)
    """
    logger.info("Running tests")

    debug_mode = args.log_level in ["DEBUG", "TRACE"]

    strategy = StrategyFactory.create_strategy(config)
    if not strategy:
        logger.error("Failed to create a valid connection strategy")
        return 1

    connection = strategy.create_connection()
    if not connection:
        logger.error("Failed to establish connection")
        return 1

    ConnectionRegistry.set_active_connection(connection)
    logger.info(f"Connection '{connection.id}' set as active for testing")

    try:
        current_dir = Path(__file__).parent.absolute()
        tests_dir = current_dir / "tests"

        if not tests_dir.exists() or not tests_dir.is_dir():
            logger.error(f"Tests directory not found: {tests_dir}")
            return 1

        logger.info(f"Using tests path: {tests_dir}")

        pytest_args = [str(tests_dir)]

        if args.test_pattern and args.test_pattern != "*":
            pytest_args.extend(["-k", args.test_pattern])

        if debug_mode:
            pytest_args.append("-v")

        if args.pytest_args:
            pytest_args.extend(args.pytest_args.split())

        class ResultCollector:
            def __init__(self, log_level="INFO"):
                """Inicializa el colector de resultados.

                Args:
                    log_level: Nivel de logging para controlar el detalle
                """
                self.results = []
                self.log_level = log_level
                self.debug_mode = log_level in ["DEBUG", "TRACE"]
                self.all_test_items = []

            def pytest_collection_modifyitems(self, session, config, items):
                """Captura todos los items de test disponibles.

                Args:
                    session: Sesión de pytest
                    config: Configuración de pytest
                    items: Lista de items de test
                """
                self.all_test_items = items

            def pytest_runtest_protocol(self, item, nextitem):
                """Método llamado antes de ejecutar cada test.

                Args:
                    item: Item de test que se va a ejecutar
                    nextitem: Siguiente item que se ejecutará
                """
                if self.debug_mode:
                    logger.debug(f"Running test: {item.nodeid}")
                return None

            def pytest_runtest_logreport(self, report):
                """Método llamado para cada reporte de test.

                Args:
                    report: Reporte de pytest
                """
                if report.when == "call" or (report.when == "setup" and report.failed):
                    nodeid = report.nodeid
                    status = TestStatus.PASS if report.passed else TestStatus.FAIL if report.failed else TestStatus.SKIPPED

                    module_name = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
                    module_name = module_name.replace("test_", "").capitalize()

                    test_name = nodeid.split("::")[-1].replace("test_", "").replace("_", " ").capitalize()

                    message = ""
                    if hasattr(report, "longrepr") and report.longrepr:
                        if self.debug_mode:
                            message = str(report.longrepr)
                        else:
                            if hasattr(report.longrepr, "reprcrash") and report.longrepr.reprcrash:
                                message = report.longrepr.reprcrash.message
                            else:
                                message = str(report.longrepr).split("\n")[-1] if "\n" in str(report.longrepr) else str(report.longrepr)

                    test_result = TestResult(
                        test_id=nodeid,
                        name=f"{module_name}: {test_name}",
                        status=status,
                        message=message,
                        duration=getattr(report, "duration", 0),
                        module=module_name
                    )
                    self.results.append(test_result)

                    status_colors = {
                        TestStatus.PASS: "\033[92m",     # Green
                        TestStatus.FAIL: "\033[91m",     # Red
                        TestStatus.WARNING: "\033[93m",  # Yellow
                        TestStatus.SKIPPED: "\033[94m",  # Blue
                        TestStatus.ERROR: "\033[91m",    # Red
                    }

                    color = status_colors.get(status, "")
                    reset = "\033[0m"

                    if status == TestStatus.FAIL:
                        if self.debug_mode:
                            logger.info(f"{color}{status.value}{reset} - {test_name}")
                            for line in message.split("\n"):
                                logger.debug(f"  {line}")
                        else:
                            logger.info(f"{color}{status.value}{reset} - {test_name}")
                    else:
                        logger.info(f"{color}{status.value}{reset} - {test_name}")

            def pytest_report_teststatus(self, report, config):
                """Intercepta el estado de cada test.

                Args:
                    report: Reporte de pytest
                    config: Configuración de pytest
                """
                return None

            def pytest_terminal_summary(self, terminalreporter, exitstatus, config):
                """Captura el resumen final de pytest.

                Args:
                    terminalreporter: Reporte de la terminal de pytest
                    exitstatus: Estado de salida
                    config: Configuración de pytest
                """
                pass

        result_collector = ResultCollector(log_level=args.log_level)

        logger.info(f"Running pytest with arguments: {pytest_args}")

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            exit_code = pytest.main(pytest_args, plugins=[result_collector])

        if debug_mode:
            stdout_content = stdout_capture.getvalue()
            stderr_content = stderr_capture.getvalue()

            if stdout_content:
                logger.debug("Pytest stdout output:")
                for line in stdout_content.split("\n"):
                    if line.strip():
                        logger.debug(f"  {line}")

            if stderr_content:
                logger.debug("Pytest stderr output:")
                for line in stderr_content.split("\n"):
                    if line.strip():
                        logger.debug(f"  {line}")

        report_manager = ReportManager(debug_mode=debug_mode)

        for test_result in result_collector.results:
            report_manager.add_result(test_result)

        summary = report_manager.get_summary()

        status_colors = {
            TestStatus.PASS: "\033[92m",     # Green
            TestStatus.FAIL: "\033[91m",     # Red
            TestStatus.WARNING: "\033[93m",  # Yellow
            TestStatus.SKIPPED: "\033[94m",  # Blue
            TestStatus.ERROR: "\033[91m",    # Red
        }
        reset = "\033[0m"

        logger.info(f"Tests summary: Total: {summary.total}, "
                   f"Passed: {summary.passed}, "
                   f"Failed: {summary.failed}, "
                   f"Skipped: {summary.skipped}")

        failed_tests = [t for t in report_manager.results if t.status == TestStatus.FAIL or t.status == TestStatus.ERROR]
        passed_tests = [t for t in report_manager.results if t.status == TestStatus.PASS]
        skipped_tests = [t for t in report_manager.results if t.status == TestStatus.SKIPPED]

        if failed_tests:
            logger.info("Failed tests:")
            for test in failed_tests:
                color = status_colors.get(test.status, "")
                logger.info(f"  {color}{test.status.value}{reset} - {test.name}")
                if debug_mode:
                    message = test.message.strip()
                    if message:
                        for line in message.split("\n"):
                            if line.strip():
                                logger.info(f"    {line}")
                else:
                    message = test.message.strip()
                    if message:
                        first_line = message.split("\n")[0]
                        logger.info(f"    {first_line[:150]}")
                        if len(first_line) > 150 or "\n" in message:
                            logger.info("    ...")

        if passed_tests:
            logger.info("Passed tests:")
            for test in passed_tests:
                color = status_colors.get(test.status, "")
                logger.info(f"  {color}{test.status.value}{reset} - {test.name}")

        if skipped_tests:
            logger.info("Skipped tests:")
            for test in skipped_tests:
                color = status_colors.get(test.status, "")
                logger.info(f"  {color}{test.status.value}{reset} - {test.name}")
                message = test.message.strip()
                if message:
                    first_line = message.split("\n")[0]
                    logger.info(f"    {first_line[:150]}")

        if args.output_file:
            report_manager.save_report(args.output_file, args.output)

        report_manager.print_report()
        return exit_code

    finally:
        strategy.cleanup()


def main() -> int:
    """Main entry point.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Parse arguments
        args = parse_args()

        # Setup logging as early as possible
        setup_logging(
            default_level=args.log_level
        )

        # Get properly configured logger
        logger = get_logger(__name__)

        # Validate arguments
        try:
            validate_args(args)
        except ValueError as e:
            logger.error(f"Argument validation error: {e}")
            return 1

        # Load configuration
        config = load_config_from_args(args)

        # Run tests with the configuration
        return run_tests(config, args)

    except KeyboardInterrupt:
        logger.info("Process interrupted by the user")
        return 130
    except Exception as e:
        logger.error(f"Unhandled error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/__init__.py
#==================================================

"""
Wazuh VM Tester - Framework for validating Wazuh VMs using pytest.
"""

__version__ = "0.2.0"

from .config import AMITesterConfig, setup_logging, get_logger

__all__ = ["AMITesterConfig", "setup_logging", "get_logger"]

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/utils/inventory.py
#==================================================

"""
Utility module for working with Ansible inventory files.
"""

import logging
import os
from typing import Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


def read_ansible_inventory(inventory_path: str) -> Dict:
    """Read and parse an Ansible inventory file.

    Args:
        inventory_path: Path to the Ansible inventory file

    Returns:
        Dictionary with the parsed inventory content

    Raises:
        FileNotFoundError: If the inventory file does not exist
        ValueError: If the inventory file cannot be parsed
    """
    if not os.path.exists(inventory_path):
        raise FileNotFoundError(f"Ansible inventory file not found: {inventory_path}")

    try:
        with open(inventory_path, 'r') as f:
            inventory_content = yaml.safe_load(f)
            return inventory_content
    except Exception as e:
        raise ValueError(f"Error parsing Ansible inventory file: {e}")


def get_host_connection_info(inventory_path: str, host_id: Optional[str] = None) -> Dict:
    """Extract connection information for a host from an Ansible inventory.

    Args:
        inventory_path: Path to the Ansible inventory file
        host_id: Optional host ID to extract information for. If not provided,
                 the first host in the inventory will be used.

    Returns:
        Dictionary with connection information for the host

    Raises:
        ValueError: If the host is not found in the inventory or if required connection
                    information is missing
    """
    inventory = read_ansible_inventory(inventory_path)

    if 'all' not in inventory or 'hosts' not in inventory['all']:
        raise ValueError("Invalid Ansible inventory format: 'all.hosts' section is missing")

    hosts = inventory['all']['hosts']
    if not hosts:
        raise ValueError("No hosts found in the Ansible inventory")

    if host_id:
        if host_id not in hosts:
            raise ValueError(f"Host '{host_id}' not found in the Ansible inventory")
        host_info = hosts[host_id]
        host_info['id'] = host_id
    else:
        host_id = next(iter(hosts))
        host_info = hosts[host_id]
        host_info['id'] = host_id

    required_fields = ['ansible_host', 'ansible_user']
    missing_fields = [field for field in required_fields if field not in host_info]

    if missing_fields:
        raise ValueError(f"Missing required fields in host configuration: {', '.join(missing_fields)}")

    connection_info = {
        'host_id': host_info['id'],
        'hostname': host_info['ansible_host'],
        'username': host_info['ansible_user'],
        'port': host_info.get('ansible_port', 22),
        'ssh_key_file': host_info.get('ansible_ssh_private_key_file'),
        'ssh_common_args': host_info.get('ansible_ssh_common_args', ''),
    }

    return connection_info


def list_hosts_in_inventory(inventory_path: str) -> List[str]:
    """List all hosts in an Ansible inventory file.

    Args:
        inventory_path: Path to the Ansible inventory file

    Returns:
        List of host IDs in the inventory
    """
    inventory = read_ansible_inventory(inventory_path)

    if 'all' not in inventory or 'hosts' not in inventory['all']:
        return []

    return list(inventory['all']['hosts'].keys())

import sys
import time
from datetime import datetime

def simple_progress_bar(total_seconds):
    for i in range(total_seconds + 1):
        progress = i / total_seconds
        bar_length = 40
        filled_length = int(bar_length * progress)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        percent = progress * 100

        sys.stdout.write(f'\r[{bar}] {percent:.1f}% ({i}/{total_seconds} seconds)')
        sys.stdout.flush()
        time.sleep(1)
    print()

def digital_clock(total_seconds):
    start_time = time.time()
    for remaining in range(total_seconds, -1, -1):
        elapsed = time.time() - start_time
        percent = ((total_seconds - remaining) / total_seconds) * 100
        elapsed_formatted = time.strftime("%M:%S", time.gmtime(elapsed))
        remaining_formatted = time.strftime("%M:%S", time.gmtime(remaining))
        progress = (total_seconds - remaining) / total_seconds
        bar_length = 50
        filled_length = int(bar_length * progress)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)

        sys.stdout.write(f'\r[{bar}] {percent:.1f}% | Elapsed: {elapsed_formatted} | Remaining: {remaining_formatted}')
        sys.stdout.flush()

        time.sleep(1)
    print()

def spinner_clock(total_seconds):
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    start_time = time.time()

    for i in range(total_seconds):
        elapsed = time.time() - start_time
        remaining = total_seconds - i
        percent = (i / total_seconds) * 100
        spinner_char = spinner[i % len(spinner)]

        elapsed_formatted = time.strftime("%M:%S", time.gmtime(elapsed))
        remaining_formatted = time.strftime("%M:%S", time.gmtime(remaining))

        sys.stdout.write(f'\r{spinner_char} Waiting for AWS instance: {percent:.1f}% | {elapsed_formatted}/{time.strftime("%M:%S", time.gmtime(total_seconds))} | Remaining: {remaining_formatted}')
        sys.stdout.flush()
        time.sleep(1)
    print()

def tqdm_progress(total_seconds):
    try:
        from tqdm import tqdm
        for _ in tqdm(range(total_seconds), desc="Waiting for AWS instance", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [Time: {elapsed}<{remaining}]"):
            time.sleep(1)
    except ImportError:
        simple_progress_bar(total_seconds)

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/utils/__init__.py
#==================================================

"""
Utility modules for the wazuh-ami-tester package.
"""

from .inventory import (
    get_host_connection_info,
    list_hosts_in_inventory,
    read_ansible_inventory,
)

__all__ = [
    "read_ansible_inventory",
    "get_host_connection_info",
    "list_hosts_in_inventory",
]

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/instances/ec2_instance.py
#==================================================

"""
EC2 instance implementation using SSHConnection.
"""

from typing import Optional, Tuple

from ..config import get_logger
from .base import InstanceInterface
from ..connections.ssh import SSHConnection

logger = get_logger(__name__)


class EC2Instance(InstanceInterface):
    """Class for managing an EC2 instance."""

    def __init__(
        self,
        instance_id: str,
        region: str,
        public_ip: Optional[str] = None,
        private_ip: Optional[str] = None,
    ):
        """Initialize with the instance ID.

        Args:
            instance_id: EC2 instance ID
            region: AWS region
            public_ip: Public IP address (optional)
            private_ip: Private IP address (optional)
        """
        self._instance_id = instance_id
        self.region = region
        self._public_ip = public_ip
        self._private_ip = private_ip
        self._ssh_connection = None

    @property
    def instance_id(self) -> str:
        """Get the instance ID."""
        return self._instance_id

    @property
    def public_ip(self) -> Optional[str]:
        """Get the public IP address."""
        return self._public_ip

    @property
    def private_ip(self) -> Optional[str]:
        """Get the private IP address."""
        return self._private_ip

    def connect_ssh(
        self,
        username: str,
        key_path: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
        ssh_common_args: Optional[str] = None,
        max_retries: int = 5,
        retry_delay: int = 30,
        **kwargs
    ) -> 'EC2Instance':
        """Connect to the instance via SSH with retries.

        Args:
            username: Username for the SSH connection
            key_path: Path to the private key file (optional)
            private_key: Private key content (optional)
            port: SSH port
            timeout: Connection timeout in seconds for each attempt
            ssh_common_args: Additional SSH arguments
            max_retries: Maximum number of connection attempts
            retry_delay: Delay between retries in seconds
            **kwargs: Additional parameters for paramiko

        Returns:
            Self for method chaining

        Raises:
            ValueError: If neither key_path nor private_key is provided
            SSHException: If the SSH connection fails after all retries
        """
        if not self.public_ip:
            raise ValueError("No public IP address available for SSH connection")

        if self._ssh_connection is None:
            self._ssh_connection = SSHConnection(
                connection_id=f"ec2-{self.instance_id}",
                host=self.public_ip,
                username=username,
                port=port,
                key_path=key_path,
                private_key=private_key
            )

        self._ssh_connection.connect(
            timeout=timeout,
            ssh_common_args=ssh_common_args,
            max_retries=max_retries,
            retry_delay=retry_delay,
            **kwargs
        )

        return self

    def execute_command(
        self, command: str, sudo: bool = True
    ) -> Tuple[int, str, str]:
        """Execute a command on the instance via SSH.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)

        Raises:
            ValueError: If no SSH connection is established
        """
        if self._ssh_connection is None:
            raise ValueError("No SSH connection established, call connect_ssh first")

        return self._ssh_connection.execute_command(command, sudo)

    def close_ssh(self) -> None:
        """Close the SSH connection if open."""
        if self._ssh_connection:
            self._ssh_connection.close()
            self._ssh_connection = None
            logger.info(f"SSH connection closed to {self.public_ip}")

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/instances/__init__.py
#==================================================

"""
Instance management package.
"""

from .base import InstanceInterface
from .ec2_instance import EC2Instance
from .local_instance import LocalInstance
from .factory import create_instance

__all__ = ["InstanceInterface", "EC2Instance", "LocalInstance", "create_instance"]

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/instances/local_instance.py
#==================================================

"""
Local machine instance implementation.
"""

import subprocess
import shlex
from typing import Tuple

from ..config import get_logger
from .base import InstanceInterface

logger = get_logger(__name__)


class LocalInstance(InstanceInterface):
    """Class to handle local machine testing."""

    def __init__(self):
        """Initialize with local machine info."""
        self._instance_id = "local"
        self._region = "local"
        self._public_ip = "127.0.0.1"
        self._private_ip = "127.0.0.1"
        self._connected = False

    @property
    def instance_id(self) -> str:
        """Get the instance ID."""
        return self._instance_id

    @property
    def public_ip(self) -> str:
        """Get the public IP address."""
        return self._public_ip

    @property
    def private_ip(self) -> str:
        """Get the private IP address."""
        return self._private_ip

    @property
    def region(self) -> str:
        """Get the region."""
        return self._region

    def connect_ssh(self, **kwargs) -> 'LocalInstance':
        """Mock method for local testing (no SSH needed).

        Args:
            **kwargs: Ignored connection parameters

        Returns:
            Self for method chaining
        """
        logger.info("Local testing mode - SSH connection not needed")
        self._connected = True
        return self

    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the local machine.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)
        """
        if sudo and not command.startswith("sudo "):
            command = f"sudo {command}"

        logger.debug(f"Executing command: {command}")

        try:
            # Execute the command
            process = subprocess.Popen(
                shlex.split(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            exit_code = process.returncode

            return exit_code, stdout, stderr
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return 1, "", str(e)

    def close_ssh(self) -> None:
        """Mock method for local testing."""
        logger.info("Local testing mode - no SSH connection to close")
        self._connected = False

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/instances/factory.py
#==================================================

"""
Factory module for creating instances.
"""

from typing import Optional

from ..config import AMITesterConfig, get_logger
from .base import InstanceInterface
from .local_instance import LocalInstance
from .ec2_instance import EC2Instance

logger = get_logger(__name__)


def create_instance(config: AMITesterConfig) -> Optional[InstanceInterface]:
    """Create the appropriate instance type based on configuration.

    Args:
        config: Tester configuration

    Returns:
        An instance of EC2Instance, LocalInstance, or None if creation fails
    """
    logger.info("Creating instance based on configuration...")

    # Local testing mode
    if config.use_local:
        logger.info("Using local instance for testing")
        return LocalInstance()

    # For inventory
    if config.ansible_inventory_path and config.ssh_host in ['localhost', '127.0.0.1']:
        logger.info("Using local instance from Ansible inventory")
        return LocalInstance()

    # SSH connection
    if config.ssh_host:
        logger.info(f"Creating instance for direct SSH to {config.ssh_host}")
        return EC2Instance(
            instance_id="direct-ssh",
            region=config.aws_region,
            public_ip=config.ssh_host
        )

    # AMI testing
    if config.ami_id:
        logger.info(f"Launching new EC2 instance from AMI {config.ami_id}")
        from ..aws.ec2 import EC2Client
        ec2_client = EC2Client(region=config.aws_region)

        security_groups = config.security_group_ids or config.default_security_group_ids

        instance = ec2_client.launch_instance(
            ami_id=config.ami_id,
            instance_type=config.instance_type,
            subnet_id=config.subnet_id,
            security_group_ids=security_groups,
            tags=config.tags,
            instance_profile=config.instance_profile,
            key_name=config.temp_key_name,
            wait=True,
            wait_timeout=config.launch_timeout,
        )

        if instance:
            logger.info(f"Instance {instance.instance_id} launched successfully")
            return instance
        else:
            logger.error(f"Failed to launch instance from AMI {config.ami_id}")
            return None

    # Existing EC2 instance
    if config.existing_instance_id:
        logger.info(f"Using existing EC2 instance {config.existing_instance_id}")
        from ..aws.ec2 import EC2Client
        ec2_client = EC2Client(region=config.aws_region)
        instance_info = ec2_client.get_instance_info(config.existing_instance_id)

        if instance_info:
            return EC2Instance(
                instance_id=config.existing_instance_id,
                region=config.aws_region,
                public_ip=instance_info.get("PublicIpAddress"),
                private_ip=instance_info.get("PrivateIpAddress"),
            )
        else:
            logger.error(f"Failed to get information for instance {config.existing_instance_id}")
            return None

    logger.error("No valid instance configuration provided")
    return None

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/instances/base.py
#==================================================

"""
Base interface for instance types.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional


class InstanceInterface(ABC):
    """Abstract interface for all instance types."""

    @abstractmethod
    def connect_ssh(self, **kwargs) -> 'InstanceInterface':
        """Establish connection to the instance.

        Args:
            **kwargs: Connection parameters

        Returns:
            Self for method chaining
        """
        pass

    @abstractmethod
    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the instance.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit_code, stdout, stderr)
        """
        pass

    @abstractmethod
    def close_ssh(self) -> None:
        """Close connection to the instance."""
        pass

    @property
    @abstractmethod
    def instance_id(self) -> str:
        """Get the instance ID."""
        pass

    @property
    def public_ip(self) -> Optional[str]:
        """Get the public IP address."""
        return None

    @property
    def private_ip(self) -> Optional[str]:
        """Get the private IP address."""
        return None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.instance_id})"

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_services.py
#==================================================

"""
Tests for Wazuh services.
"""

import os
import pytest

from ..config import AMITesterConfig, get_logger
from ..connections.pytest_connector import get_connection

logger = get_logger(__name__)

@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """
    expected_version = os.environ.get("WAZUH_EXPECTED_VERSION")
    expected_revision = os.environ.get("WAZUH_EXPECTED_REVISION")

    return AMITesterConfig(
        expected_version=expected_version,
        expected_revision=expected_revision
    )

@pytest.mark.services
class TestServices:
    """Tests for Wazuh services."""

    def test_services_active(self, config: AMITesterConfig):
        """Test that all services are active."""
        connection = get_connection()

        failures = []

        for service_config in config.services:
            service_name = service_config.name
            logger.info(f"Testing if service is active: {service_name}")

            exit_code, stdout, stderr = connection.execute_command(
                f"systemctl is-active {service_name}"
            )

            if exit_code != 0 or stdout.strip() != "active":
                failures.append(f"Service {service_name} is not active. Output: {stdout} {stderr}")
                logger.warning(f"Service {service_name} is not active. Output: {stdout} {stderr}")


        if failures:
            assert False, "\n".join(failures)

    def test_services_running(self, config: AMITesterConfig):
        """Test that all services are running."""
        connection = get_connection()

        failures = []

        for service_config in config.services:
            service_name = service_config.name
            logger.info(f"Testing if service is running: {service_name}")

            exit_code, stdout, stderr = connection.execute_command(
                f"systemctl status {service_name}"
            )

            if exit_code != 0 or "running" not in stdout:
                failures.append(f"Service {service_name} is not running. Output: {stdout[:100]}...")
                logger.warning(f"Service {service_name} is not running. Exit code: {exit_code}")

        if failures:
            assert False, "\n".join(failures)

    def test_required_directories(self, config: AMITesterConfig):
        """Test that required directories exist."""
        connection = get_connection()

        failures = []

        for service_config in config.services:
            service_name = service_config.name

            for directory in service_config.required_dirs:
                logger.info(f"Testing if directory exists: {directory} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -d {directory} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    failures.append(f"Directory {directory} for {service_name} does not exist")
                    logger.warning(f"Directory {directory} for {service_name} does not exist")

        if failures:
            assert False, "\n".join(failures)

    def test_required_files(self, config: AMITesterConfig):
        """Test that required files exist."""
        connection = get_connection()
        failures = []

        for service_config in config.services:
            service_name = service_config.name

            for file_path in service_config.required_files:
                logger.info(f"Testing if file exists: {file_path} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {file_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    failures.append(f"File {file_path} for {service_name} does not exist")
                    logger.warning(f"File {file_path} for {service_name} does not exist")

        if failures:
            assert False, "\n".join(failures)

    def test_ports_listening(self, config: AMITesterConfig):
        """Test that service ports are listening."""
        connection = get_connection()
        failures = []

        for service_config in config.services:
            if not service_config.port:
                continue

            service_name = service_config.name
            ports = []
            if isinstance(service_config.port, list):
                ports = service_config.port
            else:
                ports = [service_config.port]

            for port in ports:
                logger.info(f"Testing if port is listening: {port} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"netstat -tuln | grep -E ':{port}\\s'"
                )

                if exit_code != 0 or not stdout.strip():

                    exit_code, stdout, _ = connection.execute_command(
                        f"ss -tuln | grep -E ':{port}\\s'"
                    )

                if exit_code != 0 or not stdout.strip():
                    failures.append(f"Port {port} for {service_name} is not listening")
                    logger.warning(f"Port {port} for {service_name} is not listening")

        if failures:
            assert False, "\n".join(failures)

    def test_health_endpoints(self, config: AMITesterConfig):
        """Test health_endpoints of services."""
        connection = get_connection()
        failures = []

        for service_config in config.services:
            service_name = service_config.name

            for endpoint_config in service_config.health_endpoints:
                url = endpoint_config.url
                auth = endpoint_config.auth
                headers = endpoint_config.headers
                expected_status = endpoint_config.expected_status

                logger.info(f"Testing endpoint: {url} for {service_name}")

                if auth:
                    command = f"curl -s -k -u {auth['username']}:{auth['password']} -o /dev/null -w '%{{http_code}}' {url}"
                else:
                    command = f"curl -s -k -o /dev/null -w '%{{http_code}}' {url}"

                for header_name, header_value in headers.items():
                    command += f" -H '{header_name}: {header_value}'"

                exit_code, stdout, stderr = connection.execute_command(command)
                http_code = stdout.strip()

                if exit_code != 0 or int(http_code) not in expected_status:
                    failures.append(
                        f"Endpoint {url} for {service_name} "
                        f"failed with code {http_code}. Error: {stderr}"
                    )
                    logger.warning(
                        f"Endpoint {url} for {service_name} "
                        f"failed with code {http_code}. Error: {stderr}"
                    )

        if failures:
            assert False, "\n".join(failures)

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_certificates.py
#==================================================

"""
Tests for Wazuh certificates.
"""

import os
import pytest
from datetime import datetime

from ..config import AMITesterConfig, get_logger
from ..connections.pytest_connector import get_connection

logger = get_logger(__name__)


@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """
    expected_version = os.environ.get("WAZUH_EXPECTED_VERSION")
    expected_revision = os.environ.get("WAZUH_EXPECTED_REVISION")

    return AMITesterConfig(
        expected_version=expected_version,
        expected_revision=expected_revision
    )


@pytest.mark.certificates
class TestCertificates:
    """Tests for Wazuh certificates."""

    def test_certificates_exist(self, config: AMITesterConfig):
        """Test that all required certificates exist."""
        connection = get_connection()

        failures = []

        for cert_config in config.certificates:
            cert_path = cert_config.path
            logger.info(f"Testing if certificate exists: {cert_path}")

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                failures.append(f"Certificate {cert_path} does not exist")
                logger.warning(f"Certificate {cert_path} does not exist")

        if failures:
            assert False, "\n".join(failures)

    def test_certificates_validity(self, config: AMITesterConfig):
        """Test that certificates are valid and not expired."""
        connection = get_connection()

        failures = []
        skipped_certs = []

        for cert_config in config.certificates:
            cert_path = cert_config.path
            logger.info(f"Testing certificate validity: {cert_path}")

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skipped_certs.append(f"Certificate {cert_path} does not exist - skipping validity check")
                logger.warning(f"Certificate {cert_path} does not exist - skipping validity check")
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -checkend 0"
            )

            if exit_code != 0:
                failures.append(f"Certificate {cert_path} has expired or is invalid: {stderr}")
                logger.warning(f"Certificate {cert_path} has expired or is invalid: {stderr}")
                continue

            # Check days remaining
            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -enddate | cut -d= -f2"
            )

            if exit_code != 0 or not stdout.strip():
                failures.append(f"Could not get end date for certificate {cert_path}: {stderr}")
                logger.warning(f"Could not get end date for certificate {cert_path}: {stderr}")
                continue

            end_date_str = stdout.strip()
            try:
                end_date = datetime.strptime(end_date_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.now()
                days_remaining = (end_date - now).days

                # Verify certificate has enough days remaining
                if days_remaining < cert_config.days_valid:
                    failures.append(
                        f"Certificate {cert_path} will expire in {days_remaining} days "
                        f"(less than the required {cert_config.days_valid} days)"
                    )
                    logger.warning(
                        f"Certificate {cert_path} will expire in {days_remaining} days "
                        f"(less than the required {cert_config.days_valid} days)"
                    )
                else:
                    logger.info(
                        f"Certificate {cert_path} has {days_remaining} days remaining "
                        f"(requirement: {cert_config.days_valid} days)"
                    )
            except ValueError as e:
                failures.append(f"Could not parse certificate end date: {end_date_str}")
                logger.warning(f"Could not parse certificate end date: {end_date_str}")

        if skipped_certs and not failures:
            pytest.skip("\n".join(skipped_certs))

        if failures:
            assert False, "\n".join(failures)

    def test_certificate_subjects(self, config: AMITesterConfig):
        """Test certificate subjects match expected values."""
        connection = get_connection()

        failures = []
        skipped_certs = []

        for cert_config in config.certificates:
            if not cert_config.subject_match:
                continue

            cert_path = cert_config.path
            subject_match = cert_config.subject_match
            logger.info(f"Testing certificate subject: {cert_path} - should match {subject_match}")

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skipped_certs.append(f"Certificate {cert_path} does not exist - skipping subject check")
                logger.warning(f"Certificate {cert_path} does not exist - skipping subject check")
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -subject"
            )

            if exit_code != 0:
                failures.append(f"Error getting subject from certificate {cert_path}: {stderr}")
                logger.warning(f"Error getting subject from certificate {cert_path}: {stderr}")
                continue

            subject = stdout.strip()

            if subject_match.lower() not in subject.lower():
                failures.append(f"Certificate subject {subject} does not match expected pattern {subject_match}")
                logger.warning(f"Certificate subject {subject} does not match expected pattern {subject_match}")

        if skipped_certs and not failures:
            pytest.skip("\n".join(skipped_certs))

        if failures:
            assert False, "\n".join(failures)

    def test_certificate_issuers(self, config: AMITesterConfig):
        """Test certificate issuers match expected values."""
        connection = get_connection()

        failures = []
        skipped_certs = []

        for cert_config in config.certificates:
            if not cert_config.issuer_match:
                continue

            cert_path = cert_config.path
            issuer_match = cert_config.issuer_match
            logger.info(f"Testing certificate issuer: {cert_path} - should match {issuer_match}")

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skipped_certs.append(f"Certificate {cert_path} does not exist - skipping issuer check")
                logger.warning(f"Certificate {cert_path} does not exist - skipping issuer check")
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -issuer"
            )

            if exit_code != 0:
                failures.append(f"Error getting issuer from certificate {cert_path}: {stderr}")
                logger.warning(f"Error getting issuer from certificate {cert_path}: {stderr}")
                continue

            issuer = stdout.strip()

            if issuer_match.lower() not in issuer.lower():
                failures.append(f"Certificate issuer {issuer} does not match expected pattern {issuer_match}")
                logger.warning(f"Certificate issuer {issuer} does not match expected pattern {issuer_match}")

        if skipped_certs and not failures:
            pytest.skip("\n".join(skipped_certs))

        if failures:
            assert False, "\n".join(failures)

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/__init__.py
#==================================================

"""
Test package for Wazuh VM Tester.
"""

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_connectivity.py
#==================================================

"""
Tests for connectivity between Wazuh services.
"""

import os
import pytest

from ..config import AMITesterConfig, get_logger
from ..connections.pytest_connector import get_connection

logger = get_logger(__name__)

@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """
    expected_version = os.environ.get("WAZUH_EXPECTED_VERSION")
    expected_revision = os.environ.get("WAZUH_EXPECTED_REVISION")

    return AMITesterConfig(
        expected_version=expected_version,
        expected_revision=expected_revision
    )

@pytest.mark.connectivity
class TestConnectivity:
    """Tests for connectivity between Wazuh services."""

    def test_service_connectivity(self, config: AMITesterConfig):
        """Test connectivity between services using the configured tests."""
        connection = get_connection()
        failures = []

        for test in config.connectivity_tests:
            logger.info(f"Testing connectivity: from {test.source} to {test.target} by (port {test.port})")
            exit_code, stdout, stderr = connection.execute_command(
                f"curl -v telnet://{test.host}:{test.port} 2>&1"
            )

            if exit_code == 0:
                logger.info(f"Connectivity test passed: from {test.source} to {test.target} by (port {test.port})")
            else:
                exit_code, stdout, stderr = connection.execute_command(
                    f"echo '' | timeout 5 telnet {test.host} {test.port} 2>&1"
                )

                if "Connected to" not in stdout and "Connected to" not in stderr:
                    failures.append(f"Connectivity failure: from {test.source} to {test.target} by (port {test.port})")
                    logger.warning(f"Connectivity failure: from {test.source} to {test.target} by (port {test.port})")

        if failures:
            assert False, "\n".join(failures)

    def test_wazuh_api_connectivity(self, config: AMITesterConfig):
        """Test connectivity to the Wazuh API using configured api_endpoints."""
        connection = get_connection()
        failures = []

        for service in config.services:
            if not service.api_endpoints:
                continue
            logger.info(f"Testing API connectivity for service: {service.name}")

            api_access_successful = False
            for endpoint_config in service.api_endpoints:
                url = endpoint_config.url
                token = endpoint_config.token
                auth = endpoint_config.auth
                headers = endpoint_config.headers

                if not auth:
                    continue
                else:
                    if token:
                        command = f"curl -s -k -u {auth['username']}:{auth['password']} -X POST {token}"
                        exit_code, stdout, stderr = connection.execute_command(command)
                        if exit_code == 0:
                            generated_token = stdout

                    command = f'curl -s -k '

                    if generated_token:
                        command += f'-H "Authorization: Bearer {generated_token}" '

                    for header_name, header_value in headers.items():
                        command += f" -H '{header_name}: {header_value}'"

                    command += f" -X GET -k {url} "

                    logger.info(f"Trying API access with configured auth to {url}")

                    exit_code, stdout, stderr = connection.execute_command(command)

                    if exit_code == 0 and ("token" in stdout or "data" in stdout):
                        logger.info(f"API endpoint {url} is accessible with configured auth")
                        api_access_successful = True
                        break

                if api_access_successful:
                    break

            if not api_access_successful and service.api_endpoints:
                failures.append(f"API access failed for service {service.name}, endpoint {url}, with command {command}, using {generated_token}: no endpoint was accessible")

        if failures:
            assert False, "\n".join(failures)

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_version.py
#==================================================

"""
Tests for Wazuh version and revision.
"""

import os
import pytest
import re
from typing import Dict, List, Optional

from ..config import AMITesterConfig, get_logger
from ..connections.pytest_connector import get_connection

logger = get_logger(__name__)

@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """
    expected_version = os.environ.get("WAZUH_EXPECTED_VERSION")
    expected_revision = os.environ.get("WAZUH_EXPECTED_REVISION")

    return AMITesterConfig(
        expected_version=expected_version,
        expected_revision=expected_revision
    )

@pytest.mark.version
class TestVersion:
    """Tests for Wazuh version and revision."""

    def test_services_versions(self, config: AMITesterConfig):
        """Test the version of all Wazuh services."""
        connection = get_connection()
        services_to_test = ["wazuh-server", "wazuh-indexer", "wazuh-dashboard"]

        for service_name in services_to_test:
            logger.info(f"Testing {service_name} version")

            service_config = next((s for s in config.services if s.name == service_name), None)
            if not service_config:
                pytest.fail(f"{service_name} configuration not found")
                continue

            version_found = False
            detected_version = None

            for cmd_config in service_config.version_commands:
                exit_code, stdout, stderr = connection.execute_command(cmd_config.command)

                if exit_code != 0:
                    logger.warning(f"Command failed for {service_name}: {cmd_config.command}, error: {stderr}")
                    continue
                expected_version = service_config.version

                if cmd_config.expected_regex:
                    version_match = re.search(cmd_config.expected_regex, stdout)
                    if version_match:
                        detected_version = version_match.group(1)
                        logger.info(f"Detected {service_name} version: {detected_version}")
                        version_found = True
                        break
                elif cmd_config.expected_output and cmd_config.expected_output in stdout:
                    logger.info(f"Detected expected output in version command for {service_name}: {cmd_config.command}")
                    version_found = True
                    break

            if not version_found:
                pytest.fail(f"Could not extract {service_name} version from any configured command")
                continue

            if expected_version not in detected_version:
                pytest.fail(
                    f"{service_name} version ({detected_version}) might not be compatible "
                    f"with expected Wazuh version ({expected_version})"
                )

            logger.info(f"{service_name} version check passed")

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/tests/test_logs.py
#==================================================

"""
Tests for Wazuh log files.
"""

import os
import pytest
import re

from ..config import AMITesterConfig, get_logger
from ..connections.pytest_connector import get_connection

logger = get_logger(__name__)


@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """
    expected_version = os.environ.get("WAZUH_EXPECTED_VERSION")
    expected_revision = os.environ.get("WAZUH_EXPECTED_REVISION")

    return AMITesterConfig(
        expected_version=expected_version,
        expected_revision=expected_revision
    )

@pytest.mark.logs
class TestLogs:
    """Tests for Wazuh log files."""

    def test_log_files_exist(self, config: AMITesterConfig):
        """Test that all service log files exist."""
        connection = get_connection()

        failures = []

        for service_config in config.services:
            service_name = service_config.name
            for log_file in service_config.log_files:
                logger.info(f"Testing if log file exists: {log_file} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    failures.append(f"Log file {log_file} for {service_name} does not exist")
                    logger.warning(f"Log file {log_file} for {service_name} does not exist")

        if failures:
            assert False, "\n".join(failures)

    def test_logs_for_errors(self, config: AMITesterConfig):
        """Test logs for error messages."""
        connection = get_connection()
        error_patterns = config.log_error_patterns
        false_positives = config.log_false_positives

        failures = []
        skipped_logs = []

        for service_config in config.services:
            service_name = service_config.name

            for log_command in service_config.log_commands:
                logger.info(f"Checking for errors using command: {log_command} for {service_name}")

                error_patterns_str = "|".join(error_patterns)

                if "grep" in log_command:
                    command = log_command
                else:
                    command = f"{log_command} | grep -E '{error_patterns_str}'"

                exit_code, stdout, _ = connection.execute_command(command)

                if exit_code == 0 and stdout.strip():
                    lines = stdout.strip().split("\n")
                    real_errors = []

                    for line in lines:
                        is_false_positive = any(re.search(fp, line) for fp in false_positives)
                        if not is_false_positive:
                            real_errors.append(line.strip())

                    if real_errors:
                        error_msg = (
                            f"Found {len(real_errors)} errors using command '{log_command}' for {service_name}: "
                            f"{real_errors[:10]}"
                        ) + (f" and {len(real_errors) - 10} more..." if len(real_errors) > 10 else "")
                        failures.append(error_msg)
                        logger.warning(error_msg)

            for log_file in service_config.log_files:
                if not log_file:
                    continue

                logger.info(f"Checking for errors in log file: {log_file} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    skipped_logs.append(f"Log file {log_file} does not exist - skipping error check")
                    logger.warning(f"Log file {log_file} does not exist - skipping error check")
                    continue

                error_patterns_str = "|".join(error_patterns)
                grep_command = f"grep -E '{error_patterns_str}' {log_file}"

                exit_code, stdout, _ = connection.execute_command(grep_command)

                if exit_code == 0 and stdout.strip():
                    lines = stdout.strip().split("\n")
                    real_errors = []

                    for line in lines:
                        is_false_positive = any(re.search(fp, line) for fp in false_positives)

                        if not is_false_positive:
                            real_errors.append(line.strip())

                    if real_errors:
                        error_msg = f"Found {len(real_errors)} errors in log {log_file} for {service_name}: " \
                                f"{real_errors[:10]}" + \
                                (f" and {len(real_errors) - 10} more..." if len(real_errors) > 10 else "")
                        failures.append(error_msg)
                        logger.warning(error_msg)

        if skipped_logs and not failures:
            pytest.skip("\n".join(skipped_logs))

        if failures:
            assert False, "\n".join(failures)

    def test_recent_logs(self, config: AMITesterConfig):
        """Test for recent errors in logs (last 24 hours)."""
        connection = get_connection()

        error_patterns = config.log_error_patterns
        false_positives = config.log_false_positives

        failures = []
        skipped_logs = []
        warnings = []

        for service_config in config.services:
            service_name = service_config.name

            for log_command in service_config.log_commands:
                logger.info(f"Checking for recent errors using command: {log_command} for {service_name}")

                if "journalctl" in log_command and "--since" not in log_command:
                    recent_command = log_command.replace("journalctl", "journalctl --since '24 hours ago'")
                else:
                    recent_command = log_command

                error_patterns_str = "|".join(error_patterns)


                if "grep" in recent_command:
                    command = recent_command
                else:
                    command = f"{recent_command} | grep -E '{error_patterns_str}'"

                exit_code, stdout, _ = connection.execute_command(command)

                if exit_code == 0 and stdout.strip():
                    lines = stdout.strip().split("\n")
                    real_errors = []

                    for line in lines:
                        is_false_positive = any(re.search(fp, line) for fp in false_positives)
                        if not is_false_positive:
                            real_errors.append(line.strip())

                    if real_errors:
                        error_msg = (
                            f"Found recent errors using command '{recent_command}' for {service_name}: "
                            f"{real_errors[:5]}"
                        )
                        warnings.append(error_msg)
                        logger.warning(error_msg)

            for log_file in service_config.log_files:
                if not log_file:
                    continue

                logger.info(f"Checking for recent errors in log file: {log_file} for {service_name}")

                exit_code, stdout, _ = connection.execute_command(
                    f"test -f {log_file} && echo 'EXISTS' || echo 'NOT_EXISTS'"
                )

                if stdout.strip() != "EXISTS":
                    skipped_logs.append(f"Log file {log_file} does not exist - skipping recent error check")
                    logger.warning(f"Log file {log_file} does not exist - skipping recent error check")
                    continue

                command = (
                    f"find {log_file} -mtime -1 -type f -exec grep -l -E "
                    f"'{'|'.join(error_patterns)}' {{}} \\;"
                )

                exit_code, stdout, _ = connection.execute_command(command)

                if exit_code == 0 and stdout.strip():
                    files_with_errors = stdout.strip().split("\n")

                    for file_with_errors in files_with_errors:
                        error_patterns_str = "|".join(error_patterns)
                        grep_command = f"grep -E '{error_patterns_str}' {file_with_errors}"

                        exit_code, stdout, _ = connection.execute_command(grep_command)

                        if exit_code == 0 and stdout.strip():
                            lines = stdout.strip().split("\n")
                            real_errors = []

                            for line in lines:
                                is_false_positive = any(re.search(fp, line) for fp in false_positives)

                                if not is_false_positive:
                                    real_errors.append(line.strip())

                            if real_errors:
                                error_msg = f"Found recent errors in {file_with_errors}: {real_errors[:5]}"
                                warnings.append(error_msg)
                                logger.warning(error_msg)

        if skipped_logs and not failures and not warnings:
            pytest.skip("\n".join(skipped_logs))

        if warnings:
            pytest.xfail("\n".join(warnings))

        if failures:
            assert False, "\n".join(failures)

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/connections/ssh.py
#==================================================

"""
SSH connection implementation.
"""

import re
import time
from typing import Optional, Tuple

import paramiko
from paramiko.ssh_exception import SSHException
import socket

from ..config import get_logger
from .base import ConnectionInterface
from ..utils.inventory import spinner_clock

logger = get_logger(__name__)


class SSHConnection(ConnectionInterface):
    """Class for SSH connections."""

    def __init__(
        self,
        connection_id: str,
        host: str,
        username: str = "wazuh-user",
        port: int = 22,
        key_path: Optional[str] = None,
        private_key: Optional[str] = None,
    ):
        """Initialize SSH connection.

        Args:
            connection_id: Unique identifier for this connection
            host: Host to connect to
            username: SSH username
            port: SSH port
            key_path: Path to private key file
            private_key: Private key content
        """
        self._id = connection_id
        self._host = host
        self._username = username
        self._port = port
        self._key_path = key_path
        self._private_key = private_key
        self._ssh_client = None

    @property
    def id(self) -> str:
        """Get connection identifier."""
        return self._id

    @property
    def host(self) -> str:
        """Get the host address."""
        return self._host

    def connect(
        self,
        timeout: int = 30,
        ssh_common_args: Optional[str] = None,
        max_retries: int = 5,
        retry_delay: int = 30,
        **kwargs
    ) -> 'SSHConnection':
        """Connect to the remote host via SSH with retries.

        Args:
            timeout: Connection timeout in seconds for each attempt
            ssh_common_args: Additional SSH arguments
            max_retries: Maximum number of connection attempts
            retry_delay: Delay between retries in seconds
            **kwargs: Additional parameters for paramiko

        Returns:
            Self for method chaining

        Raises:
            ValueError: If neither key_path nor private_key is provided
            SSHException: If the SSH connection fails after all retries
        """
        if not self._key_path and not self._private_key:
            raise ValueError("Either key_path or private_key must be provided for SSH connection")

        if self._ssh_client is not None:
            return self

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_options = {}
        if ssh_common_args:
            # Parse SSH arguments
            if "-o StrictHostKeyChecking=no" in ssh_common_args:
                logger.debug("Setting StrictHostKeyChecking=no")
                connect_options["look_for_keys"] = False
                connect_options["allow_agent"] = False

            port_match = re.search(r"-p\s+(\d+)", ssh_common_args)
            if port_match:
                custom_port = int(port_match.group(1))
                logger.debug(f"Using custom port from SSH common args: {custom_port}")
                self._port = custom_port

        pkey = None
        if self._private_key:
            pkey = paramiko.RSAKey.from_private_key(self._private_key)

        last_exception = None
        attempts = 0

        logger.info(f"Attempting to establish SSH connection to {self._host} (max {max_retries} attempts, timeout {timeout}s per attempt)")

        while attempts < max_retries:
            attempts += 1
            try:
                conn_args = {
                    "hostname": self._host,
                    "username": self._username,
                    "port": self._port,
                    "timeout": timeout,
                    **connect_options,
                    **kwargs
                }

                # Set authentication method
                if self._key_path:
                    conn_args["key_filename"] = self._key_path
                else:
                    conn_args["pkey"] = pkey

                logger.info(f"SSH connection attempt {attempts}/{max_retries}...")
                logger.debug(f"Connection arguments: {conn_args}")
                client.connect(**conn_args)
                self._ssh_client = client
                logger.info(f"SSH connection established to {self._host} on attempt {attempts}")
                return self
            except (SSHException, socket.error, ConnectionError, TimeoutError) as e:
                last_exception = e
                logger.warning(f"SSH connection attempt {attempts} failed: {str(e)}")

                if attempts < max_retries:
                    logger.info(f"Waiting {retry_delay} seconds before next attempt...")
                    spinner_clock(retry_delay)
                else:
                    logger.error(f"All {max_retries} SSH connection attempts failed")

        raise SSHException(
            f"Could not establish SSH connection to {self._host} after {max_retries} attempts: {last_exception}"
        )

    def execute_command(
        self, command: str, sudo: bool = True
    ) -> Tuple[int, str, str]:
        """Execute a command on the remote host via SSH.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)

        Raises:
            ValueError: If no SSH connection is established
        """
        if self._ssh_client is None:
            raise ValueError("No SSH connection established, call connect first")

        if sudo and not command.startswith("sudo "):
            command = f"sudo {command}"

        logger.debug(f"Executing command: {command}")
        stdin, stdout, stderr = self._ssh_client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()

        return (
            exit_code,
            stdout.read().decode("utf-8"),
            stderr.read().decode("utf-8"),
        )

    def close(self) -> None:
        """Close the SSH connection if open."""
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
            logger.info(f"SSH connection closed to {self._host}")

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/connections/ansible.py
#==================================================

"""
Ansible-based connection implementation.
"""

import os
from typing import Optional, Tuple

from ..config import get_logger
from ..utils.inventory import get_host_connection_info
from .base import ConnectionInterface
from .ssh import SSHConnection

logger = get_logger(__name__)


class AnsibleConnection(ConnectionInterface):
    """Class to handle connections via Ansible inventory."""

    def __init__(
        self,
        inventory_path: str,
        host_id: Optional[str] = None,
        connection_id: Optional[str] = None
    ):
        """Initialize with Ansible inventory info.

        Args:
            inventory_path: Path to Ansible inventory file
            host_id: Host ID in inventory (uses first host if None)
            connection_id: Unique identifier for this connection
        """
        self._inventory_path = inventory_path
        self._host_id = host_id
        self._connection_info = None
        self._ssh_connection = None
        self._is_local = False

        if connection_id:
            self._id = connection_id
        else:
            if host_id:
                self._id = f"ansible-{host_id}"
            else:
                base_name = os.path.basename(inventory_path)
                self._id = f"ansible-{base_name}"

    @property
    def id(self) -> str:
        """Get connection identifier."""
        return self._id

    @property
    def host(self) -> Optional[str]:
        """Get the host address."""
        if self._connection_info:
            return self._connection_info.get('hostname')
        return None

    def connect(self, **kwargs) -> 'AnsibleConnection':
        """Connect to host specified in Ansible inventory.

        Args:
            **kwargs: Additional connection parameters

        Returns:
            Self for method chaining

        Raises:
            ValueError: If inventory file doesn't exist or host not found
        """
        logger.info(f"Connecting to host from Ansible inventory: {self._inventory_path}")

        self._connection_info = get_host_connection_info(
            self._inventory_path,
            self._host_id
        )

        # Check if this is a local connection
        hostname = self._connection_info.get('hostname', '')
        if hostname in ['localhost', '127.0.0.1']:
            logger.info("Detected local connection from Ansible inventory")
            self._is_local = True
            return self

        # Otherwise, create SSH connection
        self._ssh_connection = SSHConnection(
            connection_id=self.id,
            host=self._connection_info['hostname'],
            username=self._connection_info['username'],
            port=self._connection_info.get('port', 22),
            key_path=self._connection_info.get('ssh_key_file'),
        )

        # Connect via SSH
        ssh_common_args = self._connection_info.get('ssh_common_args', '')
        self._ssh_connection.connect(ssh_common_args=ssh_common_args, **kwargs)

        logger.info(f"Connected to {self._connection_info['hostname']} via Ansible inventory")
        return self

    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the target host.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)
        """
        # For local connections
        if self._is_local:
            import shlex
            import subprocess

            if sudo and not command.startswith("sudo "):
                command = f"sudo {command}"

            logger.debug(f"Executing local command: {command}")

            try:
                process = subprocess.Popen(
                    shlex.split(command),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate()
                exit_code = process.returncode
                return exit_code, stdout, stderr
            except Exception as e:
                logger.error(f"Error executing local command: {e}")
                return 1, "", str(e)

        # For SSH connections
        if self._ssh_connection:
            return self._ssh_connection.execute_command(command, sudo)

        # If no connection method available
        raise ValueError("No valid connection method available")

    def close(self) -> None:
        """Close the connection."""
        if self._ssh_connection:
            self._ssh_connection.close()
            logger.info(f"Closed connection to {self.host} from Ansible inventory")

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/connections/factory.py
#==================================================

"""
Factory module for creating appropriate connections.
"""

from typing import Optional

from ..config import AMITesterConfig, get_logger
from .base import ConnectionInterface
from .local import LocalConnection
from .ssh import SSHConnection
from .ansible import AnsibleConnection

logger = get_logger(__name__)


def create_connection(config: AMITesterConfig) -> Optional[ConnectionInterface]:
    """Create the appropriate connection type based on configuration.

    Args:
        config: Tester configuration

    Returns:
        A connection instance or None if creation fails
    """
    logger.info("Creating connection based on configuration...")

    # Local testing mode
    if config.use_local:
        logger.info("Using local connection for testing")
        return LocalConnection()

    # From Ansible inventory
    if config.ansible_inventory_path:
        logger.info(f"Creating connection from Ansible inventory: {config.ansible_inventory_path}")
        return AnsibleConnection(
            inventory_path=config.ansible_inventory_path,
            host_id=config.ansible_host_id
        )

    # Direct SSH connection
    if config.ssh_host:
        logger.info(f"Creating SSH connection to {config.ssh_host}")
        connection = SSHConnection(
            connection_id="direct-ssh",
            host=config.ssh_host,
            username=config.ssh_username,
            port=config.ssh_port,
            key_path=config.ssh_key_path,
            private_key=config.ssh_private_key
        )

        try:
            connection.connect(
                timeout=config.ssh_connect_timeout,
                max_retries=config.max_retries,
                retry_delay=config.retry_delay
            )
            return connection
        except Exception as e:
            logger.error(f"Failed to establish SSH connection: {e}")
            return None

    logger.error("No valid connection configuration provided")
    return None

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/connections/pytest_connector.py
#==================================================

"""
Connection handler for pytest integrations.
"""

from typing import Optional

from ..config import get_logger
from .base import ConnectionInterface
from .local import LocalConnection

logger = get_logger(__name__)


class ConnectionRegistry:
    """Registry of active connections that can be accessed across modules."""

    _instance: Optional[ConnectionInterface] = None

    @classmethod
    def set_active_connection(cls, connection: ConnectionInterface) -> None:
        """Set the active connection for testing.

        Args:
            connection: Connection to use for testing
        """
        cls._instance = connection
        logger.debug(f"Set active connection: {connection.id}")

    @classmethod
    def get_active_connection(cls) -> Optional[ConnectionInterface]:
        """Get the currently active connection.

        Returns:
            Active connection instance or None if not set
        """
        if cls._instance is None:
            logger.warning("No active connection found, creating a local connection")
            local_connection = LocalConnection()
            local_connection.connect()
            cls._instance = local_connection

        return cls._instance


def get_connection() -> ConnectionInterface:
    """Get the active connection for test execution.

    Returns:
        Connection interface

    Raises:
        RuntimeError: If no connection can be established
    """
    connection = ConnectionRegistry.get_active_connection()
    if not connection:
        raise RuntimeError("No active connection available for testing")
    return connection

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/connections/local.py
#==================================================

"""
Local machine connection implementation.
"""

import subprocess
import shlex
from typing import Tuple

from ..config import get_logger
from .base import ConnectionInterface

logger = get_logger(__name__)


class LocalConnection(ConnectionInterface):
    """Class to handle local machine connections."""

    def __init__(self, connection_id: str = "local"):
        """Initialize with local machine info.

        Args:
            connection_id: Unique identifier for this connection
        """
        self._id = connection_id
        self._host = "127.0.0.1"
        self._connected = False

    @property
    def id(self) -> str:
        """Get connection identifier."""
        return self._id

    @property
    def host(self) -> str:
        """Get the host address."""
        return self._host

    def connect(self, **kwargs) -> 'LocalConnection':
        """Mock method for local testing (no connection needed).

        Args:
            **kwargs: Ignored connection parameters

        Returns:
            Self for method chaining
        """
        logger.info("Local testing mode - connection not needed")
        self._connected = True
        return self

    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the local machine.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit code, stdout, stderr)
        """
        if sudo and not command.startswith("sudo "):
            command = f"sudo {command}"

        logger.debug(f"Executing command: {command}")

        try:
            # Execute the command
            process = subprocess.Popen(
                shlex.split(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            exit_code = process.returncode

            return exit_code, stdout, stderr
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return 1, "", str(e)

    def close(self) -> None:
        """Mock method for local testing."""
        logger.info("Local testing mode - no connection to close")
        self._connected = False

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/connections/base.py
#==================================================

"""
Base connection interface for all connection types.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional


class ConnectionInterface(ABC):
    """Abstract interface for all connection types."""

    @abstractmethod
    def connect(self, **kwargs) -> 'ConnectionInterface':
        """Establish connection to the target.

        Args:
            **kwargs: Connection parameters

        Returns:
            Self for method chaining
        """
        pass

    @abstractmethod
    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Execute a command on the target.

        Args:
            command: Command to execute
            sudo: Whether to execute with sudo

        Returns:
            Tuple with (exit_code, stdout, stderr)
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Close connection to the target."""
        pass

    @property
    @abstractmethod
    def id(self) -> str:
        """Get connection identifier."""
        pass

    @property
    def host(self) -> Optional[str]:
        """Get the host address."""
        return None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.id})"
#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/reporting/formatters.py
#==================================================

"""
Report formatters for different output formats.
"""

import json
from datetime import datetime

from ..config import get_logger
from .base import TestSummary, TestStatus

logger = get_logger(__name__)


def _process_error_message(message: str, debug_mode: bool = False) -> str:
    """Procesa un mensaje de error para mostrarlo de forma adecuada.

    Args:
        message: Mensaje de error a procesar
        debug_mode: Si es True, muestra el mensaje completo; si es False, lo simplifica

    Returns:
        Mensaje procesado
    """
    if not message:
        return ""

    # Get multiple errors
    if "\n" in message and any(line.strip().startswith("- ") for line in message.split("\n")):
        error_lines = []
        for line in message.split("\n"):
            line = line.strip()
            if line.startswith("- "):
                error_lines.append(line)

        if error_lines:
            return "\n".join(error_lines)

    if message.startswith("AssertionError") and "\n" in message:
        parts = message.split("AssertionError:", 1)
        if len(parts) > 1 and "\n" in parts[1]:
            error_part = parts[1].strip()
            if "\n" in error_part:
                error_lines = []
                for line in error_part.split("\n"):
                    line = line.strip()
                    if line and not line.startswith(">") and not line.startswith("E "):
                        error_lines.append(f"- {line}")

                if error_lines:
                    return "\n".join(error_lines)

    if not debug_mode and "\n" in message:
        # Get potencial errors
        potential_lines = []
        for line in message.split("\n"):
            line = line.strip()
            if line and not line.startswith(">") and not line.startswith("E "):
                potential_lines.append(line)

        if "AssertionError:" in message:
            # Get Assertion errors
            found = False
            for i, line in enumerate(potential_lines):
                if "AssertionError:" in line:
                    found = True
                    error_msg = line.split("AssertionError:", 1)[1].strip()
                    if error_msg:
                        return error_msg
                    next_lines = [l for l in potential_lines[i+1:] if l.strip()]
                    if next_lines:
                        return "\n".join(f"- {l}" for l in next_lines)
                    break

        if potential_lines:
            if len(potential_lines) == 1:
                return potential_lines[0]
            else:
                return "\n".join(f"- {line}" for line in potential_lines)

    # Debug return complete message
    if debug_mode:
        return message

    if "AssertionError:" in message:
        parts = message.split("AssertionError:", 1)
        if len(parts) > 1:
            return parts[1].strip()

    return message.split("\n")[0] if "\n" in message else message


class ReportFormatter:
    """Base class for report formatters."""

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary into report.

        Args:
            summary: Test summary to format

        Returns:
            Formatted report as string
        """
        raise NotImplementedError("Subclasses must implement format_report")


class JSONFormatter(ReportFormatter):
    """JSON report formatter."""

    def __init__(self, debug_mode=False):
        """Inicializar el formateador.

        Args:
            debug_mode: Si es True, incluye información detallada de errores
        """
        self.debug_mode = debug_mode

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary as JSON.

        Args:
            summary: Test summary to format

        Returns:
            JSON string representation of the report
        """
        summary_data = summary.to_dict()

        processed_results = []
        for result in summary.results:
            result_dict = result.to_dict()

            if result.message:
                result_dict['message'] = _process_error_message(result.message, self.debug_mode)

            processed_results.append(result_dict)

        report_data = {
            "summary": summary_data,
            "results": processed_results,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        return json.dumps(report_data, indent=2)


class MarkdownFormatter(ReportFormatter):
    """Markdown report formatter."""

    def __init__(self, debug_mode=False):
        """Inicializar el formateador.

        Args:
            debug_mode: Si es True, muestra información detallada de los errores
        """
        self.debug_mode = debug_mode

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary as Markdown.

        Args:
            summary: Test summary to format

        Returns:
            Markdown string representation of the report
        """
        markdown = f"# Wazuh VM Test Results\n\n"
        markdown += f"## Summary\n\n"
        markdown += f"**Status**: {summary.status.value}\n\n"
        markdown += f"| Metric | Count |\n"
        markdown += f"|--------|-------|\n"
        markdown += f"| Total Tests | {summary.total} |\n"
        markdown += f"| Passed | {summary.passed} |\n"
        markdown += f"| Failed | {summary.failed} |\n"
        markdown += f"| Warnings | {summary.warnings} |\n"
        markdown += f"| Skipped | {summary.skipped} |\n"

        # Group by test
        tests_by_module = {}
        for result in summary.results:
            module = result.module or "Other"
            if module not in tests_by_module:
                tests_by_module[module] = []
            tests_by_module[module].append(result)

        # Test failed with details
        if summary.failed > 0:
            markdown += f"\n## Failed Tests\n\n"

            for module, tests in tests_by_module.items():
                failed_tests = [t for t in tests if t.status == TestStatus.FAIL]
                if not failed_tests:
                    continue

                markdown += f"### {module}\n\n"
                for test in failed_tests:
                    markdown += f"**{test.name}**\n\n"
                    if test.message:
                        processed_message = _process_error_message(test.message, self.debug_mode)

                        if self.debug_mode:
                            markdown += f"```\n{processed_message}\n```\n\n"
                        else:
                            if "\n" in processed_message and any(line.startswith("- ") for line in processed_message.split("\n")):
                                markdown += "Errors found:\n\n"
                                for line in processed_message.split("\n"):
                                    markdown += f"{line}\n"
                                markdown += "\n"
                            else:
                                markdown += f"Error: `{processed_message}`\n\n"

        # Success test
        if summary.passed > 0:
            markdown += f"\n## Passed Tests\n\n"

            for module, tests in sorted(tests_by_module.items()):
                passed_tests = [t for t in tests if t.status == TestStatus.PASS]
                if not passed_tests:
                    continue

                markdown += f"### {module}\n\n"
                markdown += "- " + "\n- ".join(t.name for t in passed_tests) + "\n\n"

        # Skiped test
        if summary.skipped > 0:
            markdown += f"\n## Skipped Tests\n\n"

            for module, tests in sorted(tests_by_module.items()):
                skipped_tests = [t for t in tests if t.status == TestStatus.SKIPPED]
                if not skipped_tests:
                    continue

                markdown += f"### {module}\n\n"
                for test in skipped_tests:
                    markdown += f"**{test.name}**\n\n"
                    if test.message:
                        reason = _process_error_message(test.message, False).split("\n")[0]
                        markdown += f"Reason: `{reason}`\n\n"

        return markdown


class GithubActionsFormatter(ReportFormatter):
    """GitHub Actions compatible formatter."""

    def __init__(self, debug_mode=False):
        """Inicializar el formateador.

        Args:
            debug_mode: Si es True, muestra información detallada de los errores
        """
        self.debug_mode = debug_mode

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary for GitHub Actions.

        Args:
            summary: Test summary to format

        Returns:
            GitHub Actions compatible output format
        """
        # MarkDown format
        markdown = MarkdownFormatter(debug_mode=self.debug_mode).format_report(summary)

        # GitHub Actions format
        short_summary = f"Tests Summary: {summary.status.value} - Total: {summary.total}, Passed: {summary.passed}, Failed: {summary.failed}, Skipped: {summary.skipped}"

        github_data = (
            f"test_status={summary.status.value}\n"
            f"total_tests={summary.total}\n"
            f"passed_tests={summary.passed}\n"
            f"failed_tests={summary.failed}\n"
            f"warning_tests={summary.warnings}\n"
            f"skipped_tests={summary.skipped}\n"
            f"short_summary={short_summary}\n"
            f"summary<<EOF\n{markdown}\nEOF\n"
        )

        return github_data


class ConsoleFormatter(ReportFormatter):
    """Console (terminal) report formatter with ANSI colors."""

    # Console format
    COLORS = {
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "RED": "\033[91m",
        "GREEN": "\033[92m",
        "YELLOW": "\033[93m",
        "BLUE": "\033[94m",
        "MAGENTA": "\033[95m",
        "CYAN": "\033[96m",
        "WHITE": "\033[97m",
        "BG_RED": "\033[41m",
        "BG_GREEN": "\033[42m",
        "BG_YELLOW": "\033[43m",
        "BG_BLUE": "\033[44m",
    }

    def __init__(self, debug_mode=False, use_colors=True):
        """Inicializar el formateador.

        Args:
            debug_mode: Si es True, muestra información detallada de los errores
            use_colors: Si es True, usa colores ANSI en la salida
        """
        self.debug_mode = debug_mode
        self.use_colors = use_colors

    def _get_color(self, color_name):
        """Devuelve el código de color o una cadena vacía si no se usan colores.

        Args:
            color_name: Nombre del color en self.COLORS

        Returns:
            Código ANSI o cadena vacía
        """
        if self.use_colors:
            return self.COLORS.get(color_name, "")
        return ""

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary for console output with optional colors.

        Args:
            summary: Test summary to format

        Returns:
            Formatted console output
        """
        output = []

        output.append("\n" + "=" * 80)
        output.append(f"{self._get_color('BOLD')}Wazuh VM Test Summary{self._get_color('RESET')}")
        output.append("=" * 80)

        # Print status by color
        status_color = self._get_color("GREEN") if summary.status == TestStatus.PASS else self._get_color("RED")
        output.append(f"\nOverall Status: {status_color}{self._get_color('BOLD')}{summary.status.value}{self._get_color('RESET')}")

        # Print statistics
        output.append(f"\nTotal Tests: {summary.total}")
        output.append(f"Passed: {self._get_color('GREEN')}{summary.passed}{self._get_color('RESET')}")
        output.append(f"Failed: {self._get_color('RED')}{summary.failed}{self._get_color('RESET')}")
        output.append(f"Warnings: {self._get_color('YELLOW')}{summary.warnings}{self._get_color('RESET')}")
        output.append(f"Errors: {self._get_color('RED')}{summary.errors}{self._get_color('RESET')}")
        output.append(f"Skipped: {self._get_color('BLUE')}{summary.skipped}{self._get_color('RESET')}")

        # Group tests by module
        tests_by_module = {}
        for result in summary.results:
            module = result.module or "Other"
            if module not in tests_by_module:
                tests_by_module[module] = []
            tests_by_module[module].append(result)

        # First show failed test
        if summary.failed > 0 or summary.errors > 0:
            output.append("\n" + "-" * 80)
            output.append(f"{self._get_color('BOLD')}Failed Tests{self._get_color('RESET')}")
            output.append("-" * 80)

            for module, tests in tests_by_module.items():
                failed_tests = [t for t in tests if t.status in [TestStatus.FAIL, TestStatus.ERROR]]
                if not failed_tests:
                    continue

                output.append(f"\n{self._get_color('BOLD')}{module} Module:{self._get_color('RESET')}")
                for test in failed_tests:
                    status_color = self._get_color("RED")
                    output.append(f"  {status_color}✘ {test.name}{self._get_color('RESET')}")

                    if test.message:
                        processed_message = _process_error_message(test.message, self.debug_mode)

                        if self.debug_mode:
                            output.append(f"    {self._get_color('YELLOW')}Error details:{self._get_color('RESET')}")
                            for line in processed_message.split("\n"):
                                output.append(f"      {line}")
                        else:
                            if "\n" in processed_message:
                                output.append(f"    {self._get_color('YELLOW')}Errors found:{self._get_color('RESET')}")
                                for line in processed_message.split("\n"):
                                    if not line.startswith("- ") and line.strip():
                                        line = f"- {line}"
                                    output.append(f"      {line}")
                            else:
                                message = processed_message[:150] + "..." if len(processed_message) > 150 else processed_message
                                output.append(f"    {self._get_color('YELLOW')}→ {message}{self._get_color('RESET')}")

        # Show success tests
        if summary.passed > 0:
            output.append("\n" + "-" * 80)
            output.append(f"{self._get_color('BOLD')}Passed Tests{self._get_color('RESET')}")
            output.append("-" * 80)

            for module, tests in tests_by_module.items():
                passed_tests = [t for t in tests if t.status == TestStatus.PASS]
                if not passed_tests:
                    continue

                output.append(f"\n{self._get_color('BOLD')}{module} Module:{self._get_color('RESET')}")
                for test in passed_tests:
                    output.append(f"  {self._get_color('GREEN')}✓ {test.name}{self._get_color('RESET')}")

        # Show warnings and skipped tests
        if summary.warnings > 0 or summary.skipped > 0:
            output.append("\n" + "-" * 80)
            output.append(f"{self._get_color('BOLD')}Warnings & Skipped{self._get_color('RESET')}")
            output.append("-" * 80)

            for module, tests in tests_by_module.items():
                other_tests = [t for t in tests if t.status in [TestStatus.WARNING, TestStatus.SKIPPED]]
                if not other_tests:
                    continue

                output.append(f"\n{self._get_color('BOLD')}{module} Module:{self._get_color('RESET')}")
                for test in other_tests:
                    if test.status == TestStatus.WARNING:
                        status_symbol = f"{self._get_color('YELLOW')}⚠"
                    else:
                        status_symbol = f"{self._get_color('BLUE')}○"
                    output.append(f"  {status_symbol} {test.name}{self._get_color('RESET')}")

                    if test.message:
                        processed_message = _process_error_message(test.message, self.debug_mode)

                        if self.debug_mode and test.status == TestStatus.WARNING:
                            output.append(f"    {self._get_color('CYAN')}Warning details:{self._get_color('RESET')}")
                            for line in processed_message.split("\n"):
                                output.append(f"      {line}")
                        else:
                            if "\n" in processed_message:
                                for line in processed_message.split("\n"):
                                    output.append(f"    {self._get_color('CYAN')}→ {line[:150]}{self._get_color('RESET')}")
                            else:
                                output.append(f"    {self._get_color('CYAN')}→ {processed_message[:150]}{self._get_color('RESET')}")

        return "\n".join(output)

class TextFormatter(ReportFormatter):
    """Text report formatter without ANSI colors."""

    def __init__(self, debug_mode=False):
        """Inicializar el formateador.

        Args:
            debug_mode: Si es True, muestra información detallada de los errores
        """
        self.debug_mode = debug_mode

    def format_report(self, summary: TestSummary) -> str:
        """Format test summary as plain text without colors.

        Args:
            summary: Test summary to format

        Returns:
            Formatted text output
        """
        # Format for plain text
        console_formatter = ConsoleFormatter(debug_mode=self.debug_mode, use_colors=False)
        return console_formatter.format_report(summary)

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/reporting/manager.py
#==================================================

"""
Report manager for handling test results and generating reports.
"""

import os
from typing import Optional

from ..config import get_logger
from .base import TestResult, TestSummary, TestStatus
from .formatters import (
    ReportFormatter,
    JSONFormatter,
    MarkdownFormatter,
    GithubActionsFormatter,
    ConsoleFormatter
)

logger = get_logger(__name__)

class ReportManager:
    """Manager for handling test results and generating reports."""

    def __init__(self, debug_mode=False):
        """Initialize the report manager.

        Args:
            debug_mode: Whether to show detailed debug information
        """
        self.results = []
        self.debug_mode = debug_mode
        self.formatters = {
            "json": JSONFormatter(debug_mode=debug_mode),
            "markdown": MarkdownFormatter(debug_mode=debug_mode),
            "github": GithubActionsFormatter(debug_mode=debug_mode),
            "console": ConsoleFormatter(debug_mode=debug_mode)
        }

    def add_result(self, result: TestResult) -> None:
        """Add a test result.

        Args:
            result: Test result to add
        """
        self.results.append(result)
        logger.debug(f"Added test result: {result.name} - {result.status.value}")

    def add_pytest_result(self, nodeid: str, status: str, message: str = "",
                         duration: float = 0.0) -> None:
        """Add a test result from pytest.

        Args:
            nodeid: pytest node ID
            status: Test status string
            message: Test message or failure reason
            duration: Test duration in seconds
        """

        module_name = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
        module_name = module_name.replace("test_", "").capitalize()


        class_name = ""
        if "::" in nodeid:
            parts = nodeid.split("::")
            if len(parts) > 1 and parts[1] != "test_":
                class_name = parts[1].replace("Test", "")

        test_name = nodeid.split("::")[-1]
        test_name = test_name.replace("test_", "").replace("_", " ").capitalize()

        display_name = f"{module_name}: {test_name}"

        try:
            test_status = TestStatus(status.upper())
        except ValueError:
            if status.lower() == "passed":
                test_status = TestStatus.PASS
            elif status.lower() == "failed":
                test_status = TestStatus.FAIL
            elif status.lower() == "skipped":
                test_status = TestStatus.SKIPPED
            elif "error" in status.lower():
                test_status = TestStatus.ERROR
            elif "warn" in status.lower():
                test_status = TestStatus.WARNING
            else:
                test_status = TestStatus.ERROR

        result = TestResult(
            test_id=nodeid,
            name=display_name,
            status=test_status,
            message=message,
            duration=duration,
            module=module_name
        )
        self.add_result(result)

        status_colors = {
            TestStatus.PASS: "\033[92m",     # Green
            TestStatus.FAIL: "\033[91m",     # Red
            TestStatus.WARNING: "\033[93m",  # Yellow
            TestStatus.SKIPPED: "\033[94m",  # Blue
            TestStatus.ERROR: "\033[91m",    # Red
        }

        color = status_colors.get(test_status, "")
        reset = "\033[0m"

        logger.info(f"{color}{test_status.value}{reset} - {display_name}")

        if self.debug_mode and message and test_status != TestStatus.PASS:
            for line in message.split("\n"):
                logger.debug(f"  {line}")

    def get_summary(self) -> TestSummary:
        """Get a summary of test results.

        Returns:
            Test summary
        """
        return TestSummary(self.results)

    def generate_report(self, format_type: str = "console") -> str:
        """Generate a report in the specified format.

        Args:
            format_type: Report format type

        Returns:
            Formatted report as a string

        Raises:
            ValueError: If the format type is not supported
        """
        if format_type not in self.formatters:
            raise ValueError(f"Unsupported report format: {format_type}")

        summary = self.get_summary()
        return self.formatters[format_type].format_report(summary)

    def save_report(self, filename: str, format_type: Optional[str] = None) -> None:
        """Save a report to a file.

        Args:
            filename: Path to the output file
            format_type: Report format type (defaults to format based on file extension)

        Raises:
            ValueError: If the format type cannot be determined
        """

        if not format_type:
            ext = os.path.splitext(filename)[1].lower()
            if ext == '.json':
                format_type = 'json'
            elif ext == '.md':
                format_type = 'markdown'
            elif ext == '.github':
                format_type = 'github'
            else:
                format_type = 'console'

        if format_type == 'console':
            no_color_formatter = ConsoleFormatter(debug_mode=self.debug_mode, use_colors=False)
            report = no_color_formatter.format_report(self.get_summary())
        else:
            report = self.generate_report(format_type)

        try:
            directory = os.path.dirname(filename)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)

            logger.info(f"Report saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving report to {filename}: {e}")
            raise

    def print_report(self) -> None:
        """Print a report to the console."""
        print(self.generate_report("console"))

    def clear(self) -> None:
        """Clear all test results."""
        self.results = []

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/reporting/base.py
#==================================================

"""
Base classes and utilities for test reporting.
"""

from enum import Enum
from typing import Dict, List, Any
from datetime import datetime

from ..config import get_logger

logger = get_logger(__name__)


class TestStatus(str, Enum):
    """Possible states for a test."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class TestResult:
    """Class representing a single test result."""

    def __init__(
        self,
        test_id: str,
        name: str,
        status: TestStatus,
        message: str = "",
        duration: float = 0.0,
        module: str = "",
    ):
        """Initialize a test result.

        Args:
            test_id: Unique identifier for the test
            name: Display name of the test
            status: Test status (PASS, FAIL, etc.)
            message: Test message or failure reason
            duration: Test duration in seconds
            module: Test module name
        """
        self.id = test_id
        self.name = name
        self.status = status
        self.message = message
        self.duration = duration
        self.module = module
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary.

        Returns:
            Dictionary representation of the test result
        """
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "duration": self.duration,
            "module": self.module,
            "timestamp": self.timestamp,
        }


class TestSummary:
    """Class representing a summary of test results."""

    def __init__(self, results: List[TestResult]):
        """Initialize a test summary.

        Args:
            results: List of test results
        """
        self.results = results
        self.total = len(results)
        self.passed = sum(1 for r in results if r.status == TestStatus.PASS)
        self.failed = sum(1 for r in results if r.status == TestStatus.FAIL)
        self.warnings = sum(1 for r in results if r.status == TestStatus.WARNING)
        self.errors = sum(1 for r in results if r.status == TestStatus.ERROR)
        self.skipped = sum(1 for r in results if r.status == TestStatus.SKIPPED)

        # Determine overall status
        self.status = TestStatus.PASS
        if self.failed > 0 or self.errors > 0:
            self.status = TestStatus.FAIL
        elif self.warnings > 0:
            self.status = TestStatus.WARNING

        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary.

        Returns:
            Dictionary representation of the test summary
        """
        return {
            "status": self.status.value,
            "total": self.total,
            "pass": self.passed,
            "fail": self.failed,
            "warning": self.warnings,
            "error": self.errors,
            "skipped": self.skipped,
            "timestamp": self.timestamp,
        }

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/aws/credentials.py
#==================================================

"""
AWS Credential Manager for Wazuh VM Tester.
"""

import os
import boto3
from typing import Optional, Tuple
from enum import Enum
from botocore.exceptions import ClientError

from ..config import get_logger

logger = get_logger(__name__)


class AWSRole(Enum):
    """Roles available to assume in AWS."""
    QA = "qa"
    DEV = "dev"
    DEFAULT = "default"


class AWSCredentialsManager:
    """AWS Credential Manager."""

    def __init__(self):
        """Initializes the credential manager."""
        self.profiles = {
            'qa': os.environ.get('AWS_QA_PROFILE', 'qa'),
            'dev': os.environ.get('AWS_DEV_PROFILE', 'dev'),
            'default': os.environ.get('AWS_DEFAULT_PROFILE', 'default')
        }
        self.role_arns = {
            'qa': os.environ.get('AWS_QA_ROLE_ARN'),
            'dev': os.environ.get('AWS_DEV_ROLE_ARN')
        }
        self.is_github_actions = 'GITHUB_ACTIONS' in os.environ

    def get_credentials(self, role_type: AWSRole = AWSRole.DEFAULT) -> Tuple[str, Optional[str]]:
        """Gets the profile and role ARN based on the action type.

        Args:
            role_type: Type of role to assume (QA, DEV, DEFAULT)

        Returns:
            Tuple containing (profile, role_arn)
        """
        role_name = role_type.value

        # If we are in GitHub Actions, we use the configured ARN role
        if self.is_github_actions:
            if role_name in ['qa', 'dev'] and self.role_arns.get(role_name):
                logger.info(f"Using ARN role for {role_name} in GitHub Actions")
                return self.profiles[role_name], self.role_arns[role_name]
            else:
                logger.info("Using default credentials in GitHub Actions")
                return None, None

        # If we are local, we use the profile configured in ~/.aws/credentials
        logger.info(f"Using local profile: {self.profiles[role_name]}")
        return self.profiles[role_name], None

    def create_session(self,
                      profile: Optional[str] = None,
                      role_arn: Optional[str] = None,
                      region: str = 'us-east-1') -> boto3.Session:
        """Create a boto3 session.

        Args:
            profile: Profile to use
            role_arn: ARN of the role to assume
            region: AWS Region

        Returns:
            boto3 session
        """
        try:
            if self.is_github_actions:
                if role_arn:
                    logger.info(f"Asume role: {role_arn}")
                    sts_client = boto3.client('sts')
                    assumed_role = sts_client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName="WazuhVMTester"
                    )
                    credentials = assumed_role['Credentials']

                    return boto3.Session(
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=region
                    )
                else:
                    logger.info("Using default GitHub Actions credentials")
                    return boto3.Session(region_name=region)

            # If we are local
            if profile:
                logger.info(f"Creating a session with a local profile: {profile}")
                return boto3.Session(profile_name=profile, region_name=region)
            else:
                logger.info("Creating a session with default credentials")
                return boto3.Session(region_name=region)

        except ClientError as e:
            logger.error(f"Error creating AWS session: {e}")
            logger.info("Trying with default credentials")
            return boto3.Session(region_name=region)

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/aws/ec2.py
#==================================================

"""
EC2 client for AWS operations with role assumption support.
"""

import time
from typing import Dict, List, Optional, Any
from botocore.exceptions import ClientError

from ..config import get_logger
from .credentials import AWSCredentialsManager, AWSRole

logger = get_logger(__name__)


class EC2Client:
    """Client for managing EC2 instances."""

    def __init__(self, region: str, role_type: AWSRole = AWSRole.DEFAULT):
        """Initialize the client with the specified region.

        Args:
            region: AWS region
            role_type: Tipo de rol a asumir (QA, DEV, DEFAULT)
        """
        self.region = region
        self.credentials_manager = AWSCredentialsManager()

        profile, role_arn = self.credentials_manager.get_credentials(role_type)

        session = self.credentials_manager.create_session(profile, role_arn, region)

        self.ec2 = session.client('ec2')

        logger.info(f"EC2Client inicializado en la región {region}")
        if role_arn:
            logger.info(f"Usando rol: {role_arn}")
        elif profile:
            logger.info(f"Usando perfil: {profile}")

    def launch_instance(
        self,
        ami_id: str,
        instance_type: str = "t3.medium",
        subnet_id: Optional[str] = None,
        security_group_ids: List[str] = None,
        tags: Dict[str, str] = None,
        instance_profile: Optional[str] = None,
        key_name: Optional[str] = None,
        wait: bool = True,
        wait_timeout: int = 300,
    ) -> Optional[Any]:
        """Launch an EC2 instance from the specified AMI.

        Args:
            ami_id: AMI ID
            instance_type: EC2 instance type
            subnet_id: Subnet ID (optional)
            security_group_ids: List of security group IDs (optional)
            tags: Dictionary of instance tags (optional)
            instance_profile: Instance profile name (optional)
            key_name: Name of the key pair to use (optional)
            wait: Whether to wait for the instance to be running
            wait_timeout: Timeout in seconds for waiting

        Returns:
            EC2Instance object or None if launch fails

        Raises:
            ClientError: If there's an error launching the instance
        """
        if security_group_ids is None:
            security_group_ids = []

        if tags is None:
            tags = {}

        # Add Name
        if "Name" not in tags:
            tags["Name"] = f"wazuh-vm-test-{int(time.time())}"

        # Ensure tags are in the format expected by AWS
        formatted_tags = [{"Key": k, "Value": v} for k, v in tags.items()]

        run_args = {
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": formatted_tags,
                }
            ],
        }

        if subnet_id:
            run_args["SubnetId"] = subnet_id

        if security_group_ids:
            run_args["SecurityGroupIds"] = security_group_ids

        if instance_profile:
            run_args["IamInstanceProfile"] = {"Name": instance_profile}

        if key_name:
            run_args["KeyName"] = key_name

        try:
            logger.info(f"Launching instance from AMI {ami_id}")
            response = self.ec2.run_instances(**run_args)
            instance_id = response["Instances"][0]["InstanceId"]
            logger.info(f"Instance {instance_id} launched successfully")

            if wait:
                logger.info(f"Waiting for instance {instance_id} to be running...")
                self.ec2.get_waiter("instance_running").wait(
                    InstanceIds=[instance_id],
                    WaiterConfig={"Delay": 5, "MaxAttempts": wait_timeout // 5},
                )
                logger.info(f"Instance {instance_id} is now running")

                # Get updated instance information
                instance_info = self.get_instance_info(instance_id)
                if instance_info:
                    from ..instances.ec2_instance import EC2Instance
                    return EC2Instance(
                        instance_id=instance_id,
                        region=self.region,
                        public_ip=instance_info.get("PublicIpAddress"),
                        private_ip=instance_info.get("PrivateIpAddress"),
                    )
            else:
                from ..instances.ec2_instance import EC2Instance
                return EC2Instance(
                    instance_id=instance_id,
                    region=self.region,
                )

        except ClientError as e:
            logger.error(f"Error launching instance: {e}")
            raise

        return None

    def get_instance_info(self, instance_id: str) -> Optional[Dict]:
        """Get detailed information about an EC2 instance.

        Args:
            instance_id: EC2 instance ID

        Returns:
            Dictionary with instance information or None if not found
        """
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            reservations = response.get("Reservations", [])
            if not reservations:
                return None

            instances = reservations[0].get("Instances", [])
            if not instances:
                return None

            return instances[0]
        except ClientError as e:
            logger.error(f"Error getting instance information for {instance_id}: {e}")
            return None

    def terminate_instance(self, instance_id: str, wait: bool = True) -> bool:
        """Terminate an EC2 instance.

        Args:
            instance_id: EC2 instance ID
            wait: Whether to wait for the instance to be terminated

        Returns:
            True if termination was successful, False otherwise
        """
        try:
            logger.info(f"Terminating instance {instance_id}")
            self.ec2.terminate_instances(InstanceIds=[instance_id])

            if wait:
                logger.info(f"Waiting for instance {instance_id} to be terminated...")
                self.ec2.get_waiter("instance_terminated").wait(
                    InstanceIds=[instance_id],
                    WaiterConfig={"Delay": 5, "MaxAttempts": 60},
                )
                logger.info(f"Instance {instance_id} terminated successfully")

            return True
        except ClientError as e:
            logger.error(f"Error terminating instance {instance_id}: {e}")
            return False

    def get_ami_info(self, ami_id: str) -> Optional[Dict]:
        """Get detailed information about an AMI.

        Args:
            ami_id: AMI ID

        Returns:
            Dictionary with AMI information or None if not found
        """
        try:
            response = self.ec2.describe_images(ImageIds=[ami_id])
            images = response.get("Images", [])
            if not images:
                return None

            return images[0]
        except ClientError as e:
            logger.error(f"Error getting AMI information for {ami_id}: {e}")
            return None

    def get_ami_tags(self, ami_id: str) -> Dict[str, str]:
        """Get the tags of an AMI.

        Args:
            ami_id: AMI ID

        Returns:
            Dictionary with AMI tags
        """
        ami_info = self.get_ami_info(ami_id)
        if not ami_info or "Tags" not in ami_info:
            return {}

        return {tag["Key"]: tag["Value"] for tag in ami_info.get("Tags", [])}

    def update_instance_security_groups(
        self,
        instance_id: str,
        security_group_ids: List[str],
        append: bool = False
    ) -> bool:
        """Update the security groups of an existing EC2 instance.

        Args:
            instance_id: EC2 instance ID
            security_group_ids: List of security group IDs to assign to the instance
            append: If True, adds the security groups to existing ones. If False, replaces them.

        Returns:
            True if security groups were updated successfully, False otherwise
        """
        if not security_group_ids:
            logger.warning(f"No security groups provided to update instance {instance_id}")
            return False

        try:
            logger.info(f"{'Adding' if append else 'Setting'} security groups for instance {instance_id}")

            instance_info = self.get_instance_info(instance_id)
            if not instance_info:
                logger.error(f"Instance {instance_id} not found")
                return False

            if append:
                try:
                    current_security_groups = []
                    for sg in instance_info.get('SecurityGroups', []):
                        if 'GroupId' in sg:
                            current_security_groups.append(sg['GroupId'])

                    # Combine existing and new security groups
                    combined_groups = list(set(current_security_groups + security_group_ids))
                    security_group_ids = combined_groups

                    logger.info(f"Adding to existing security groups. Combined list: {security_group_ids}")
                except Exception as e:
                    logger.warning(f"Error getting current security groups: {e}. Will replace instead of append.")
                    append = False

            # Set new security groups
            response = self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=security_group_ids
            )

            logger.info(f"Security groups updated for instance {instance_id}: {security_group_ids}")
            return True
        except ClientError as e:
            logger.error(f"Error updating security groups for instance {instance_id}: {e}")
            return False

    def add_security_groups(
        self,
        instance_id: str,
        security_group_ids: List[str]
    ) -> bool:
        """Add security groups to an existing EC2 instance without removing existing ones.

        Args:
            instance_id: EC2 instance ID
            security_group_ids: List of security group IDs to add to the instance

        Returns:
            True if security groups were added successfully, False otherwise
        """
        return self.update_instance_security_groups(instance_id, security_group_ids, append=True)

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/aws/__init__.py
#==================================================

"""
Modules for interacting with AWS.
"""

from .ec2 import EC2Client

__all__ = ["EC2Client"]

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/strategies/ami.py
#==================================================

"""
AMI (EC2 instance) connection strategy implementation.
"""

import tempfile
import time
import os
from typing import Optional, Tuple

from ..config import AMITesterConfig, get_logger
from ..connections.base import ConnectionInterface
from ..connections.ssh import SSHConnection
from ..aws.ec2 import EC2Client
from ..aws.credentials import AWSRole
from ..utils.inventory import spinner_clock
from .base import ConnectionStrategy

logger = get_logger(__name__)


class AMIStrategy(ConnectionStrategy):
    """Strategy for testing an AMI by launching EC2 instance."""

    def __init__(self, config: AMITesterConfig):
        """Initialize strategy with configuration.

        Args:
            config: Tester configuration
        """
        super().__init__(config)
        self.instance_id = None
        self.instance_public_ip = None
        self.temp_key_name = None
        self.temp_key_path = None
        self.ec2_client = None
        self.connection = None

    def _generate_ssh_key_pair(self) -> Tuple[str, str]:
        """Generate a temporary SSH key pair and import it to AWS.

        Returns:
            Tuple containing (key_name, key_path)
        """
        # Create temporary directory for SSH key
        temp_dir = tempfile.mkdtemp()
        key_path = os.path.join(temp_dir, "wazuh_temp_key")

        # Generate SSH key pair
        os.system(f"ssh-keygen -t rsa -b 2048 -f {key_path} -N '' -q")

        # Key name
        key_name = f"wazuh-vm-test-temp-{int(time.time())}"

        try:
            if not self.ec2_client:
                aws_role = AWSRole(self.config.aws_role)
                self.ec2_client = EC2Client(region=self.config.aws_region, role_type=aws_role)

            with open(f"{key_path}.pub", "r") as f:
                public_key = f.read()

            self.ec2_client.ec2.import_key_pair(
                KeyName=key_name,
                PublicKeyMaterial=public_key.encode()
            )
            logger.info(f"Imported temporary SSH key {key_name} to AWS")
        except Exception as e:
            logger.error(f"Error importing SSH key to AWS: {e}")
            raise

        return key_name, key_path

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Launch an EC2 instance from AMI and create connection.

        Returns:
            SSH connection to the launched instance or None if launch fails
        """
        if not self.config.ami_id:
            logger.error("AMI ID not specified in configuration")
            return None

        if not self.ec2_client:
            aws_role = AWSRole(self.config.aws_role)
            self.ec2_client = EC2Client(region=self.config.aws_region, role_type=aws_role)

        if not self.config.ssh_key_path and not self.config.ssh_private_key:
            logger.info("Generating temporary SSH key pair for EC2 instance")
            self.temp_key_name, self.temp_key_path = self._generate_ssh_key_pair()
            key_name = self.temp_key_name
            key_path = self.temp_key_path
        else:
            key_name = self.config.temp_key_name
            key_path = self.config.ssh_key_path

        tags = {
            "Name": f"wazuh-vm-test-{self.config.ami_id}",
            "CreatedBy": "wazuh-vm-tester",
            "AutoTerminate": "true" if self.config.terminate_on_completion else "false",
        }

        if hasattr(self.config, 'tags') and self.config.tags:
            tags.update(self.config.tags)

        security_groups = self.config.security_group_ids or self.config.default_security_group_ids
        logger.info(f"Launching EC2 instance from AMI {self.config.ami_id} with security groups {security_groups}")

        # Launch the instance
        try:
            instance = self.ec2_client.launch_instance(
                ami_id=self.config.ami_id,
                instance_type=self.config.instance_type,
                subnet_id=self.config.subnet_id,
                security_group_ids=security_groups,
                tags=tags,
                instance_profile=self.config.instance_profile,
                key_name=key_name,
                wait=True,
                wait_timeout=self.config.launch_timeout
            )

            if not instance:
                logger.error(f"Failed to launch instance from AMI {self.config.ami_id}")
                return None

            self.instance_id = instance.instance_id
            self.instance_public_ip = instance.public_ip

            if not self.instance_public_ip:
                logger.error(f"Launched instance {self.instance_id} has no public IP address")
                self.cleanup()
                return None

            logger.info(f"Instance {self.instance_id} launched successfully (IP: {self.instance_public_ip})")

            # Wait for services to start
            wait_time = 360
            logger.info(f"Waiting {wait_time} seconds for services to start...")
            spinner_clock(wait_time)

            self.connection = SSHConnection(
                connection_id=f"ami-{self.instance_id}",
                host=self.instance_public_ip,
                username=self.config.ssh_username,
                port=self.config.ssh_port,
                key_path=key_path,
                private_key=self.config.ssh_private_key
            )

            # Connect to the instance
            try:
                self.connection.connect(
                    timeout=self.config.ssh_connect_timeout,
                    max_retries=self.config.max_retries,
                    retry_delay=self.config.retry_delay
                )

                # Test connection with basic command
                exit_code, stdout, stderr = self.connection.execute_command("whoami")

                if exit_code != 0:
                    logger.error(f"SSH connection test to instance {self.instance_id} failed: {stderr}")
                    self.cleanup()
                    return None

                logger.info(f"Successfully connected to launched instance {self.instance_id}")
                return self.connection

            except Exception as e:
                logger.error(f"Failed to connect to instance {self.instance_id}: {str(e)}")
                self.cleanup()
                return None

        except Exception as e:
            logger.error(f"Error launching instance from AMI {self.config.ami_id}: {str(e)}")
            self.cleanup()
            return None

    def cleanup(self) -> None:
        """Clean up resources after testing."""
        # Close connection if open
        if self.connection:
            try:
                self.connection.close()
                logger.info(f"Closed SSH connection to instance {self.instance_id}")
            except Exception as e:
                logger.warning(f"Error closing SSH connection: {str(e)}")

        # Terminate instance if needed
        if self.instance_id and self.config.terminate_on_completion and self.ec2_client:
            try:
                logger.info(f"Terminating instance {self.instance_id}")
                self.ec2_client.terminate_instance(
                    instance_id=self.instance_id,
                    wait=True
                )
                logger.info(f"Instance {self.instance_id} terminated successfully")
            except Exception as e:
                logger.error(f"Error terminating instance {self.instance_id}: {str(e)}")

        # Delete temporary key pair if created
        if self.temp_key_name and self.ec2_client:
            try:
                logger.info(f"Deleting temporary key pair {self.temp_key_name}")
                self.ec2_client.ec2.delete_key_pair(KeyName=self.temp_key_name)
                logger.info(f"Temporary key pair {self.temp_key_name} deleted successfully")
            except Exception as e:
                logger.error(f"Error deleting temporary key pair: {str(e)}")

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/strategies/ssh.py
#==================================================

"""
SSH connection strategy implementation.
"""

from typing import Optional

from ..config import get_logger
from ..connections.base import ConnectionInterface
from ..connections.ssh import SSHConnection
from .base import ConnectionStrategy

logger = get_logger(__name__)


class SSHStrategy(ConnectionStrategy):
    """Strategy for direct SSH connection."""

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create an SSH connection.

        Returns:
            SSH connection instance or None if connection fails
        """
        if not self.config.ssh_host:
            logger.error("SSH host not specified in configuration")
            return None

        logger.info(f"Creating SSH connection to {self.config.ssh_host}")

        try:
            connection = SSHConnection(
                connection_id="direct-ssh",
                host=self.config.ssh_host,
                username=self.config.ssh_username,
                port=self.config.ssh_port,
                key_path=self.config.ssh_key_path,
                private_key=self.config.ssh_private_key
            )

            connection.connect(
                timeout=self.config.ssh_connect_timeout,
                max_retries=self.config.max_retries,
                retry_delay=self.config.retry_delay
            )

            exit_code, stdout, stderr = connection.execute_command("whoami")

            if exit_code != 0:
                logger.error(f"SSH connection test failed: {stderr}")
                return None

            logger.info(f"Successfully connected to {self.config.ssh_host} via SSH")
            return connection

        except Exception as e:
            logger.error(f"Failed to establish SSH connection: {str(e)}")
            return None

    def cleanup(self) -> None:
        """Clean up resources after testing."""
        logger.info("Cleanup for SSH connection (no action needed)")

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/strategies/__init__.py
#==================================================

"""
Connection strategies for Wazuh VM Tester.
"""

from .base import ConnectionStrategy
from .local import LocalStrategy
from .ssh import SSHStrategy
from .ansible import AnsibleStrategy
from .ami import AMIStrategy
from .factory import StrategyFactory

__all__ = [
    "ConnectionStrategy",
    "LocalStrategy",
    "SSHStrategy",
    "AnsibleStrategy",
    "AMIStrategy",
    "StrategyFactory",
]
#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/strategies/ansible.py
#==================================================

"""
Ansible connection strategy implementation.
"""

import os
from typing import Optional

from ..config import get_logger
from ..connections.base import ConnectionInterface
from ..connections.ansible import AnsibleConnection
from .base import ConnectionStrategy

logger = get_logger(__name__)


class AnsibleStrategy(ConnectionStrategy):
    """Strategy for Ansible inventory connection."""

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create a connection from Ansible inventory.

        Returns:
            Ansible connection instance or None if creation fails
        """
        if not self.config.ansible_inventory_path:
            logger.error("Ansible inventory path not specified in configuration")
            return None

        if not os.path.exists(self.config.ansible_inventory_path):
            logger.error(f"Ansible inventory file not found: {self.config.ansible_inventory_path}")
            return None

        logger.info(f"Creating connection from Ansible inventory: {self.config.ansible_inventory_path}")

        try:
            connection = AnsibleConnection(
                inventory_path=self.config.ansible_inventory_path,
                host_id=self.config.ansible_host_id
            )

            connection.connect()

            exit_code, stdout, stderr = connection.execute_command("whoami")

            if exit_code != 0:
                logger.error(f"Ansible connection test failed: {stderr}")
                return None

            logger.info(f"Successfully connected using Ansible inventory")
            return connection

        except Exception as e:
            logger.error(f"Failed to establish connection from Ansible inventory: {str(e)}")
            return None

    def cleanup(self) -> None:
        """Clean up resources after testing."""
        logger.info("Cleanup for Ansible connection (no action needed)")

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/strategies/factory.py
#==================================================

"""
Factory for creating appropriate connection strategies.
"""

from typing import Optional

from ..config import AMITesterConfig, get_logger
from .base import ConnectionStrategy
from .local import LocalStrategy
from .ssh import SSHStrategy
from .ansible import AnsibleStrategy
from .ami import AMIStrategy

logger = get_logger(__name__)


class StrategyFactory:
    """Factory for creating connection strategies."""

    @staticmethod
    def create_strategy(config: AMITesterConfig) -> Optional[ConnectionStrategy]:
        """Create the appropriate strategy based on configuration.

        Args:
            config: Tester configuration

        Returns:
            Connection strategy instance or None if no valid strategy found
        """
        if config.use_local:
            logger.info("Using local strategy")
            return LocalStrategy(config)

        if config.ami_id:
            logger.info(f"Using AMI strategy for AMI {config.ami_id}")
            return AMIStrategy(config)

        if config.ansible_inventory_path:
            logger.info(f"Using Ansible strategy with inventory {config.ansible_inventory_path}")
            return AnsibleStrategy(config)

        if config.ssh_host:
            logger.info(f"Using SSH strategy for host {config.ssh_host}")
            return SSHStrategy(config)

        logger.error("No valid connection strategy could be determined from configuration")
        return None

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/strategies/local.py
#==================================================

"""
Local connection strategy implementation.
"""

from typing import Optional

from ..config import get_logger
from ..connections.base import ConnectionInterface
from ..connections.local import LocalConnection
from .base import ConnectionStrategy

logger = get_logger(__name__)


class LocalStrategy(ConnectionStrategy):
    """Strategy for local machine testing."""

    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create a local connection.

        Returns:
            Local connection instance
        """
        logger.info("Creating local connection for testing")

        connection = LocalConnection()
        connection.connect()

        return connection

    def cleanup(self) -> None:
        """Clean up resources after testing (no-op for local)."""
        logger.info("Cleanup for local connection (no action needed)")

#==================================================
# Archivo Python: /home/fcaffieri/wazuh-env/wazuh-virtual-machines/wazuh_vm_tester/src/vm_tester/strategies/base.py
#==================================================

"""
Base classes for connection and execution strategies.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ..config import AMITesterConfig, get_logger
from ..connections.base import ConnectionInterface

logger = get_logger(__name__)


class ConnectionStrategy(ABC):
    """Abstract base class for connection strategies."""

    def __init__(self, config: AMITesterConfig):
        """Initialize strategy with configuration.

        Args:
            config: Tester configuration
        """
        self.config = config

    @abstractmethod
    def create_connection(self) -> Optional[ConnectionInterface]:
        """Create and return a connection.

        Returns:
            Connection instance or None if creation fails
        """
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Clean up resources after testing."""
        pass


==================================================
Resumen:
Total de archivos Python procesados: 36
==================================================
