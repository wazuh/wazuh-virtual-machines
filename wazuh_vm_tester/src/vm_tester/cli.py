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

from .config import AMITesterConfig
from .utils.logger import setup_logging, get_logger
from .strategies import StrategyFactory
from .connections.pytest_connector import ConnectionRegistry
from .reporting.manager import ReportManager
from .reporting.base import TestResult, TestStatus, get_status_color, COLOR_RESET
from .reporting.collectors import ResultCollector

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
        "--instance-type", default="c5ad.xlarge", help="EC2 instance type (default: c5ad.xlarge)"
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
    # Detect if running in GitHub Actions
    is_github_actions = 'GITHUB_ACTIONS' in os.environ

    # Validate direct SSH mode arguments
    if args.ssh_host:
        if not is_github_actions and not args.ssh_key_path and "SSH_PRIVATE_KEY" not in os.environ:
            raise ValueError("SSH key path (--ssh-key-path) is required for direct SSH mode when running locally.")
        elif is_github_actions and not args.ssh_key_path and "SSH_PRIVATE_KEY" not in os.environ:
            logger.debug("No SSH key provided in GitHub Actions. A temporary key will be created automatically.")
    elif args.inventory:
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
            aws_region=args.aws_region,
        )

    return config


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

        if args.test_pattern and (args.test_pattern != "*" and args.test_pattern.lower() != "all"):
            pytest_args.extend(["-k", args.test_pattern])

        if debug_mode:
            pytest_args.extend(["-vvv", "--log-cli-level=DEBUG"])

        if args.pytest_args:
            pytest_args.extend(args.pytest_args.split())

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
                color = get_status_color(test.status)
                logger.info(f"  {color}{test.status.value}{COLOR_RESET} - {test.name}")
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
                color = get_status_color(test.status)
                logger.info(f"  {color}{test.status.value}{COLOR_RESET} - {test.name}")

        if skipped_tests:
            logger.info("Skipped tests:")
            for test in skipped_tests:
                color = get_status_color(test.status)
                logger.info(f"  {color}{test.status.value}{COLOR_RESET} - {test.name}")
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
