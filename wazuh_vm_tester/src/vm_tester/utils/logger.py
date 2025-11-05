import logging
import logging.config
from pathlib import Path

import yaml


def setup_logging(
    default_level: str = "INFO",
    config_file: str | Path | None = None,
    log_file: str | Path | None = None,
    verbose: bool = False,
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

    if verbose and default_level not in ["DEBUG", "TRACE"]:
        default_level = "DEBUG"

    if config_file and config_file.exists():
        try:
            with open(config_file) as f:
                config = yaml.safe_load(f)
            logging.config.dictConfig(config)
            return
        except Exception as e:
            print(f"Error loading logging config from {config_file}: {e}")

    # TRACE level - completely verbose logging (shows all libraries)
    trace_mode = default_level == "TRACE"
    if trace_mode:
        default_level = "DEBUG"
    else:
        # Disable detailed logs for external libraries
        loggers_to_disable = [
            "boto3",
            "botocore",
            "urllib3",
            "paramiko",
            "s3transfer",
            "filelock",
            "asyncio",
        ]

        for logger_name in loggers_to_disable:
            logging.getLogger(logger_name).setLevel(logging.WARNING)

        logging.getLogger("pip").setLevel(logging.CRITICAL)
        logging.getLogger("pip._internal").setLevel(logging.CRITICAL)
        logging.getLogger("pip._vendor").setLevel(logging.CRITICAL)
        logging.getLogger("distutils").setLevel(logging.CRITICAL)
        logging.getLogger("setuptools").setLevel(logging.CRITICAL)
        logging.getLogger("subprocess").setLevel(logging.CRITICAL)

    handlers = {"console": {"class": "logging.StreamHandler", "formatter": "standard", "level": default_level}}

    if log_file:
        log_file_path = Path(log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

        handlers["file"] = {
            "class": "logging.FileHandler",
            "filename": str(log_file),
            "formatter": "detailed",
            "level": "DEBUG",
        }

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {"format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"},
            "detailed": {"format": "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"},
        },
        "handlers": handlers,
        "loggers": {
            "": {"handlers": list(handlers.keys()), "level": "DEBUG", "propagate": True},
            "vm_tester": {"handlers": list(handlers.keys()), "level": "DEBUG", "propagate": False},
        },
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
