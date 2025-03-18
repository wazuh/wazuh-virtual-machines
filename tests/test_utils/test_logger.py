import logging
from unittest.mock import MagicMock, patch

import pytest

from utils.logger import CustomFormatter, Logger


@pytest.fixture
def mock_logger():
    with patch.object(logging.Logger, "error") as mock_error, patch.object(
        logging.Logger, "info"
    ) as mock_info, patch.object(logging.Logger, "debug") as mock_debug:
        logger = Logger("test_logger")

        handler = MagicMock(spec=logging.StreamHandler)
        handler.level = logging.DEBUG
        handler.formatter = MagicMock(spec=CustomFormatter)
        handler.setFormatter = MagicMock(return_value=CustomFormatter())
        logger.handlers.append(handler)

        logger.mock_error = mock_error  # type: ignore
        logger.mock_info = mock_info  # type: ignore
        logger.mock_debug = mock_debug  # type: ignore

        yield logger


def test_logger_initialization(mock_logger):
    assert mock_logger.name == "test_logger"

    assert mock_logger.level == logging.DEBUG

    handler = mock_logger.handlers[0]
    assert isinstance(handler, logging.StreamHandler)

    assert isinstance(handler.formatter, CustomFormatter)


def test_logger_info_success(mock_logger):
    mock_logger.info_success("Test message")

    mock_logger.mock_info.assert_called_once_with("\33[32m✓ Test message\33[0m")


def test_logger_error(mock_logger):
    mock_logger.error("Test message")

    mock_logger.mock_error.assert_called_once_with("\33[31m✗ Test message\33[0m")


def test_logger_debug_title(mock_logger):
    mock_logger.debug_title("Test message")

    mock_logger.mock_debug.assert_called_once_with("---- \33[1mTest message\33[0m ----")
