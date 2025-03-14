import logging
from unittest.mock import MagicMock, patch

import pytest

import utils
from utils.logger import CustomFormatter, Logger


@pytest.fixture
@patch.object(logging.Logger, "addHandler")
def mock_logger(mock_add_handler) -> Logger:
    logger = Logger("test_logger")
    
    logger.info = MagicMock()
    logger.debug = MagicMock()
    logger.error = MagicMock()

    handler = MagicMock(spec=logging.StreamHandler)
    handler.level = logging.DEBUG
    handler.formatter = MagicMock(spec=CustomFormatter)
    handler.setFormatter = MagicMock(return_value=CustomFormatter())
    logger.handlers.append(handler)


    return logger


def test_logger_initialization(mock_logger):
    assert mock_logger.name == "test_logger"

    assert mock_logger.level == logging.DEBUG

    handler = mock_logger.handlers[0]
    assert isinstance(handler, logging.StreamHandler)
    
    assert isinstance(handler.formatter, CustomFormatter)


def test_logger_info_success(mock_logger):

    mock_logger.info_success("Test message")

    mock_logger.info.assert_called_once_with("\33[32m✓ Test message\33[0m") 

def test_logger_use_correct_colors(mock_logger):
    pass