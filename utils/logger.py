import logging


class CustomFormatter(logging.Formatter):
    """
    CustomFormatter is a custom logging formatter that formats log messages with different colors based on the log level.

    Attributes:
        FMT (str): The default log message format.
        FORMATS (dict): A dictionary mapping log levels to their respective colored formats.
    """
    FMT = "{asctime} [{levelname:^7}] {name}: {message}"
    FORMATS = {
        logging.DEBUG: FMT,
        logging.INFO: f"\33[36m{FMT}\33[0m",
        logging.WARNING: f"\33[33m{FMT}\33[0m",
        logging.ERROR: f"\33[31m{FMT}\33[0m",
        logging.CRITICAL: f"\33[1m\33[31m{FMT}\33[0m",
    }

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the specified log record as text with a colored output based on the log level.
        >>> DEBUG: gray
        >>> INFO: blue
        >>> WARNING: yellow/orange
        >>> ERROR: red
        >>> CRITICAL: bold red

        Args:
            record (logging.LogRecord): The log record to be formatted.

        Returns:
            str: The formatted log record as a string.
        """
        log_fmt = self.FORMATS.get(record.levelno, self.FMT)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S", style="{")
        return formatter.format(record)


class Logger(logging.Logger):
    """
    Custom Logger class that extends the standard logging.Logger to provide additional functionality
    with colored output for different log levels.
    """
    def __init__(self, name: str):
        """
        Initialize the logger with the specified name.

        Args:
            name (str): The name of the logger.

        The logger is set to the DEBUG level and a StreamHandler with a custom formatter is added to it.
        """
        super().__init__(name)
        self.setLevel(logging.DEBUG)

        handler = logging.StreamHandler()
        handler.setFormatter(CustomFormatter())
        self.addHandler(handler)

    def info_success(self, message: str):
        """
        Logs a success message modifying the default INFO log adding a check marks in the beggining of
        the log and colored it with a green color.

        Args:
            message (str): The success message to log.
        """
        self.info(f"\33[32m✓ {message}\33[0m")

    def error(self, message: str):
        """
        Logs an error message modifying the default ERROR log with a cross symbol.

        Args:
            message (str): The error message to be logged.
        """
        super().error(f"\33[31m✗ {message}\33[0m")

    def debug_title(self, message: str):
        """
        Logs a debug message modifying the default DEBUG log with a formatted title.

        Args:
            message (str): The message to be logged as a title.
        """
        self.debug(f"---- \33[1m{message}\33[0m ----")
