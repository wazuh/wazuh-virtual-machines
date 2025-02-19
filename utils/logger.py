import logging

class CustomFormatter(logging.Formatter):
    FMT = "[{levelname:^7}] {name}: {message}"
    FORMATS = {
        logging.DEBUG: FMT,
        logging.INFO: f"\33[36m{FMT}\33[0m",
        logging.WARNING: f"\33[33m{FMT}\33[0m",
        logging.ERROR: f"\33[31m{FMT}\33[0m",
        logging.CRITICAL: f"\33[1m\33[31m{FMT}\33[0m"
    }

    def format(self, record: logging.LogRecord) -> str:
        log_fmt = self.FORMATS.get(record.levelno, self.FMT)
        formatter = logging.Formatter(log_fmt, style="{")
        return formatter.format(record)

class Logger(logging.Logger):
    def __init__(self, name: str):
        super().__init__(name)
        self.setLevel(logging.DEBUG)
        
        handler = logging.StreamHandler()
        handler.setFormatter(CustomFormatter())
        self.addHandler(handler)

    def info_success(self, message: str):
        self.info(f"\33[32m✓ {message}\33[0m")

    def error(self, message: str):
        super().error(f"\33[31m✗ {message}\33[0m")

    def debug_title(self, message: str):
        self.debug(f"---- \33[1m{message}\33[0m ----")
    