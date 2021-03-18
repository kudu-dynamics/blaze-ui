import logging

import binaryninja

from . import client_plugin
from . import cfg

LOG_LEVEL = logging.INFO


class BinaryNinjaUILoggingHandler(logging.Handler):
    def __init__(self, level):
        super().__init__(level)

    def emit(self, record: logging.LogRecord):
        if record.levelno >= logging.ERROR:
            binaryninja.log_error(self.format(record))
        elif record.levelno >= logging.WARN:
            binaryninja.log_warn(self.format(record))
        elif record.levelno >= logging.INFO:
            binaryninja.log_info(self.format(record))
        elif record.levelno >= logging.DEBUG:
            binaryninja.log_debug(self.format(record))
        else:
            binaryninja.log_warn(f'Unknown log level: {record.levelno} ({record.levelname})')


def setup_logging():
    for handler in list(logging.root.handlers):
        if any(t.__name__ == BinaryNinjaUILoggingHandler.__name__
               for t in handler.__class__.__mro__):
            logging.root.removeHandler(handler)

    handler = BinaryNinjaUILoggingHandler(level=LOG_LEVEL)
    formatter = logging.Formatter('Blaze: {message} [{name}:{funcName}:{lineno}]', style='{')
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)


setup_logging()
