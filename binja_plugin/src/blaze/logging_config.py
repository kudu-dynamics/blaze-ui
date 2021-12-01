import json
import logging
import logging.handlers
import os
import time
from pathlib import Path
from typing import Any, Dict, cast

import binaryninja
from binaryninja.scriptingprovider import _PythonScriptingInstanceOutput

BLAZE_HOME = Path(os.environ.get('BLAZE_HOME', Path.home() / '.local/share/blaze'))
BLAZE_LOG_FILE = BLAZE_HOME / 'logs/blaze.log'

UI_LOG_FORMAT = 'Blaze: {message} [{name}:{funcName}:{lineno}]'
PACKAGE_NAME = __name__.partition('.')[0]


class BinaryNinjaUILoggingHandler(logging.Handler):
    '''
    A :py:class:`logging.Handler` which outputs records to the Binary Ninja log
    '''
    def __init__(self, level: int) -> None:
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


class ForgivingJSONEncoder(json.JSONEncoder):
    '''A :py:class:`logging.JSONEncoder` which tries to be as forgiving as possible.
    If a value cannot be serialized the usual way, replace it with a string
    which includes the value's ``repr``, and if that doesn't work, replace it
    with ``None``.

    '''
    def default(self, o: object):
        try:
            return super().default(o)
        except (TypeError, ValueError):
            try:
                return f'<unserializable: {o!r}>'
            except Exception:
                return None


class JSONFormatter(logging.Formatter):
    '''
    A :py:class:`logging.Formatter` which formats records as JSONL objects
    '''

    # https://github.com/madzak/python-json-logger/blob/e2287881/src/pythonjsonlogger/jsonlogger.py#L16-L22
    RESERVED_LOGRECORD_ATTRS = {
        'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename', 'funcName', 'levelname',
        'levelno', 'lineno', 'module', 'msecs', 'message', 'msg', 'name', 'pathname', 'process',
        'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName'
    }

    def format(self, record: logging.LogRecord) -> str:
        '''
        Format ``record`` as a string-serialized JSONL object
        '''

        out: Dict[str, Any] = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'message': record.getMessage(),
            'exception': self.formatException(record.exc_info) if record.exc_info else None,
            'logger': record.name,
            'path': record.pathname,
            'function': record.funcName,
            'line': record.lineno,
            'pid': record.process,
            'process_name': record.processName,
            'thread_name': record.threadName,
            'uptime': record.relativeCreated / 1000,
            'extra':
                {
                    k: v
                    for (k, v) in record.__dict__.items()
                    if k not in self.RESERVED_LOGRECORD_ATTRS
                },
        }

        return json.dumps(out, cls=ForgivingJSONEncoder)

    def formatTime(self, record: logging.LogRecord) -> str:
        '''
        Format ``record.created`` in approximately IEEE 8601 datetime format with time
        zone, plus milliseconds
        Example: ``'2021-06-17T12:13:14,034-0400'``
        '''

        t = time.localtime(record.created)
        return f'{time.strftime("%Y-%m-%dT%H:%M:%S", t)},{int(record.msecs):03}{time.strftime("%z", t)}'


def setup_logging(log_path: Path = BLAZE_LOG_FILE) -> None:
    ui_handler = BinaryNinjaUILoggingHandler(level=logging.INFO)
    # Keep format concise for UI log
    ui_formatter = logging.Formatter(UI_LOG_FORMAT, style='{')
    ui_handler.setFormatter(ui_formatter)

    blaze_ui_log = logging.getLogger(PACKAGE_NAME)
    blaze_ui_log.level = min(logging.DEBUG, blaze_ui_log.level)
    blaze_ui_log.addHandler(ui_handler)

    # Rotate log files once they reach 500 kB
    log_path.parent.mkdir(parents=True, exist_ok=True)
    debug_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=100)
    debug_formatter = JSONFormatter()
    debug_handler.setFormatter(debug_formatter)
    # Log all blaze messages, and any other messages that are >= INFO
    debug_handler.addFilter(
        lambda record: \
            record.name.partition('.')[0] == PACKAGE_NAME or record.levelno >= logging.INFO)

    root_debug_log = logging.root
    root_debug_log.level = min(logging.DEBUG, root_debug_log.level)
    root_debug_log.addHandler(debug_handler)

    # HACK to remove the bad default handler in Qt 6 version of Binary Ninja
    # see https://gitlab/blaze/blaze-ui/-/issues/83#note_23631
    for handler in root_debug_log.handlers[:]:
        print(handler)
        if isinstance(handler, logging.StreamHandler) and \
                isinstance(handler.stream, _PythonScriptingInstanceOutput):
            print('removing %r' % handler)
            root_debug_log.removeHandler(cast(logging.Handler, handler))

    blaze_ui_log.debug('Blaze logging initialized')
