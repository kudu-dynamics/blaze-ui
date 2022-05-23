import logging as _logging

from . import logging_config as _logging_config

_logging_config.setup_logging()
log = _logging.getLogger(__name__)

del _logging, _logging_config

# NOTE: any modules that should make use of the above logging configuration
# (output to the BinaryNinja UI log, and jsonl to the logfile) MUST be imported
# after this line

__all__ = ['cfg', 'client_plugin', 'snaptree', 'poi']

from . import cfg, client_plugin, poi, snaptree

log.debug('Blaze initialized')
