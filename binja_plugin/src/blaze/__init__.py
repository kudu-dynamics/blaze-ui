import logging

from . import logging_config

logging_config.setup_logging()
log = logging.getLogger(__name__)

# NOTE: any modules that should make use of the above logging configuration
# (output to the BinaryNinja UI log, and jsonl to the logfile) MUST be imported
# after this line

__all__ = ['cfg', 'client_plugin', 'snaptree', 'poi']

from . import cfg, client_plugin, snaptree, poi

log.debug('Blaze initialized')
