import logging

logger = None

def init_logging(verbose):
    global logger

    if verbose:
        loggingLevel = logging.DEBUG
    else:
        loggingLevel = logging.INFO

    logger = logging.getLogger('gpotraillog')
    logger.setLevel(loggingLevel)

    consoleLogger = logging.StreamHandler()
    consoleLogger.setLevel(loggingLevel)
    logger.addHandler(consoleLogger)

    logger.debug("[*] Logging initialized")