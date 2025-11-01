let log = (...data) => console.log(...data);
log.info = (...data) => console.info(...data);
log.debug = (...data) => console.debug(...data);
log.warn = (...data) => console.warn(...data);
log.error = (...data) => console.error(...data);

function setLogger(logger, verbose = false, debug = false) {
    if (!logger) return;

    if (logger.debugEnabled) {
        log = logger;
        if (typeof log.warn !== 'function') {
            log.warn = (...data) => log.info(...data);
        }
    }
    else {
        log = (...data) => logger(...data);
        log.error = (...data) => logger.error(...data);
        log.info = () => undefined;
        log.warn = (...data) => (logger.warn ? logger.warn(...data) : logger(...data));
        log.debug = () => undefined;
        if (verbose || debug) {
            log.info = (...data) => logger.info(...data);
        }

        if (debug) {
            log.debug = (...data) => logger.info(...data);
        }
    }
    module.exports.log = log;
}

module.exports = {log, setLogger};
