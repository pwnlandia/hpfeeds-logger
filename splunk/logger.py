import json
import hpfeeds
import sys
import logging
from logging.handlers import RotatingFileHandler

import processors

PROCESSORS = {
    'amun.events': [processors.amun_events],
    'glastopf.events': [processors.glastopf_event,],
    'dionaea.capture': [processors.dionaea_capture,],
    'dionaea.connections': [processors.dionaea_connections,],
    'beeswarm.hive': [processors.beeswarm_hive,],
    'kippo.sessions': [processors.kippo_sessions,],
    'conpot.events': [processors.conpot_events,],
    'snort.alerts': [processors.snort_alerts,],
    'wordpot.events': [processors.wordpot_event,],
    'shockpot.events': [processors.shockpot_event,],
    'p0f.events': [processors.p0f_events,],
    'suricata.events': [processors.suricata_events,],
}

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def main():
    if len(sys.argv) < 2:
        logger.error('No config file found. Exiting')
        return 1

    logger.info('Parsing config file: %s', sys.argv[1])

    config = json.load(file(sys.argv[1]))
    host        = config['host']
    port        = config['port']
    # hpfeeds protocol has trouble with unicode, hence the utf-8 encoding here
    channels    = [c.encode('utf-8') for c in config['channels']]
    ident       = config['ident'].encode('utf-8')
    secret      = config['secret'].encode('utf-8')
    logfile     = config['log_file']

    handler = RotatingFileHandler(logfile, maxBytes=100*1024*1024, backupCount=3)
    handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    data_logger = logging.getLogger('data')
    data_logger.setLevel(logging.INFO)
    data_logger.addHandler(handler)

    logger.info('Writing events to %s', logfile)

    try:
        hpc = hpfeeds.new(host, port, ident, secret)
    except hpfeeds.FeedException, e:
        logger.error('feed exception', e)
        return 1

    logger.info('connected to %s', hpc.brokername)

    def on_message(identifier, channel, payload):
        procs = PROCESSORS.get(channel, [])
        for processor in procs:
            try:
                message = processor(identifier, payload)
            except Exception, e:
                logger.error('invalid message %s', payload)
                logger.exception(e)
                continue

            if message: 
                # TODO: log message to CIM format
                data_logger.info(message)

    def on_error(payload):
        logger.error('Error message from server: %s', payload)
        hpc.stop()

    hpc.subscribe(channels)
    try:
        hpc.run(on_message, on_error)
    except hpfeeds.FeedException, e:
        logger.error('feed exception:')
        logger.exception(e)
    except KeyboardInterrupt:
        logger.error('KeyboardInterrupt encountered, exiting ...')
    except:
        logger.error('Unknown error encountered, exiting ...')
        logger.exception(e)
    finally:
        hpc.close()
    return 0

if __name__ == '__main__':
    try: 
        sys.exit(main())
    except KeyboardInterrupt:
        logger.error('KeyboardInterrupt encountered, exiting ...')
        sys.exit(0)
