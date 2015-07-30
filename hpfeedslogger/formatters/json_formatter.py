import json
import datetime


def format(message):
    msg = dict(message)
    msg['timestamp'] = datetime.datetime.isoformat(datetime.datetime.utcnow())
    return json.dumps(msg)
