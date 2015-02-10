
import json
import traceback
import urlparse
import socket

class ezdict(object):
    def __init__(self, d):
        self.d = d
    def __getattr__(self, name):
        return self.d.get(name, None)

def create_message(event_type, identifier, src_ip, dst_ip, 
    src_port=None, dst_port=None, transport='tcp', protocol='ip', vendor_product=None, 
    direction=None, ids_type=None, severity=None, signature=None, app=None):
    return {
        'type':   event_type, 
        'sensor': identifier, 
        'src_ip': src_ip,
        'dest_ip': dst_ip,
        'src_port': src_port,
        'dest_port': dst_port,
        'transport': transport,
        'protocol': protocol,
        'vendor_product': vendor_product,
        'direction': direction,
        'ids_type': ids_type,
        'severity': severity,
        'signature': signature,
        'app': app,
    }

def glastopf_event(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing glastopf event'
        traceback.print_exc()
        return None 

    if dec.pattern == 'unknown': 
        return None

    return create_message(
        'glastopf.events', 
        identifier, 
        src_ip=dec.source[0], 
        src_port=dec.source[1], 
        dst_ip=None,
        dst_port=80,
        vendor_product='Glastopf',
        app='glastopf',
        direction='inbound',
        ids_type='network',
        severity='high',
    )

def dionaea_capture(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing dionaea event'
        traceback.print_exc()
        return
    return create_message(
        'dionaea.capture', 
        identifier, 
        src_ip=dec.saddr, 
        dst_ip=dec.daddr,
        src_port=dec.sport, 
        dst_port=dec.dport,
        vendor_product='Dionaea',
        app='dionaea',
        direction='inbound',
        ids_type='network',
        severity='high',
        # TODO: pull out md5 and sha512 and do something with it
    )

def dionaea_connections(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing dionaea connection'
        traceback.print_exc()
        return
    return create_message(
        'dionaea.connections', 
        identifier, 
        src_ip=dec.remote_host, 
        dst_ip=dec.local_host,
        src_port=dec.sport, 
        dst_port=dec.dport,
        vendor_product='Dionaea',
        app='dionaea',
        direction='inbound',
        ids_type='network',
        severity='high',
    )

def beeswarm_hive(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing beeswarm.hive event'
        traceback.print_exc()
        return
    return create_message(
        'beeswarm.hive', 
        identifier, 
        src_ip=dec.attacker_ip, 
        dst_ip=dec.honey_ip,
        src_port=dec.attacker_source_port, 
        dst_port=dec.honey_port,
        vendor_product='Beeswarm',
        app='beeswarm',
        direction='inbound',
        ids_type='network',
        severity='high',
    )

def kippo_sessions(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing kippo event'
        traceback.print_exc()
        return
    return create_message(
        'kippo.sessions', 
        identifier, 
        src_ip=dec.peerIP, 
        dst_ip=dec.hostIP,
        src_port=dec.peerPort, 
        dst_port=dec.hostPort,
        vendor_product='Kippo',
        app='kippo',
        direction='inbound',
        ids_type='network',
        severity='high',
    )

def conpot_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
        remote = dec.remote[0]
        port = dec.remote[1]

        # http asks locally for snmp with remote ip = "127.0.0.1"
        if remote == "127.0.0.1":
            return
    except:
        print 'exception processing conpot event'
        traceback.print_exc()
        return

    return create_message(
        'conpot.events-'+dec.data_type, 
        identifier, 
        src_ip=remote, 
        dst_ip=dec.public_ip,
        src_port=port,
        dst_port=502,
        vendor_product='Conpot',
        app='conpot',
        direction='inbound',
        ids_type='network',
        severity='medium',
    )

def snort_alerts(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing snort alert'
        traceback.print_exc()
        return None
    return create_message(
        'snort.alerts', 
        identifier, 
        src_ip=dec.source_ip, 
        dst_ip=dec.destination_ip,
        src_port=dec.source_port, 
        dst_port=dec.destination_port,
        transport=dec.protocol,
        vendor_product='Snort',
        app='snort',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature=dec.signature,

        # TODO: pull out the other snort specific items
        # 'snort': {
        #         'header': o_data['header'],
        #         'signature': o_data['signature'],
        #         'classification': o_data['classification'],
        #         'priority': o_data['priority'],
        #     },
        #     'sensor': o_data['sensor'] # UUID
    )

def suricata_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing suricata event'
        traceback.print_exc()
        return None
    return create_message(
        'suricata.events', 
        identifier, 
        src_ip=dec.source_ip, 
        dst_ip=dec.destination_ip,
        src_port=dec.source_port, 
        dst_port=dec.destination_port,
        transport=dec.protocol,
        vendor_product='Suricata',
        app='suricata',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature=dec.signature,

        # TODO: add the suricata specific items:
        # 'suricata': {
        #         'action':         o_data['action'],
        #         'signature':      o_data['signature'],
        #         'signature_id':   o_data['signature_id'],
        #         'signature_rev':  o_data['signature_rev'],
        #     },
        #     'sensor': o_data['sensor'] # UUID
    )

def p0f_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing suricata event'
        traceback.print_exc()
        return None
    return create_message(
        'p0f.events', 
        identifier, 
        src_ip=dec.client_ip, 
        dst_ip=dec.server_ip,
        src_port=dec.client_port, 
        dst_port=dec.server_port,
        vendor_product='p0f',
        app='p0f',
        direction='inbound',
        ids_type='network',
        severity='informational',
    )
    # TODO: add other p0f specific items:
    # def get_metadata(self, o_data, submission_timestamp):
    #     metadata = {}
    #     for name in ['app', 'link', 'os', 'uptime', ]:
    #         if name in o_data and o_data[name] != '???':
    #             metadata[name] = o_data[name]
    #     if metadata:
    #         metadata['ip'] = o_data['client_ip']
    #         metadata['honeypot'] = 'p0f'
    #         metadata['timestamp'] = submission_timestamp
    #     return metadata


def amun_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing amun event'
        traceback.print_exc()
        return
    return create_message(
        'amun.events', 
        identifier, 
        src_ip=dec.attackerIP, 
        dst_ip=dec.victimIP,
        src_port=dec.attackerPort, 
        dst_port=dec.victimPort,
        vendor_product='Amun',
        app='amun',
        direction='inbound',
        ids_type='network',
        severity='high',
    )

def wordpot_event(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing wordpot alert'
        traceback.print_exc()
        return

    return create_message(
        'wordpot.alerts', 
        identifier, 
        src_ip=dec.source_ip, 
        dst_ip=dec.dest_ip,
        src_port=dec.source_port, 
        dst_port=dec.dest_port,
        vendor_product='Wordpot',
        app='wordpot',
        direction='inbound',
        ids_type='network',
        severity='high',
    )

def shockpot_event(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        print 'exception processing shockpot alert'
        traceback.print_exc()
        return None

    try:
        p = urlparse.urlparse(dec.url)
        socket.inet_aton(urlparse.urlparse(dec.url).netloc)
        dest_ip = p.netloc
    except:
        dest_ip = None

    return create_message(
        'shockpot.events', 
        identifier, 
        src_ip=dec.source_ip, 
        dst_ip=dest_ip,
        src_port=0,
        dst_port=dec.dest_port,
        vendor_product='ThreatStream Shockpot',
        app='shockpot',
        direction='inbound',
        ids_type='network',
        severity='high',
    )
