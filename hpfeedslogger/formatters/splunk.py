#!/usr/bin/python

def format(message):

    outmsg = dict(message)
    
    if 'src_ip' in outmsg:
        outmsg['src'] = outmsg['src_ip']
        del outmsg['src_ip']

    if 'dest_ip' in outmsg:
        outmsg['dest'] = outmsg['dest_ip']
        del outmsg['dest_ip']

    return u', '.join([u'{}="{}"'.format(name, unicode(value).replace('"', '\\"')) for name, value in outmsg.items() if value])
