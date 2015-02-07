#!/usr/bin/python

def format(message):
    return u' '.join(['{}={}'.format(name, value) for name, value in message.items() if value])
