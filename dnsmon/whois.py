__author__ = '3ev0'
"""
Whois library.
See RFC 3912
https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en#whois

We parse the key/value pairs as-is and do not try to transform to a uniformish format. This should be good enough.

Whois servers are kept in our own mongo collection.

How to deal with domain intermediaries? Like godaddy.com and markmonitor.
"""

import logging
import socket

_log = logging.getLogger(__name__)

def whois_lookup(querystr, wserver=None):

    pass

def ip_whois_lookup(querystr, wserver=None):

    pass

def as_whois_lookup(querystr, wserver=None):

    pass

def domain_whois_lookup(querystr, wserver=None):
    pass

def lookup_auth_wserver(querystr):
    WSRV_ROOT = "whois.iana.org"
    pass

def talk_whois(querystr, wserver):
    sock = socket.create_connection((wserver, 43))
    msglen = len(querystr)
    totalsent = 0
    while totalsent < msglen:
        sent = sock.send(bytes(totalsent[totalsent:], encoding="utf8"))
        totalsent += sent
    _log.debug("Request sent: %s", querystr)

    chunks = []
    chunk = sock.recv(4096)
    chunks.append(chunk)
    while len(chunk) > 0:
        chunk = sock.recv(4096)
        chunks.append(chunk)

    response = str(b"".join(chunks), encoding="utf8")
    _log.debug("Response received:\n%s", response)
    return response





