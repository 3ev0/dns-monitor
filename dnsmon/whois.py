__author__ = '3ev0'
"""
Whois library.
See RFC 3912
https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en#whois

We parse the key/value pairs as-is and do not try to transform to a uniformish format. This should be good enough.

How to deal with domain intermediaries? This is, afaik, limited to .com, .edu and .net domains.
For these domains we do a second referal to get the more detailed whois data.
"""

import re
import logging
import socket
import threading
import datetime
import time

from . import libnet

_log = logging.getLogger(__name__)
_lock = threading.Lock()
_auth_wserver_cache = {}
_whois_root = "whois.iana.org"
_last_queried = {}
_last_queried_lock = threading.RLock()
_config = {"min_query_interval": 0.5}

def configure(**kwargs):
    _config.update(kwargs)
    _log.info("Module configured: %s", _config)

def repr_records(whoisdata):
    lines = []
    for record in whoisdata:
        for k in sorted(record):
            values = record[k].split("\n")
            for val in values:
                lines.append("{}:   {}".format(k, val))
        lines.append("")
    return "\n".join(lines)


def domain_lookup(domain, wserver=None, raw=False):
    if not libnet.is_domain(domain):
        raise ValueError("%s is not a valid domain", domain)

    if len(domain.strip(".").split(".")) is 1:
        tld = domain.split(".")[-1]
        whoisdata = _talk_whois(_whois_root, "."+tld)
    else:
        if not wserver:
            wserver = _get_auth_wserver_domain(domain)
        whoisdata = _talk_whois(wserver, domain)
    if raw:
        return whoisdata
    else:
        return _parse_whois_response(whoisdata)


def lookup(querystr, wserver=None, raw=False):
    if libnet.is_domain(querystr):
        return domain_lookup(querystr, wserver, raw)
    elif libnet.is_ipaddr(querystr):
        return ip_lookup(querystr, wserver, raw)
    elif libnet.is_asnum(querystr):
        return ip_lookup(querystr, wserver, raw)
    else:
        raise ValueError(querystr, "Should be domain, ip or asnum")
    pass


def ip_lookup(querystr, wserver=None, raw=False):
    if not libnet.is_ipaddr(querystr) and not libnet.is_asnum(querystr):
        raise ValueError("%s is not a valid IP-address or ASnum", querystr)

    if not wserver:
        wserver = _get_auth_wserver(querystr)
    if wserver == "whois.arin.net":  # ofcourse, the yanks need some special switches
        querystr = "+ " + querystr
    elif wserver == "whois.ripe.net":  # no special query needed
        pass
    elif wserver == "whois.apnic.net":  # no special query needed
        pass
    elif wserver == "whois.afrinic.net":  # no special query needed
        pass
    elif wserver == "whois.lacnic.net":  # no special query needed
        pass
    if raw:
        return _talk_whois(wserver, querystr)
    else:
        return _parse_whois_response(_talk_whois(wserver, querystr))


def _parse_whois_response(response):
    """
    Dealing with the many many different interpretations of the whois response format.
    If an empty line is encountered, start a new record
    If a line with a semicolon is encountered, treat everything before first : as key and start a value
    If a line without semicolon is encountered when value is started, add it to current value.
    If a line without semicolon is encountered before value is started, skip it.
    :param response: the raw response to parse
    :return:a list of records containg (key, value) tuples
    """
    newkvre = re.compile("^(\s*)([^\>\%\s][^:]+):(\s*(.*))?$")
    commre = re.compile("^\s*[\%\>\@\;].*$")
    records = []
    currecord, curkey = {}, None
    comment = False
    for line in response.splitlines():
        if line.strip() is "":
            comment = False
            if len(currecord):
                records.append(currecord)
            currecord, curkey = {}, None
            continue
        if comment:
            continue
        match = newkvre.match(line)
        matchcomm = commre.match(line)
        if match and matchcomm is None:
            curkey = match.group(2)
            val = match.group(4) if match.group(4) else ""
            if curkey in currecord:
                currecord[curkey] += "\n" + val
            else:
                currecord[curkey] = val
        elif matchcomm:  # part of comments
            comment = True
            continue
        elif match is None and curkey:  # this is likely part of multiline value
            currecord[curkey] += "\n" + line.strip()
        else:
            comment = True
            continue  # this is likely start of comments
    if len(currecord):
        records.append(currecord)
    _log.debug("Response parsed succesfully. %d records", len(records))
    return records


def _talk_whois(wserver, querystr):
    _delay(wserver)
    sock = socket.create_connection((wserver, 43))
    _log.debug("Connected to %s", wserver)
    queryblob = bytes(querystr + "\r\n", encoding="utf8", errors="replace")
    msglen = len(querystr)
    totalsent = 0
    while totalsent < msglen:
        sent = sock.send(queryblob[totalsent:])
        totalsent += sent
    _log.debug("Request sent: %s", querystr)

    chunks = []
    chunk = sock.recv(4096)
    chunks.append(chunk)
    while len(chunk) > 0:
        chunk = sock.recv(4096)
        chunks.append(chunk)

    response = str(b"".join(chunks), encoding="utf8", errors="replace")
    _log.debug("Response received:\n%s", response)
    return response


def _get_cached_wserver(key):
    with _lock:
        wserver = _auth_wserver_cache.get(key, None)
        if wserver:
            _log.debug("Cache hit on %s: %s", key, wserver)
        else:
            _log.debug("Cache miss on %s", key)
        return wserver


def _cache_wserver(domain, wserver):
    with _lock:
        _auth_wserver_cache[domain] = wserver


def _get_auth_wserver_domain(domain):
    """
    Return the authorative whois server for the domain. It queries the global iana whois server and finds the referal
    whois server for the TLD of this domain
    :param domain: The domain for which the whois server should be found
    :return:the domain name of the whois server for this domain
    """
    tld = domain.split(".")[-1]
    _log.debug("looking up authorative wserver for %s (tld: %s)", domain, tld)
    auth_wserver = _get_cached_wserver(tld)

    if not auth_wserver:
        respdata = _parse_whois_response(_talk_whois(_whois_root, "."+tld))
        for record in respdata:
            if "whois" in record:
                auth_wserver = record["whois"]
                _cache_wserver(tld, auth_wserver)
                break

    if not auth_wserver:
        _log.error("Could not determine auth whois server for %s", domain)
        raise Exception("Could not determine auth whois server for {}".format(domain))

    # Special case. There is a second tier authorative server for .com .edu and .net
    if auth_wserver == "whois.verisign-grs.com":
        _log.debug("Looking up intermediary authorative wserver for %s", domain)
        respdata = _parse_whois_response(_talk_whois(auth_wserver, "=" + domain))
        for record in respdata:
            if "Domain Name" in record:
                auth_wserver = record["Whois Server"]
                break

    _log.debug("Found authorative whois server: %s", auth_wserver)
    return auth_wserver


def _get_auth_wserver(querystr):
    """
    Return the authorative whois server for this request. It queries the global iana whois server and finds the referal
    whois server for the query.
    :param querystr: The IP or ASnum for which the whois server should be found
    :return:the address of the whois server for this query string
    """
    _log.debug("looking up authorative wserver for %s", querystr)
    auth_wserver = _get_cached_wserver(querystr)
    if auth_wserver:
        return auth_wserver
    respdata = _parse_whois_response(_talk_whois(_whois_root, querystr))
    try:
        auth_wserver = respdata[0]["refer"]
    except (KeyError, IndexError) as e:
        auth_wserver = None

    if not auth_wserver:
        _log.error("Could not determine auth whois server for %s", querystr)
        raise Exception("Could not determine auth whois server for {}".format(querystr))
    _cache_wserver(querystr, auth_wserver)

    _log.debug("Found authorative whois server: %s", auth_wserver)
    return auth_wserver

def _delay(wserver):
    """
    This forces threads to delay a preconfigured interval before querying the specified whois server again.
    The thread that holds the wserver lock does not release until at least interval seconds have passed since last release.
    :param wserver: The wserver for which the thread should delay
    :return:
    """
    with _last_queried_lock:
        if wserver not in _last_queried:
            _last_queried[wserver] = [threading.RLock(), 0]

    with _last_queried[wserver][0]:
        interval = datetime.datetime.now().timestamp() - _last_queried[wserver][1]
        sleep_time = _config["min_query_interval"] - interval
        if sleep_time > 0:
            _log.debug("%s Delaying to query %s: %f seconds...", threading.current_thread().name, wserver, sleep_time)
            time.sleep(sleep_time)
        _last_queried[wserver][1] = datetime.datetime.now().timestamp()


