__author__ = '3ev0'

import threading
import queue
import logging
import datetime
import time
import re

from dns import query
from dns import message
from dns import reversename
import requests

from dnsmon import mongostore
from dnsmon import whois
from dnsmon import libnet

_domain_queue = queue.Queue()
_log = logging.getLogger(__name__)
_threads = []
_config = {"num_threads": 5,
           "lookup_interval": datetime.timedelta(days=1),
           "nameserver": "8.8.8.8"
        }

def configure(**kwargs):
    _config.update(kwargs)
    _log.info("Module configured:\n%r", _config)
    _log.debug("Retrieving tld list...")
    try:
        r = requests.get("https://publicsuffix.org/list/effective_tld_names.dat")
        libnet.configure(tlds=[line.strip() for line in r.text.split("\n") if len(line) and not line.startswith("/")])
    except Exception as e:
        _log.error("Could not download tld file: %s", e)

    logging.getLogger("dnsmon.whois").setLevel(logging.INFO)

def run():
    """
    Endlessly
    :return:
    """
    _log.info("Service starting")
    mongostore.configure(host="localhost", db="dnsmon")
    for i in range(_config["num_threads"]):
        t = threading.Thread(name="worker-{:d}".format(i),daemon=True, target=thread_main)
        _threads.append(t)
        t.start()
        _log.info("Thread %s started", t.name)

    _log.info("Service started")

    while True:
        if _domain_queue.empty():
            _log.info("Job queue depleted")
            _log.info("Waiting for all jobs to be finished...")
            _domain_queue.join()
            _log.info("Done")
            cnt = 0
            for domainspec in mongostore.domains(min_age=_config["lookup_interval"]):
                _domain_queue.put_nowait(domainspec)
                cnt += 1
            if not cnt:
                _log.info("No new jobs found for now, going to sleep...")
                time.sleep(60)
            else:
                _log.info("Job queue refilled with %d domainspecs", cnt)

        # Check thread health
        for t in [dead for dead in _threads if not dead.is_alive()]:
            _log.warning("Thread %s died, will restart it", t.name)
            t = threading.Thread(name=t.name, daemon=True, target=thread_main)
            t.start()
            _log.info("Thread %s started", t.name)
        time.sleep(2)
    return

def thread_main():
    while True:
        domainspec = _domain_queue.get(block=True, timeout=None) # Wait until an item is available
        try:
            _log.debug("%s: working job %r", threading.current_thread().name, domainspec)
            prevlookup = domainspec["last_lookup"]
            domainspec["last_lookup"] = datetime.datetime.now()
            statusspec = process_domainspec(domainspec)
            statusspec["prev_lookup"] = prevlookup
            cur_statuses = mongostore.domain_statuses(domainspec)
            if not cur_statuses.count():
                _log.info("No previous statuses for domain %s. Storing new status", domainspec["name"])
                statusid = mongostore.add_status(statusspec, domainspec)
            elif not compare_statuses(statusspec, cur_statuses[0]):
                 _log.debug("Status is unchanged. Not storing this status")
            else:
                _log.info("Status changed. Storing new status")
                statusid = mongostore.add_status(statusspec, domainspec)
            mongostore.save_domain(domainspec)
            _log.debug("Job finished")

        except Exception as ex:
            _log.error("%s crashed: %s", threading.current_thread().name, ex)
        finally:
            _domain_queue.task_done()
    pass

def compare_statuses(status1, status2):
    if status1["dns_state"] is not status2["dns_state"]:
        return False
    elif status1["whois_state"] is not status2["whois_state"]:
        return False
    else:
        return True

def process_domainspec(domainspec):
    wresults = whois_lookup(domainspec["name"])
    dresults = resolve_name(domainspec["name"])
    now = datetime.datetime.now()
    return {"lookup": now, "dns_state":dresults, "whois_state":wresults}


def whois_lookup(name):
    _log.info("WHOIS lookup for %s", name)
    if libnet.is_domain(name):
        name = libnet.domain_part(name)
    try:
        result = whois.lookup(name)
    except Exception as ex:
        _log.error("Whois lookup error: %s", ex)
        result = "Lookup error: {}".format(str(ex))
    else:
        _log.info("WHOIS lookup successful")
    return result


def resolve_name(name):
    _log.info("DNS resolve for %s", name)
    if libnet.is_ipaddr(name):
        name = reversename.from_address(name)
    try:
        msg = message.make_query(name, "ANY")
        resp = query.udp(msg, _config["nameserver"])
        result = [str(rr) for rr in resp.answer]
    except Exception as ex:
        _log.error("Dns resolve error: %s", ex)
        result = "Dns resolve error: {}".format(str(ex))
    else:
        _log.info("DNS resolve successful")
    return result