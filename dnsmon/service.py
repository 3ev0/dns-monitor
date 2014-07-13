__author__ = '3ev0'

import threading
import queue
import logging
import datetime
import time

from dnsmon import mongostore

NUM_THREADS = 5
INTERVAL = datetime.timedelta(hours=6)

_domain_queue = queue.Queue()
_log = logging.getLogger(__name__)
_threads = []
_config = {}

def configure(**kwargs):
    _config.update(kwargs)
    _log.info("Service config updated:\n%r", _config)

def run():
    """
    Endlessly
    :return:
    """
    _log.info("Service starting")
    mongostore.configure(host="localhost", db="dnsmon")
    for i in range(NUM_THREADS):
        t = threading.Thread(name="resolveThread{:d}".format(i),daemon=False, target=thread_main)
        _threads.append(t)
        t.start()
        _log.info("Thread %r started", t)

    _log.info("Service started")

    while True:
        if _domain_queue.isempty:
            cnt = 0
            for domainspec in mongostore.domains(min_age=INTERVAL):
                _domain_queue.put_nowait(domainspec)
                cnt += 1
            _log.info("Job queue depleted, refilled with %d domainspecs", cnt)

        # Check thread health
        for t in _threads:
            if not t.is_alive():
                _log.warning("Thread %r died, will restart it", t)
                t.start()

        time.sleep(1)
    return

def thread_main():
    while True:
        domainspec = _domain_queue.get(block=True, timeout=None) # Wait until an item is available
        _log.debug("%(threadName)s: working job %r", domainspec)
        time.sleep(1)
    pass


def retrieve_IP_whois(ip):
    pass

def retrieve_domain_whois(domain):
    pass

def resolve_domain(domain):
    pass

def resolve_ip(ip):
    pass

