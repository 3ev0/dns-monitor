__author__ = '3ev0'

import argparse
import logging
import sys
import datetime

from dnsmon import service
from dnsmon import webapp

_log = logging.getLogger()

def main():
    argparser = argparse.ArgumentParser(description="Control the dns-monitor service.")
    argparser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    argparser.add_argument("--nowebui", action="store_true", help="Do not start the webinterface")
    args = argparser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s|%(levelname)s|%(module)s|%(threadName)s|%(message)s")
    _log.info("Cli invoked: %s", " ".join(sys.argv))

    webapp.configure(host="0.0.0.0", port="80")
    service.configure(num_threads=3, lookup_interval=datetime.timedelta(hours=1))
    service.run()




if __name__ == "__main__":
    main()