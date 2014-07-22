__author__ = '3ev0'

import argparse
import logging
import sys
import datetime

from dnsmon import service
from dnsmon import webapp

_log = logging.getLogger()

def main():
    argparser = argparse.ArgumentParser(description="Control the dns-monitor services.")
    argparser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")

    subparser = argparser.add_subparsers(dest="service", help="Choose a service to control")
    ls_parser = subparser.add_parser("monitor", help="The service that monitors the domains.")

    webapp_parser = subparser.add_parser("webapp", help="The web application.")

    args = argparser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s|%(levelname)s|%(module)s|%(threadName)s|%(message)s")
    _log.info("Cli invoked: %s", " ".join(sys.argv))

    if args.service == "monitor":
        service.configure(num_threads=3, lookup_interval=datetime.timedelta(hours=1))
        service.run()
    elif args.service == "webapp":
        webapp.configure(host="0.0.0.0", port="8000")
        webapp.run()
    else:
        _log.error("%s not implemented", args.service)

if __name__ == "__main__":
    main()