__author__ = '3ev0'

import argparse
import logging
import sys

from dnsmon import service

_log = logging.getLogger()

def main():
    argparser = argparse.ArgumentParser(description="Control the dns-monitor service.")
    argparser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    argparser.add_argument("--nowebui", action="store_true", help="Do not start the webinterface")
    args = argparser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    _log.info("Cli invoked: %s", " ".join(sys.argv))

    service.configure()
    service.run()

    if not args.nowebui:
        pass

if __name__ == "__main__":
    main()