dns-monitor
===========
Monitor domains for DNS status changes. 

Required
========
- Tested in python 3.4. Will probably work on python 3.x. Surely not on python 2.x, deal with it. 
- mongodb + pymongo

Installation
============
This program assumes the mongodb is running on localhost. 
1. Setup python3.4 ('sudo apt-get install python3.4' on debian-like OS)
2. Setup mongodb ('sudo apt-get install mongodb' on debian-like OS)
3. Setup dns-monitor:
    pip3 install -r requirements -e <path/to/dns-monitor>
    
Usage
=====
The monitoring daemon and web application need to be started separately, but can be started using the same script. 
python3 dnsmon/cli.py monitor
and
python3 dnsmon/cli.py webapp




