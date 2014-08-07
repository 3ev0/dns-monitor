dns-monitor
===========
Monitor domains for DNS status changes. 

Required
========
- Tested in python 3.4. Will probably work on python 3.x. Surely not on python 2.x, deal with it. 
- mongodb + pymongo

Installation
============
1. Setup python3.4 
------------------
'sudo apt-get install python3.4' on debian-like OS)

2. Setup mongodb 
----------------
('sudo apt-get install mongodb' on debian-like OS)

3. Install this package
-----------------------
'pip install -r requirements.txt -e /path/to/this/package'

4. Optional: Install supervisord script
---------------------------------------
Supervisord is awesome for running shit as daemon service. 

'sudo apt-get install supervisor'

'cp dns-monitor/supervisor.conf /etc/supervisor/conf.d/dnsmon.conf'

Edit the supervisor conf file to your needs. 

Usage
=====
Dnsmon consists of a monitoring service and a web interface. 
Both can be started by the cli.py script using the subcommand (webapp | monitor).

Web interface
-------------
python3 dnsmon/cli.py webapp

Monitoring service
------------------
python3 dnsmon/cli.py monitor

Use -h switch for help on cli.py or any of the subcommands. 



