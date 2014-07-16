dns-monitor
===========
Monitor domains for status changes. 

Required
========
- Tested in python 3.4. Will probably work on python 3.x. Surely not on python 2.x, deal with it. 
- mongodb + pymongo

IDEA
====
Enter domain to monitor
Domainname is checked at regular interval (day?) for it's whois data and resolve data. 
This is compared to previous checked and any delta's are stored. 

A delta stores the new WHOIS and resolves. 
A diff tool should be available to visualize changes. Also over time. 

A user should be able to delete domains and IP-adresses from the monitor

Data is stored in mongodb (because i am prototyping)


