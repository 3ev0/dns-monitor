__author__ = 'ivo'
"""
Library for handy network functions.

The tld list is kept up-to-date online.
Download it from:
https://publicsuffix.org/list/effective_tld_names.dat
"""
import re
import logging

_domain_re = re.compile("([a-z0-9\-](\.[a-z0-9\-]+)*)*\.[a-z][a-z0-9]*", re.I)
_ip_re = re.compile("[0-9]{1,3}(\.[0-9]{1,3}){3}")
_ip6_re = re.compile("^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$")
_asnum_re = re.compile("(as|AS)[0-9]{1,6}")
_log = logging.getLogger(__name__)
_config = {"tlds":[]}

def configure(**kwargs):
    _config.update(kwargs)
    _log.info("MOdule configured: %s", _config)

def domain_part(name):
    if not len(_config["tlds"]):
        _log.warning("This function depends on tld list, but it is not configured.")
    result = name
    parts = name.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in _config["tlds"]:
            if i <= 1:
                break
            else:
                result = ".".join(parts[i-1:])
                break
    return result


def is_domain(argstr):
    return _domain_re.match(argstr) is not None


def is_ipaddr(argstr):
    return _ip_re.match(argstr) is not None or _ip6_re.match(argstr) is not None


def is_asnum(argstr):
    return _asnum_re.match(argstr) is not None

