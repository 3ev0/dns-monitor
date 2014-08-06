__author__ = 'ivo'

from dnsmon import mongostore
import re
import difflib

def parse_names_from_liststring(liststring):
    sep_chars = (" ",",",";","\t","\t","\r","\n")
    names = re.split("[\'\"\s\,\;]+", liststring)
    return names

def strdiff(a, b):
    d = difflib.Differ()
    results = list(d.compare(a,b))
    return results