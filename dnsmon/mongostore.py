"""
Collections:

Domains
{
    _id,
    dbver,
    name,
    added,
    last_lookup,
    tags,
    description
}

status_mutations
{
    _id,
    dbver,
    domain_id: ref Domains,
    lookup,
    prev_lookup,
    dns_state,
    whois_state,
}

"""
import datetime
import logging

import pymongo
from pymongo import MongoClient

__author__ = 'ivo'
_db_version = "0.1"

DOMAINCOL = "domains"
STATUSCOL = "status_mutations"

config = {"host": "localhost",
          "port": "27017",
          "db": "dnsmon"}

_log = None


class DomainExistsException(BaseException):
    pass


def configure(**kwargs):
    global _log
    config.update(kwargs)
    config["client"] = MongoClient(config["host"], int(config["port"]))
    _log = logging.getLogger(__name__)

    db = config["client"][config["db"]]
    _log.info("Mongodb connection configured. ")
    _log.info("Database: %r", db)
    _log.info("Collections:\n")
    for colname in db.collection_names(include_system_collections=False):
        _log.info(" %s: %d records", colname, db[colname].count())
        _log.info(" %r\n", db[colname].index_information())


def init_database():
    """
    Create indices on collections. Should be called only once in the lifetime of the database
    :return:
    """
    db = config["client"][config["db"]]
    domaincol = db[DOMAINCOL]
    domaincol.ensure_index("domain")
    domaincol.ensure_index("last_lookup")
    domaincol.ensure_index("tags")
    statuscol = db[STATUSCOL]
    statuscol.ensure_index("lookup")
    statuscol.ensure_index("dns_state")
    statuscol.ensure_index("whois_state")
    _log.debug("Database %r initialized.", db)
    return True


def domains(domainspec=None, min_age=None, num=None):
    """
    Get domains from mongodb. If min_age is provided, the domains for which a status check has not
     been performed at least min_age time ago.
    :param min_age: the minimal age of the last lookup
    :param num: the max number of domains to retrieve
    :return:list of domains
    """
    domaincol = config["client"][config["db"]][DOMAINCOL]
    rlimit = 0 if num is None else num
    if domainspec is not None:
        curs = domaincol.find(domainspec)
    elif min_age is not None:
        last_lookup = datetime.datetime.now() - min_age
        curs = domaincol.find({"$or": [{"last_lookup": {"$lt": last_lookup}}, {"last_lookup": None}]}, limit=rlimit).sort("last_lookup")
    else:
        curs = domaincol.find(limit=rlimit).sort("last_lookup")
    return curs


def save_domain(domain, fail_on_duplicate=True):
    """
    Add domain to the mongo database
    :param domain: domain to add
    :param check_duplicate: if a domain record with the same name is allready present, fail.
    :return:
    """
    _check_format(domain)
    domaincol = config["client"][config["db"]][DOMAINCOL]
    if "_id" not in domain: # performing insert
        if fail_on_duplicate and domaincol.find_one({"name": domain["name"]}):
            raise DomainExistsException("domain {} allready exists in mongodb".format(domain["name"]))
        domain["dbver"] = _db_version
        domain["added"] = datetime.datetime.now()
        domain["last_lookup"] = None
        domid = domaincol.save(domain)
        _log.debug("Added domain %r with id %s", domain, str(domid))
    else:
        domid = domaincol.save(domain)
        _log.debug("Updated domain %r", domain)
    return domid



def del_domain(domain):
    """
    Delete a domain from the mongodb.
    :param domain: dict of the domain
    :return:
    """
    _check_format(domain)
    domaincol = config["client"][config["db"]][DOMAINCOL]
    res = domaincol.remove(domain)
    _log.info("Domain %r removed from db: %r.", domain, res)
    return res


def add_status(status, domain):
    """
    :param status: The status to add
    :param domain: The domain to update
    :return:the id of the status document
    """
    _check_format(status)
    _check_format(domain)
    statuscol = config["client"][config["db"]][STATUSCOL]
    status["dbver"] = _db_version
    status["domain_id"] = domain["_id"]
    statusid = statuscol.insert(status)
    _log.debug("Added status %r with id %s", status, str(statusid))
    return statusid

def domain_statuses(domain):
    _check_format(domain)
    statuscol = config["client"][config["db"]][STATUSCOL]
    curs = statuscol.find({"domain_id": domain["_id"]}, sort=[("lookup", pymongo.DESCENDING)])
    return curs

def statuses(max_age=None):
    statuscol = config["client"][config["db"]][STATUSCOL]
    if max_age is not None:
        since = datetime.datetime.now() - max_age
        curs = statuscol.find({"lookup": {"$gt": since}}, sort=[("lookup", pymongo.DESCENDING)])
    else:
        curs = statuscol.find(sort=[("lookup", pymongo.DESCENDING)])
    return curs

def _check_format(the_arg):
    if not isinstance(the_arg, dict):
        raise ValueError("{} is not a dict".format(repr(the_arg)))