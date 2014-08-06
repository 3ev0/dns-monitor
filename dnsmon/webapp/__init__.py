__author__ = 'ivo'

import flask
from flask_bootstrap import Bootstrap
import logging
import datetime

from bson import objectid
import pymongo

from dnsmon import mongostore
from dnsmon import whois
from dnsmon.webapp import forms
from dnsmon.webapp import supportlib

_config = {"host": "0.0.0.0",
           "port": "80"}
_log = logging.getLogger(__name__)
app = flask.Flask(__name__)
app.config.from_object('webapp.config')
Bootstrap(app)

def configure(**kwargs):
    _config.update(**kwargs)

def run():
    mongostore.configure()
    app.run(host=_config["host"], port=int(_config["port"]), debug=True)
    _log.info("Webapp started")

@app.route("/")
def index():
    return flask.redirect(flask.url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    delta = datetime.timedelta(hours=6)
    stats = [s for s in mongostore.statuses(max_age=delta)]
    doms = [d for d in mongostore.domains().sort("added", pymongo.DESCENDING).limit(20)]
    for status in stats:
        try:
            dname = mongostore.domains({"_id": status["domain_id"]})[0]["name"]
        except IndexError:
            dname = "unknown"
        status["domain_name"] = dname
    return flask.render_template("dashboard.html", interval=delta, statuses=stats, domains=doms)

@app.route("/domains/<name>")
def domain_info(name):
    try:
        d = mongostore.domains({"name": name})[0]
    except IndexError:
        flask.abort(404)
    stats = [s for s in mongostore.domain_statuses(d)]

    return flask.render_template("domain_info.html", domain=d, statuses=stats)


@app.route("/statuses/<id>")
def status_info(id):
    try:
        req_status = mongostore.statuses({"_id": objectid.ObjectId(id)})[0]
    except IndexError:
        flask.abort(404)
    statuses = mongostore.statuses({"domain_id": req_status["domain_id"]}).sort("lookup", pymongo.DESCENDING)
    prev_status = None
    for idx in range(statuses.count()):
        if statuses[idx]["_id"] == objectid.ObjectId(id):
            if idx + 1 < statuses.count():
                prev_status = statuses[idx+1]
            break
    if not prev_status:
        whoisstr = req_status["whois_state"] if req_status["whois_state"] else "No whois info available"
        dnsstr = req_status["dns_state"] if req_status["dns_state"] else "No DNS resolve available"
    else:
        if not req_status["whois_state"]:
            whoisstr = "No whois info available"
        else:
            whoisstr = "\n".join(supportlib.strdiff(prev_status["whois_state"].split("\n"), req_status["whois_state"].split("\n")))

        if not req_status["dns_state"]:
            dnsstr = "No DNS resolve available"
        else:
            dnsstr = "\n".join(supportlib.strdiff(prev_status["dns_state"].split("\n"), req_status["dns_state"].split("\n")))

    if flask.request.args.get("display", "") == "modal":
        return flask.render_template("status_info_modal.html", status=req_status, whois=whoisstr, dns=dnsstr)
    else:
        return flask.render_template("status_info.html", status=req_status, whois=whoisstr, dns=dnsstr)


@app.route("/del/<id>")
def del_domain(id):
    try:
        result = mongostore.del_domain(id)
        result2 = mongostore.del_statuses({"domain_id": objectid.ObjectId(id)})
    except Exception as ex:
        _log.error(ex)
        flask.flash("Could not remove domain {}: {}".format(id, str(ex)))
    if int(result["n"]) > 0:
        _log.info("Domain %s removed. %d statuses removed", id, result2["n"])
        flask.flash("Domain {} removed ({:d} statuses removed)".format(id, result2["n"]), "alert-success")
    else:
        _log.warning("Domain %s could not be removed, because it does not exist", id)
        flask.flash("Domain {} could not be removed, because it does not exist".format(id), "alert-warning")
    return flask.redirect(flask.url_for("index"))

@app.route("/add", methods=["GET", "POST"])
def add_domains():
    adform = forms.AddDomainForm()
    if flask.request.method != "POST":
        return flask.render_template("add_domains.html", form=adform)

    if not adform.validate():
        flask.flash("Some input validation errors exist", "alert-danger")
        return flask.render_template("add_domains.html", form=adform)

    names = supportlib.parse_names_from_liststring(adform.domain_names.data)
    saved = []
    tags = supportlib.parse_names_from_liststring(adform.tags.data)
    for nm in names:
        domainspec = {"name": nm, "tags": tags, "description": adform.description.data}
        try:
            mongostore.save_domain(domainspec, fail_on_duplicate=True)
        except Exception as ex:
            flask.flash("{} not saved: {}".format(nm, str(ex)), "alert-danger")
        else:
            saved.append(nm)
    if len(saved):
        savedlist = "<ul><li>" + "\n</li><li>".join(saved) + "</li></ul>"
        flask.flash(flask.Markup("Domains saved:\n{}".format(savedlist)), "alert-success")

    return flask.render_template("add_domains.html", form=adform)

@app.route("/search", methods=["GET", "POST"])
def search():
    searchform = forms.SearchForm()
    if flask.request.method != "POST":
        return flask.render_template("search.html", form=searchform, domains=None)

    if not searchform.validate():
        flask.flash("Some input validation errors exist", "alert-danger")
        return flask.render_template("search.html", form=searchform)

    domainspec = {}
    if searchform.domain.data:
        domainspec["name"] = searchform.domain.data
    if searchform.description.data:
        domainspec["description"] = searchform.description.data
    if searchform.tags.data:
        domainspec["tags"] = supportlib.parse_names_from_liststring(searchform.tags.data)
    if searchform.updated_since.data:
        statuses = mongostore.statuses(max_age=datetime.datetime.now() - datetime.datetime.combine(searchform.updated_since.data, datetime.datetime.min.time()))
        dids = set([st["domain_id"] for st in statuses])
        domainspec["_id"] = {"$in": list(dids)}

    domains = mongostore.domains(domainspec).sort("added", pymongo.DESCENDING)
    return flask.render_template("search.html", form=searchform, domains=domains)


@app.template_filter()
def dtstring(dt):
    if dt is None:
        return "None"
    if type(dt) is datetime.datetime:
        return dt.strftime("%m/%d/%Y %H:%M")
    if type(dt) is datetime.timedelta:
        if dt.days >= 1:
            if dt.seconds >= 60*60:
                return "{:d} days, {:d} hours".format(dt.days, dt.seconds//(60*60))
            else:
                return "{:d} days".format(dt.days)
        elif dt.seconds >= 60*60:
            if dt.seconds % (60*60):
                return "{:d} hours, {:d} minutes".format(dt.seconds//(60*60), dt.seconds//60)
            else:
                return "{:d} hours".format(dt.seconds//(60*60))
        else:
            return "{:d} minutes".format(dt.seconds//60)

@app.route("/test")
def test():
    return flask.render_template("test.html")