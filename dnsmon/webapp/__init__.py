__author__ = 'ivo'

import flask
from flask_bootstrap import Bootstrap
import logging
import datetime

from dnsmon import mongostore
from dnsmon.webapp import forms

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
    delta = datetime.timedelta(days=7)
    stats = [s for s in mongostore.statuses(max_age=delta)]
    for status in stats:
        try:
            dname = mongostore.domains({"_id": status["domain_id"]})[0]["name"]
        except IndexError:
            dname = "unknown"
        status["domain_name"] = dname
    return flask.render_template("dashboard.html", interval=str(delta), statuses=stats)

@app.route("/domains/<name>")
def domain_info(name):
    try:
        d = mongostore.domains({"name": name})[0]
        stats = mongostore.domain_statuses(d)
    except IndexError:
        flask.abort(404)
    return flask.render_template("domain_info.html", domain=d, statuses=stats)

@app.route("/add", methods=["GET", "POST"])
def add_domains():
    adform = forms.AddDomainForm()
    if flask.request.method == "POST":
        if adform.validate():
            flask.flash("All Domains saved successfully", "alert-success")
            return flask.redirect(flask.url_for('add_domains'))
        else:
            flask.flash("The following domains were not saved:", "alert-danger")
            flask.flash("Second error", "alert-danger")
            return flask.render_template("add_domains.html", form=adform)
    else:
        return flask.render_template("add_domains.html", form=adform)

@app.route("/test")
def test():
    return flask.render_template("test.html")