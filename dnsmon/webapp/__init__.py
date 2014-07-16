__author__ = 'ivo'

import flask
import logging

_config = {"host": "0.0.0.0",
           "port": "80"}
_log = logging.getLogger(__name__)

def configure(**kwargs):
    _config.update(**kwargs)

def run():
    app = flask.Flask(__name__)
    app.run(host=_config["host"], port=int(_config["port"]), debug=True)
    _log.info("Webapp started")

