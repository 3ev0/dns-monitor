__author__ = 'ivo'

import flask_wtf
import wtforms

class AddDomainForm(flask_wtf.Form):
    domain_names = wtforms.TextAreaField("Domains/IPs", validators=[wtforms.validators.DataRequired()],
                                         description="Multiple domains/ips can be added separated by comma, space or newline")
    description = wtforms.TextAreaField("Description", description="Any description about this domain name")
    tags = wtforms.StringField("Tags", description="Tag it and bag it!")
    submit = wtforms.SubmitField("Save")