__author__ = 'ivo'

import flask_wtf
import wtforms

class AddDomainForm(flask_wtf.Form):
    domain_names = wtforms.TextAreaField("Domains/IPs", validators=[wtforms.validators.DataRequired()],
                                         description="Multiple domains/ips can be added separated by whitespace, newline or comma")
    description = wtforms.TextAreaField("Description", description="Any description about this domain name")
    tags = wtforms.StringField("Tags", description="Tag it and bag it! Splite multiple tags with whitespace or comma")
    submit = wtforms.SubmitField("Save")

class SearchForm(flask_wtf.Form):
    domain = wtforms.StringField("Domain/IP", description="Search by domain/IP")
    description = wtforms.StringField("Description", description="Search by string in description")
    tags = wtforms.StringField("Tags", description="Search by single or multiple tags. Split multiple tags with whitespace or comma")
    updated_since = wtforms.DateField("Last update", validators=[wtforms.validators.Optional()], description="Only entries updated in this period", format="%d-%m-%Y")
    submit = wtforms.SubmitField("Search")