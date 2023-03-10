from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import Email, EqualTo, DataRequired, Length

class BasicForm(FlaskForm):
	title = StringField('Title', validators=[DataRequired()])
	author = StringField('Author', validators=[DataRequired()])
	date = StringField('Date', validators=[DataRequired()])
	agency = StringField('News Agency', validators=[DataRequired()])
	content = TextAreaField('Context', validators=[DataRequired()])
	submit = SubmitField('Create News Item')

class SearchForm(FlaskForm):
	enrollment = StringField('Enrollment No', validators=[DataRequired()])
	submit = SubmitField('Search')

class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('Login', validators=[DataRequired()])




