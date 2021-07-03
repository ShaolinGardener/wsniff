from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

from website.models import User

class CaptureForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=256)])
    desc = StringField("Description", validators=[DataRequired()])
    
    submit = SubmitField("Start Capture")


min_password_length = 8

class RegistrationForm(FlaskForm):
    username = StringField("Username",
        validators=[DataRequired(), Length(min=2, max=20)])
    
    password = PasswordField("Password", validators=[DataRequired(), Length(min=min_password_length)])
    confirm_password = PasswordField("Repeat Password",
        validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")


    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("There already is a user with that name. Please choose another username.");


class LoginForm(FlaskForm):
    username = StringField("Username",
        validators = [DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Login")
