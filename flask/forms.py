from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app import User




class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                            validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', 
                        validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    confirm_password = PasswordField('confirm password', 
                        validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')

    def validation_username(self, username):
        # if True: 
        #     raise ValidationError('validation message') this is a blueprint
        user = User.query.filter_by(username=username.data).first()  #its coming from form
        if user:
            raise ValidationError('that user name is taken try another one')

    def validation_email(self, email):
        # if True: 
        #     raise ValidationError('validation message') this is a blueprint
        user = User.query.filter_by(email=email.data).first()  #its coming from form
        if user:
            raise ValidationError('that email name is taken try another one')

class LoginForm(FlaskForm):
    email = StringField('Email', 
                        validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')