from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email
from models import User
from wtforms.validators import Regexp

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password'), Length(min=6, max=20)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('Username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EmailOTPForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

class VerifyEmailOTPForm(FlaskForm):
    otp_input = StringField('Enter OTP', validators=[
        DataRequired(),
        Regexp(r'^\d{6}$', message='Invalid OTP format. Please enter a 6-digit code.')
    ])
    submit = SubmitField('Verify OTP')

class VerifyTOTPForm(FlaskForm):
    otp_input = StringField('Enter OTP', validators=[
        DataRequired(),
        Regexp(r'^\d{6}$', message='Invalid OTP format. Please enter a 6-digit code.')
    ])
    submit = SubmitField('Verify OTP')
