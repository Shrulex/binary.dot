from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

users = {}

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

    def validate_email(self, email):
        if email.data not in users:
            raise ValidationError('Unknown email address')

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        from app import users
        if email.data in users:
            raise ValidationError('Email already taken.')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

        
@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if check_password_hash(users[form.email.data], form.password.data):
            flash('Login successful.')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your email and password.')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        users[form.email.data] = generate_password_hash(form.password.data)
        flash('Signup successful.')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        if email in users:
            reset_token = secrets.token_hex(16)
            users[email]['reset_token'] = reset_token
            # Send reset token to user's email address
            flash('An email has been sent to you with a password reset link.')
            return redirect(url_for('login'))
        else:
            flash('Unknown email address.')
    return render_template('forgot-password.html', form=form)
if __name__ == '__main__':
    app.run(debug=True)