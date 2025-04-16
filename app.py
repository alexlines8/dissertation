from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User
from forms import RegisterForm, LoginForm, EmailOTPForm, VerifyEmailOTPForm, VerifyTOTPForm
from twilio.rest import Client
import os
import random
from flask_mail import Mail, Message
from dotenv import load_dotenv
import pyotp
import qrcode
import io
import base64
import uuid
from datetime import datetime, timedelta
from flask_migrate import Migrate,upgrade


app = Flask(__name__)


bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
load_dotenv()

twilio_client = Client(os.getenv('TWILIO_ACCOUNT_SID'), os.getenv('TWILIO_AUTH_TOKEN'))
twilio_phone_number = os.getenv('TWILIO_PHONE_NUMBER')

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
db.init_app(app)
migrate = Migrate(app,db)
mail = Mail(app)



@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# Route: Enter phone number
@app.route('/sms-otp', methods=['GET', 'POST'])
@login_required
def sms_otp():
    if request.method == 'POST':
        country_code = request.form.get('country_code', '').strip()
        phone_local = request.form.get('phone', '').strip().replace(' ', '').replace('-', '')

        # Basic validation
        if not country_code or not phone_local.isdigit():
            flash('Invalid input. Please select a country and enter a valid phone number.', 'danger')
            return redirect(url_for('sms_otp'))

        full_phone = f"{country_code}{phone_local}"

        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        current_user.phone_number = full_phone
        db.session.commit()

        # Send SMS

        twilio_client.messages.create(
            body=f'Your verification code is: {otp}',
            from_=twilio_phone_number,
            to=full_phone
        )

        flash('OTP sent to your phone number.', 'success')
        return redirect(url_for('verify_sms_otp'))

    return render_template('sms_otp.html')


# Route: Verify OTP
@app.route('/verify-sms-otp', methods=['GET', 'POST'])
@login_required
def verify_sms_otp():
    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()
        if otp_input == session.get('otp'):
            current_user.sms_mfa_completed = True
            db.session.commit()
            session.pop('otp', None)  # clear OTP from session
            flash('Phone number verified successfully!', 'success')
            return redirect(url_for('home'))

        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify_sms_otp.html')


@app.route('/email-otp', methods=['GET', 'POST'])
@login_required
def email_otp():
    form = EmailOTPForm()

    if form.validate_on_submit():
        email = form.email.data.strip()

        otp = str(random.randint(100000, 999999))
        session['email_otp'] = otp
        session['email_address'] = email

        # Send email
        msg = Message('OTP for Authentication Study', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = f"""
        Hello! 
        Your verification code is: {otp}
        
        Input this code into the website to unlock the next step"""
        mail.send(msg)

        flash('OTP sent to your email address.', 'success')
        return redirect(url_for('verify_email_otp'))

    return render_template('email_otp.html', form=form)

@app.route('/verify-email-otp', methods=['GET', 'POST'])
@login_required
def verify_email_otp():
    form = VerifyEmailOTPForm()

    if form.validate_on_submit():
        otp_input = form.otp_input.data
        expected_otp = session.get('email_otp')

        if otp_input == expected_otp:
            current_user.email_mfa_completed = True
            db.session.commit()
            flash('Email OTP verified successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('verify_email_otp'))

    return render_template('verify_email_otp.html', form=form)


@app.route('/totp-setup')
@login_required
def totp_setup():
    # Generate a secret key for the user if not already
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32()
        db.session.commit()

    # Generate provisioning URI for QR code
    otp_uri = pyotp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.username,
        issuer_name='MFA App'
    )

    # Generate QR code
    qr = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    img_base64 = base64.b64encode(img_io.getvalue()).decode()

    return render_template('totp_setup.html', qr_code=img_base64)


@app.route('/verify-totp', methods=['GET', 'POST'])
@login_required
def verify_totp():
    form = VerifyTOTPForm()

    if form.validate_on_submit():
        otp_input = form.otp_input.data.strip()

        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(otp_input):
            current_user.totp_mfa_completed = True
            db.session.commit()
            flash('Authenticator app verified successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('verify_totp'))

    return render_template('verify_totp.html', form=form)




@app.route('/magic-link', methods=['GET', 'POST'])
@login_required
def magic_link():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        # Basic email validation
        if '@' not in email or '.' not in email:
            flash('Invalid email address.', 'danger')
            return redirect(url_for('magic_link'))

        # Generate unique token
        token = str(uuid.uuid4())
        session['magic_link_token'] = token
        session['magic_link_email'] = email
        session['magic_link_timestamp'] = datetime.utcnow().isoformat()

        # Generate link
        link = url_for('verify_magic_link', token=token, _external=True)

        # Send email
        msg = Message('Magic Link for Authentication Study', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = f"""
        Here is the magic link for the authentication study. It will expire in 15 minutes.
        
        Please click the link to verify: {link}"""
        mail.send(msg)

        flash('Magic link sent to your email.', 'success')
        return redirect(url_for('home'))

    return render_template('magic_link.html')

@app.route('/verify-magic-link/<token>')
@login_required
def verify_magic_link(token):
    timestamp_str = session.get('magic_link_timestamp')
    if not timestamp_str:
        flash('Invalid or expired magic link.', 'danger')
        return redirect(url_for('home'))

    timestamp = datetime.fromisoformat(timestamp_str)
    now = datetime.utcnow()

    # Check if the link has expired (older than 15 minutes)
    if now - timestamp > timedelta(minutes=15):
        flash('Magic link has expired. Please request a new one.', 'danger')
        session.pop('magic_link_token', None)
        session.pop('magic_link_email', None)
        session.pop('magic_link_timestamp', None)
        return redirect(url_for('magic_link'))

    if token == session.get('magic_link_token'):
        current_user.magic_link_completed = True
        db.session.commit()
        session.pop('magic_link_token', None)
        session.pop('magic_link_email', None)
        flash('Magic link verified successfully!', 'success')
        return redirect(url_for('home'))
    else:
        flash('Invalid or expired magic link.', 'danger')
        return redirect(url_for('home'))


# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.route('/run-migrations')
def run_migrations():
    upgrade()
    return 'Migrations applied successfully!'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
