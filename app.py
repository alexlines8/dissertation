from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User
from forms import RegisterForm, LoginForm
from twilio.rest import Client
import os
import random
from flask_mail import Mail, Message
from dotenv import load_dotenv


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app)
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
        phone = request.form.get('phone', '').strip()

        if not phone.startswith('+') or not phone[1:].isdigit():
            flash('Invalid phone number format. Please use international format, e.g., +447123456789.', 'danger')
            return redirect(url_for('sms_otp'))

        otp = str(random.randint(100000, 999999))
        current_user.phone_number = phone
        session['otp'] = otp
        current_user.otp = otp  # Add this attribute dynamically
        db.session.commit()

        # Send SMS
        twilio_client.messages.create(
            body=f'Your verification code is: {otp}',
            from_=twilio_phone_number,
            to=phone
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
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        # Basic validation
        if '@' not in email or '.' not in email:
            flash('Invalid email address.', 'danger')
            return redirect(url_for('email_otp'))

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

    return render_template('email_otp.html')

@app.route('/verify-email-otp', methods=['GET', 'POST'])
@login_required
def verify_email_otp():
    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()

        if not otp_input.isdigit() or len(otp_input) != 6:
            flash('Invalid OTP format. Please enter a 6-digit number.', 'danger')
            return redirect(url_for('verify_email_otp'))

        if otp_input == session.get('email_otp'):
            current_user.email = session.get('email_address')
            current_user.email_mfa_completed = True
            db.session.commit()
            session.pop('email_otp', None)
            session.pop('email_address', None)
            flash('Email verified successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_email_otp.html')


@app.route('/create-db')
def create_db():
    db.create_all()
    return 'Database created!'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
