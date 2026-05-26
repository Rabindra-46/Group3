import base64
from io import BytesIO
from functools import wraps

import pyotp
import qrcode
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from .models import (
    ROLE_ADMIN,
    create_user,
    enable_2fa,
    find_user_by_email,
    find_user_by_id,
    get_password_hash,
    list_users,
    save_2fa_secret,
    verify_password,
)

main_blueprint = Blueprint('main', __name__)


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if session.get('user_id') is None:
            flash('Please log in to access the dashboard.', 'warning')
            return redirect(url_for('main.login'))

        if not session.get('is_2fa_verified'):
            flash('Please complete two-factor authentication first.', 'warning')
            return redirect(get_2fa_redirect())

        return view(**kwargs)

    return wrapped_view


def role_required(required_role):
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if session.get('user_id') is None:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('main.login'))

            if not session.get('is_2fa_verified'):
                flash('Please complete two-factor authentication first.', 'warning')
                return redirect(get_2fa_redirect())

            if session.get('user_role') != required_role:
                flash('You are not authorized to access that page.', 'danger')
                return redirect(url_for('main.dashboard'))

            return view(**kwargs)

        return wrapped_view

    return decorator


def get_2fa_redirect():
    user = find_user_by_id(session.get('user_id'))
    if user and user['is_2fa_enabled']:
        return url_for('main.verify_2fa')
    return url_for('main.setup_2fa')


def get_qr_code_data_uri(secret, email):
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=email,
        issuer_name='Phishing Email Detector',
    )

    image = qrcode.make(provisioning_uri)
    buffer = BytesIO()
    image.save(buffer, format='PNG')
    qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f'data:image/png;base64,{qr_code}'


@main_blueprint.route('/')
def home():
    return render_template('index.html')


@main_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        user = find_user_by_email(email)

        if user is None:
            flash('No account found with that email.', 'danger')
        elif not verify_password(get_password_hash(user), password):
            flash('Invalid password. Please try again.', 'danger')
        else:
            session.clear()
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_role'] = user['role']
            session['is_2fa_verified'] = False

            if user['is_2fa_enabled']:
                flash('Password accepted. Enter your authentication code.', 'info')
                return redirect(url_for('main.verify_2fa'))

            flash('Password accepted. Set up two-factor authentication to continue.', 'info')
            return redirect(url_for('main.setup_2fa'))

    return render_template('login.html')


@main_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        if not email or not password or not confirm_password:
            flash('All fields are required.', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match.', 'danger')
        elif find_user_by_email(email) is not None:
            flash('An account with that email already exists.', 'danger')
        else:
            create_user(email, password)
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('main.login'))

    return render_template('register.html')


@main_blueprint.route('/2fa/setup', methods=['GET', 'POST'])
def setup_2fa():
    if session.get('user_id') is None:
        flash('Please log in before setting up two-factor authentication.', 'warning')
        return redirect(url_for('main.login'))

    user = find_user_by_id(session['user_id'])
    if user is None:
        session.clear()
        flash('Your session expired. Please log in again.', 'warning')
        return redirect(url_for('main.login'))

    if user['is_2fa_enabled']:
        return redirect(url_for('main.verify_2fa'))

    secret = user['two_factor_secret']
    if not secret:
        secret = pyotp.random_base32()
        save_2fa_secret(user['id'], secret)

    if request.method == 'POST':
        otp_code = request.form['otp_code'].strip()
        if pyotp.TOTP(secret).verify(otp_code, valid_window=1):
            enable_2fa(user['id'])
            session['is_2fa_verified'] = True
            flash('Two-factor authentication is now enabled.', 'success')
            return redirect(url_for('main.dashboard'))

        flash('Invalid OTP code. If it expired, enter the newest code from your authenticator app.', 'danger')

    return render_template(
        'setup_2fa.html',
        qr_code=get_qr_code_data_uri(secret, user['email']),
        secret=secret,
    )


@main_blueprint.route('/2fa/verify', methods=['GET', 'POST'])
def verify_2fa():
    if session.get('user_id') is None:
        flash('Please log in before entering your authentication code.', 'warning')
        return redirect(url_for('main.login'))

    user = find_user_by_id(session['user_id'])
    if user is None:
        session.clear()
        flash('Your session expired. Please log in again.', 'warning')
        return redirect(url_for('main.login'))

    if not user['is_2fa_enabled']:
        return redirect(url_for('main.setup_2fa'))

    if request.method == 'POST':
        otp_code = request.form['otp_code'].strip()
        if pyotp.TOTP(user['two_factor_secret']).verify(otp_code, valid_window=1):
            session['is_2fa_verified'] = True
            flash('Two-factor authentication verified.', 'success')
            return redirect(url_for('main.dashboard'))

        flash('Invalid OTP code. If it expired, enter the newest code from your authenticator app.', 'danger')

    return render_template('verify_2fa.html')


@main_blueprint.route('/dashboard')
@login_required
def dashboard():
    return render_template(
        'dashboard.html',
        user_email=session.get('user_email'),
        user_role=session.get('user_role'),
    )


@main_blueprint.route('/admin/dashboard')
@role_required(ROLE_ADMIN)
def admin_dashboard():
    return render_template(
        'admin_dashboard.html',
        user_email=session.get('user_email'),
        user_role=session.get('user_role'),
        users=list_users(),
    )


@main_blueprint.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))
