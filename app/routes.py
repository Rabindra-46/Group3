from functools import wraps
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from .models import create_user, find_user_by_email, get_password_hash, verify_password

main_blueprint = Blueprint('main', __name__)


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if session.get('user_id') is None:
            flash('Please log in to access the dashboard.', 'warning')
            return redirect(url_for('main.login'))
        return view(**kwargs)

    return wrapped_view


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
            session['is_2fa_verified'] = not bool(user['is_2fa_enabled'])
            flash('You are now logged in.', 'success')
            return redirect(url_for('main.dashboard'))

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


@main_blueprint.route('/dashboard')
@login_required
def dashboard():
    return render_template(
        'dashboard.html',
        user_email=session.get('user_email'),
        user_role=session.get('user_role'),
    )


@main_blueprint.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))
