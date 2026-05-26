from functools import wraps
from flask import Blueprint, redirect, render_template, request, session, url_for
from .models import find_user_by_email, verify_password

main_blueprint = Blueprint('main', __name__)


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if session.get('user_email') is None:
            return redirect(url_for('main.login'))
        return view(**kwargs)

    return wrapped_view


@main_blueprint.route('/')
def home():
    return render_template('index.html')


@main_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        user = find_user_by_email(email)

        if user is None:
            error = 'No account found with that email.'
        elif not verify_password(user['password'], password):
            error = 'Invalid password. Please try again.'
        else:
            session.clear()
            session['user_email'] = user['email']
            session['user_role'] = user['role']
            return redirect(url_for('main.dashboard'))

    return render_template('login.html', error=error)


@main_blueprint.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user_email=session.get('user_email'))


@main_blueprint.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.home'))
