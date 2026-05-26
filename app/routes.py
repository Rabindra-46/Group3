import base64
from datetime import datetime
from io import BytesIO
from functools import wraps

import pyotp
import qrcode
from flask import Blueprint, Response, flash, redirect, render_template, request, session, url_for
from .analyzer import analyze_email
from .reports import build_scan_csv, build_scans_csv
from .models import (
    ROLE_ADMIN,
    create_user,
    delete_all_email_scans,
    delete_all_scans_admin,
    delete_any_email_scan,
    delete_email_scan,
    enable_2fa,
    find_any_email_scan,
    find_user_by_email,
    find_user_by_id,
    find_email_scan,
    get_password_hash,
    get_scan_counts,
    list_all_email_scans,
    list_all_quarantined_email_scans,
    list_email_scans,
    list_quarantined_email_scans,
    list_users,
    reset_2fa,
    save_2fa_secret,
    save_email_scan,
    set_any_email_scan_quarantine,
    set_email_scan_quarantine,
    set_user_active,
    verify_password,
)

main_blueprint = Blueprint('main', __name__)

AUTH_CONTEXT_USER = 'user'
AUTH_CONTEXT_ADMIN = 'admin'
AUTH_SESSION_KEYS = {
    AUTH_CONTEXT_USER: 'user_auth',
    AUTH_CONTEXT_ADMIN: 'admin_auth',
}


@main_blueprint.app_context_processor
def inject_auth_sessions():
    return {
        'user_auth': get_auth(AUTH_CONTEXT_USER),
        'admin_auth': get_auth(AUTH_CONTEXT_ADMIN),
    }


def get_auth(context=AUTH_CONTEXT_USER):
    return session.get(AUTH_SESSION_KEYS[context])


def set_auth(user, context=AUTH_CONTEXT_USER):
    session[AUTH_SESSION_KEYS[context]] = {
        'user_id': user['id'],
        'user_email': user['email'],
        'user_role': user['role'],
        'is_2fa_verified': False,
    }


def clear_auth(context=AUTH_CONTEXT_USER):
    session.pop(AUTH_SESSION_KEYS[context], None)


def mark_2fa_verified(context=AUTH_CONTEXT_USER):
    auth = get_auth(context)
    if auth:
        auth['is_2fa_verified'] = True
        session[AUTH_SESSION_KEYS[context]] = auth


def login_required(view=None, context=AUTH_CONTEXT_USER):
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            auth = get_auth(context)
            if auth is None:
                flash('Please log in to access this page.', 'warning')
                return redirect(get_login_url(context))

            user = find_user_by_id(auth['user_id'])
            if user is None or not user['is_active']:
                clear_auth(context)
                flash('Your account is inactive. Please contact an admin.', 'danger')
                return redirect(get_login_url(context))

            if not auth.get('is_2fa_verified'):
                flash('Please complete two-factor authentication first.', 'warning')
                return redirect(get_2fa_redirect(context))

            return view(**kwargs)

        return wrapped_view

    if view is None:
        return decorator
    return decorator(view)


def role_required(required_role, context=AUTH_CONTEXT_ADMIN):
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            auth = get_auth(context)
            if auth is None:
                flash('Please log in to access this page.', 'warning')
                return redirect(get_login_url(context))

            user = find_user_by_id(auth['user_id'])
            if user is None or not user['is_active']:
                clear_auth(context)
                flash('Your account is inactive. Please contact an admin.', 'danger')
                return redirect(get_login_url(context))

            if not auth.get('is_2fa_verified'):
                flash('Please complete two-factor authentication first.', 'warning')
                return redirect(get_2fa_redirect(context))

            if auth.get('user_role') != required_role:
                flash('You are not authorized to access that page.', 'danger')
                return redirect(url_for('main.dashboard'))

            return view(**kwargs)

        return wrapped_view

    return decorator


def get_login_url(context):
    if context == AUTH_CONTEXT_ADMIN:
        return url_for('main.admin_login')
    return url_for('main.login')


def get_2fa_redirect(context=AUTH_CONTEXT_USER):
    auth = get_auth(context)
    user = find_user_by_id(auth['user_id']) if auth else None
    if user and user['is_2fa_enabled']:
        return url_for('main.admin_verify_2fa' if context == AUTH_CONTEXT_ADMIN else 'main.verify_2fa')
    return url_for('main.admin_setup_2fa' if context == AUTH_CONTEXT_ADMIN else 'main.setup_2fa')


def get_after_2fa_url(context=AUTH_CONTEXT_USER):
    if context == AUTH_CONTEXT_ADMIN:
        return url_for('main.admin_dashboard')
    return url_for('main.dashboard')


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


def export_scan_response(scan):
    timestamp = datetime.utcnow().strftime('%Y%m%d')
    filename = f"scan-report-{scan['id']}-{timestamp}.csv"
    return Response(
        build_scan_csv(scan),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


def export_scans_response(scans):
    timestamp = datetime.utcnow().strftime('%Y%m%d')
    filename = f'all-scan-reports-{timestamp}.csv'
    return Response(
        build_scans_csv(scans),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@main_blueprint.route('/')
def home():
    return render_template('index.html')


@main_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    return handle_login(AUTH_CONTEXT_USER)


@main_blueprint.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    return handle_login(AUTH_CONTEXT_ADMIN)


def handle_login(context):
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        user = find_user_by_email(email)

        if user is None:
            flash('No account found with that email.', 'danger')
        elif not user['is_active']:
            flash('This account is inactive. Please contact an admin.', 'danger')
        elif not verify_password(get_password_hash(user), password):
            flash('Invalid password. Please try again.', 'danger')
        elif context == AUTH_CONTEXT_ADMIN and user['role'] != ROLE_ADMIN:
            flash('Only admin users can log in to the admin area.', 'danger')
        else:
            set_auth(user, context)

            if user['is_2fa_enabled']:
                flash('Password accepted. Enter your authentication code.', 'info')
                return redirect(get_2fa_redirect(context))

            flash('Password accepted. Set up two-factor authentication to continue.', 'info')
            return redirect(get_2fa_redirect(context))

    return render_template(
        'login.html',
        auth_context=context,
        is_admin_login=context == AUTH_CONTEXT_ADMIN,
    )


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
    return handle_setup_2fa(AUTH_CONTEXT_USER)


@main_blueprint.route('/admin/2fa/setup', methods=['GET', 'POST'])
def admin_setup_2fa():
    return handle_setup_2fa(AUTH_CONTEXT_ADMIN)


def handle_setup_2fa(context):
    auth = get_auth(context)
    if auth is None:
        flash('Please log in before setting up two-factor authentication.', 'warning')
        return redirect(get_login_url(context))

    user = find_user_by_id(auth['user_id'])
    if user is None:
        clear_auth(context)
        flash('Your session expired. Please log in again.', 'warning')
        return redirect(get_login_url(context))

    if not user['is_active']:
        clear_auth(context)
        flash('Your account is inactive. Please contact an admin.', 'danger')
        return redirect(get_login_url(context))

    if user['is_2fa_enabled']:
        return redirect(get_2fa_redirect(context))

    secret = user['two_factor_secret']
    if not secret:
        secret = pyotp.random_base32()
        save_2fa_secret(user['id'], secret)

    if request.method == 'POST':
        otp_code = request.form['otp_code'].strip()
        if pyotp.TOTP(secret).verify(otp_code, valid_window=1):
            enable_2fa(user['id'])
            mark_2fa_verified(context)
            flash('Two-factor authentication is now enabled.', 'success')
            return redirect(get_after_2fa_url(context))

        flash('Invalid OTP code. If it expired, enter the newest code from your authenticator app.', 'danger')

    return render_template(
        'setup_2fa.html',
        qr_code=get_qr_code_data_uri(secret, user['email']),
        secret=secret,
        is_admin_login=context == AUTH_CONTEXT_ADMIN,
    )


@main_blueprint.route('/2fa/verify', methods=['GET', 'POST'])
def verify_2fa():
    return handle_verify_2fa(AUTH_CONTEXT_USER)


@main_blueprint.route('/admin/2fa/verify', methods=['GET', 'POST'])
def admin_verify_2fa():
    return handle_verify_2fa(AUTH_CONTEXT_ADMIN)


def handle_verify_2fa(context):
    auth = get_auth(context)
    if auth is None:
        flash('Please log in before entering your authentication code.', 'warning')
        return redirect(get_login_url(context))

    user = find_user_by_id(auth['user_id'])
    if user is None:
        clear_auth(context)
        flash('Your session expired. Please log in again.', 'warning')
        return redirect(get_login_url(context))

    if not user['is_active']:
        clear_auth(context)
        flash('Your account is inactive. Please contact an admin.', 'danger')
        return redirect(get_login_url(context))

    if not user['is_2fa_enabled']:
        return redirect(get_2fa_redirect(context))

    if request.method == 'POST':
        otp_code = request.form['otp_code'].strip()
        if pyotp.TOTP(user['two_factor_secret']).verify(otp_code, valid_window=1):
            mark_2fa_verified(context)
            flash('Two-factor authentication verified.', 'success')
            return redirect(get_after_2fa_url(context))

        flash('Invalid OTP code. If it expired, enter the newest code from your authenticator app.', 'danger')

    return render_template(
        'verify_2fa.html',
        is_admin_login=context == AUTH_CONTEXT_ADMIN,
    )


@main_blueprint.route('/dashboard')
@login_required
def dashboard():
    auth = get_auth(AUTH_CONTEXT_USER)
    return render_template(
        'user_dashboard.html',
        user_email=auth['user_email'],
        user_role=auth['user_role'],
        recent_scans=list_email_scans(auth['user_id'])[:3],
        scan_counts=get_scan_counts(auth['user_id']),
    )


@main_blueprint.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    auth = get_auth(AUTH_CONTEXT_USER)
    result = None
    raw_email = ''
    email_text = ''
    source_name = 'Pasted email'

    if request.method == 'POST':
        uploaded_file = request.files.get('email_file')
        if uploaded_file and uploaded_file.filename:
            if not uploaded_file.filename.lower().endswith('.eml'):
                flash('Please upload a .eml email file.', 'warning')
            else:
                raw_email = uploaded_file.read().decode('utf-8', errors='replace').strip()
                source_name = uploaded_file.filename
        else:
            raw_email = request.form['raw_email'].strip()
            email_text = raw_email

        if not raw_email:
            flash('Please paste an email or upload a .eml file before analyzing.', 'warning')
        else:
            result = analyze_email(raw_email)
            save_email_scan(auth['user_id'], result)
            flash('Email analyzed and saved to your scan history.', 'success')

    return render_template(
        'analyze_email.html',
        result=result,
        raw_email=email_text,
        source_name=source_name,
        user_role=auth['user_role'],
    )


@main_blueprint.route('/scans')
@login_required
def scan_history():
    auth = get_auth(AUTH_CONTEXT_USER)
    return render_template(
        'scan_history.html',
        scans=list_email_scans(auth['user_id']),
        user_role=auth['user_role'],
    )


@main_blueprint.route('/quarantine')
@login_required
def quarantine():
    auth = get_auth(AUTH_CONTEXT_USER)
    return render_template(
        'quarantine.html',
        scans=list_quarantined_email_scans(auth['user_id']),
        user_role=auth['user_role'],
    )


@main_blueprint.route('/scans/<int:scan_id>/quarantine', methods=['POST'])
@login_required
def quarantine_scan(scan_id):
    auth = get_auth(AUTH_CONTEXT_USER)
    updated_count = set_email_scan_quarantine(
        scan_id,
        auth['user_id'],
        True,
        'Manually quarantined by the user.',
    )
    if updated_count:
        flash('Scan report moved to quarantine.', 'success')
    else:
        flash('Scan report not found.', 'warning')
    return redirect(url_for('main.scan_history'))


@main_blueprint.route('/scans/<int:scan_id>/release', methods=['POST'])
@login_required
def release_scan(scan_id):
    auth = get_auth(AUTH_CONTEXT_USER)
    updated_count = set_email_scan_quarantine(scan_id, auth['user_id'], False)
    if updated_count:
        flash('Scan report released from quarantine.', 'success')
    else:
        flash('Scan report not found.', 'warning')
    return redirect(url_for('main.quarantine'))


@main_blueprint.route('/admin/quarantine')
@role_required(ROLE_ADMIN)
def admin_quarantine():
    auth = get_auth(AUTH_CONTEXT_ADMIN)
    return render_template(
        'quarantine.html',
        scans=list_all_quarantined_email_scans(),
        user_role=auth['user_role'],
        is_admin_view=True,
    )


@main_blueprint.route('/admin/scans/<int:scan_id>/quarantine', methods=['POST'])
@role_required(ROLE_ADMIN)
def admin_quarantine_scan(scan_id):
    updated_count = set_any_email_scan_quarantine(
        scan_id,
        True,
        'Manually quarantined by an admin.',
    )
    if updated_count:
        flash('Scan report moved to quarantine.', 'success')
    else:
        flash('Scan report not found.', 'warning')
    return redirect(url_for('main.admin_dashboard'))


@main_blueprint.route('/admin/scans/<int:scan_id>/release', methods=['POST'])
@role_required(ROLE_ADMIN)
def admin_release_scan(scan_id):
    updated_count = set_any_email_scan_quarantine(scan_id, False)
    if updated_count:
        flash('Scan report released from quarantine.', 'success')
    else:
        flash('Scan report not found.', 'warning')
    return redirect(url_for('main.admin_quarantine'))


@main_blueprint.route('/scans/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    auth = get_auth(AUTH_CONTEXT_USER)
    scan = find_email_scan(scan_id, auth['user_id'])
    if scan is None:
        flash('Scan report not found.', 'warning')
        return redirect(url_for('main.scan_history'))

    return render_template(
        'scan_detail.html',
        scan=scan,
        user_role=auth['user_role'],
    )


@main_blueprint.route('/scans/<int:scan_id>/export/<file_type>')
@login_required
def export_scan(scan_id, file_type):
    if file_type != 'csv':
        flash('Unsupported export format.', 'warning')
        return redirect(url_for('main.scan_detail', scan_id=scan_id))

    auth = get_auth(AUTH_CONTEXT_USER)
    scan = find_email_scan(scan_id, auth['user_id'])
    if scan is None:
        flash('Scan report not found.', 'warning')
        return redirect(url_for('main.scan_history'))

    return export_scan_response(scan)


@main_blueprint.route('/scans/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    auth = get_auth(AUTH_CONTEXT_USER)
    deleted_count = delete_email_scan(scan_id, auth['user_id'])
    if deleted_count:
        flash('Scan report deleted.', 'success')
    else:
        flash('Scan report not found.', 'warning')
    return redirect(url_for('main.scan_history'))


@main_blueprint.route('/scans/delete-all', methods=['POST'])
@login_required
def delete_all_scans():
    auth = get_auth(AUTH_CONTEXT_USER)
    deleted_count = delete_all_email_scans(auth['user_id'])
    flash(f'Deleted {deleted_count} scan report(s).', 'success')
    return redirect(url_for('main.scan_history'))


@main_blueprint.route('/admin/dashboard')
@role_required(ROLE_ADMIN)
def admin_dashboard():
    auth = get_auth(AUTH_CONTEXT_ADMIN)
    return render_template(
        'admin_dashboard.html',
        user_email=auth['user_email'],
        user_role=auth['user_role'],
        scans=list_all_email_scans(),
    )


@main_blueprint.route('/admin/users')
@role_required(ROLE_ADMIN)
def admin_users():
    auth = get_auth(AUTH_CONTEXT_ADMIN)
    return render_template(
        'admin_users.html',
        user_email=auth['user_email'],
        user_role=auth['user_role'],
        current_admin_id=auth['user_id'],
        users=list_users(),
    )


@main_blueprint.route('/admin/users/<int:user_id>/activate', methods=['POST'])
@role_required(ROLE_ADMIN)
def admin_activate_user(user_id):
    updated_count = set_user_active(user_id, True)
    if updated_count:
        flash('User account activated.', 'success')
    else:
        flash('User not found.', 'warning')
    return redirect(url_for('main.admin_users'))


@main_blueprint.route('/admin/users/<int:user_id>/deactivate', methods=['POST'])
@role_required(ROLE_ADMIN)
def admin_deactivate_user(user_id):
    auth = get_auth(AUTH_CONTEXT_ADMIN)
    if user_id == auth['user_id']:
        flash('You cannot deactivate your own admin account while signed in.', 'warning')
        return redirect(url_for('main.admin_users'))

    updated_count = set_user_active(user_id, False)
    if updated_count:
        flash('User account deactivated.', 'success')
    else:
        flash('User not found.', 'warning')
    return redirect(url_for('main.admin_users'))


@main_blueprint.route('/admin/scans/<int:scan_id>')
@role_required(ROLE_ADMIN)
def admin_scan_detail(scan_id):
    auth = get_auth(AUTH_CONTEXT_ADMIN)
    scan = find_any_email_scan(scan_id)
    if scan is None:
        flash('Scan report not found.', 'warning')
        return redirect(url_for('main.admin_dashboard'))

    return render_template(
        'scan_detail.html',
        scan=scan,
        user_role=auth['user_role'],
        is_admin_view=True,
    )


@main_blueprint.route('/admin/scans/<int:scan_id>/export/<file_type>')
@role_required(ROLE_ADMIN)
def admin_export_scan(scan_id, file_type):
    if file_type != 'csv':
        flash('Unsupported export format.', 'warning')
        return redirect(url_for('main.admin_scan_detail', scan_id=scan_id))

    scan = find_any_email_scan(scan_id)
    if scan is None:
        flash('Scan report not found.', 'warning')
        return redirect(url_for('main.admin_dashboard'))

    return export_scan_response(scan)


@main_blueprint.route('/admin/scans/export/csv')
@role_required(ROLE_ADMIN)
def admin_export_all_scans():
    return export_scans_response(list_all_email_scans(limit=None))


@main_blueprint.route('/admin/scans/<int:scan_id>/delete', methods=['POST'])
@role_required(ROLE_ADMIN)
def admin_delete_scan(scan_id):
    deleted_count = delete_any_email_scan(scan_id)
    if deleted_count:
        flash('Scan report deleted by admin.', 'success')
    else:
        flash('Scan report not found.', 'warning')
    return redirect(url_for('main.admin_dashboard'))


@main_blueprint.route('/admin/users/<int:user_id>/reset-2fa', methods=['POST'])
@role_required(ROLE_ADMIN)
def admin_reset_user_2fa(user_id):
    auth = get_auth(AUTH_CONTEXT_ADMIN)
    if user_id == auth['user_id']:
        flash('For your own admin account, use the local reset command shown in the project notes.', 'warning')
        return redirect(url_for('main.admin_users'))

    updated_count = reset_2fa(user_id)
    if updated_count:
        flash('Two-factor authentication was reset. The user will see a new QR code on next login.', 'success')
    else:
        flash('User not found.', 'warning')
    return redirect(url_for('main.admin_users'))


@main_blueprint.route('/admin/scans/delete-all', methods=['POST'])
@role_required(ROLE_ADMIN)
def admin_delete_all_scans():
    deleted_count = delete_all_scans_admin()
    flash(f'Admin deleted {deleted_count} scan report(s).', 'success')
    return redirect(url_for('main.admin_dashboard'))


@main_blueprint.route('/logout')
def logout():
    clear_auth(AUTH_CONTEXT_USER)
    flash('User session logged out.', 'info')
    return redirect(url_for('main.home'))


@main_blueprint.route('/admin/logout')
def admin_logout():
    clear_auth(AUTH_CONTEXT_ADMIN)
    flash('Admin session logged out.', 'info')
    return redirect(url_for('main.home'))
