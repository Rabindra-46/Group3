from werkzeug.security import check_password_hash, generate_password_hash
from .analyzer import dumps_list, loads_list
from .database import get_db

ROLE_ADMIN = 'admin'
ROLE_USER = 'user'


def find_user_by_email(email):
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    return row


def find_user_by_id(user_id):
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return row


def list_users():
    db = get_db()
    return db.execute(
        'SELECT id, email, role, is_2fa_enabled, created_at FROM users ORDER BY created_at DESC'
    ).fetchall()


def create_user(email, password, role=ROLE_USER):
    hashed_password = generate_password_hash(password)
    db = get_db()

    columns = {row['name'] for row in db.execute('PRAGMA table_info(users)').fetchall()}
    if 'password' in columns:
        db.execute(
            'INSERT INTO users (email, password, password_hash, role) VALUES (?, ?, ?, ?)',
            (email, hashed_password, hashed_password, role),
        )
    else:
        db.execute(
            'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
            (email, hashed_password, role),
        )

    db.commit()


def verify_password(stored_password, candidate):
    return check_password_hash(stored_password, candidate)


def get_password_hash(user):
    if 'password_hash' in user.keys() and user['password_hash']:
        return user['password_hash']
    return user['password']


def save_2fa_secret(user_id, secret):
    db = get_db()
    db.execute(
        'UPDATE users SET two_factor_secret = ? WHERE id = ?',
        (secret, user_id),
    )
    db.commit()


def enable_2fa(user_id):
    db = get_db()
    db.execute(
        'UPDATE users SET is_2fa_enabled = 1 WHERE id = ?',
        (user_id,),
    )
    db.commit()


def save_email_scan(user_id, result):
    db = get_db()
    cursor = db.execute(
        '''
        INSERT INTO email_scans (
            user_id,
            sender,
            subject,
            body_preview,
            urls,
            attachments,
            risk_score,
            result_label,
            result_color,
            reasons
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            user_id,
            result['sender'],
            result['subject'],
            result['body_preview'],
            dumps_list(result['urls']),
            dumps_list(result['attachments']),
            result['risk_score'],
            result['result_label'],
            result['result_color'],
            dumps_list(result['reasons']),
        ),
    )
    db.commit()
    return cursor.lastrowid


def list_email_scans(user_id):
    db = get_db()
    rows = db.execute(
        '''
        SELECT *
        FROM email_scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        ''',
        (user_id,),
    ).fetchall()
    return [format_scan(row) for row in rows]


def get_scan_counts(user_id):
    scans = list_email_scans(user_id)
    return {
        'total': len(scans),
        'phishing': sum(1 for scan in scans if scan['result_label'] == 'Phishing'),
        'suspicious': sum(1 for scan in scans if scan['result_label'] == 'Suspicious'),
        'safe': sum(1 for scan in scans if scan['result_label'] == 'Safe'),
    }


def list_all_email_scans():
    db = get_db()
    rows = db.execute(
        '''
        SELECT email_scans.*, users.email AS user_email
        FROM email_scans
        JOIN users ON users.id = email_scans.user_id
        ORDER BY email_scans.created_at DESC
        LIMIT 25
        '''
    ).fetchall()
    return [format_scan(row) for row in rows]


def format_scan(row):
    scan = dict(row)
    scan['urls'] = loads_list(scan.get('urls'))
    scan['attachments'] = loads_list(scan.get('attachments'))
    scan['reasons'] = loads_list(scan.get('reasons'))
    return scan
