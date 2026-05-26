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
        '''
        SELECT id, email, role, is_active, is_2fa_enabled, created_at
        FROM users
        ORDER BY created_at DESC
        '''
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


def reset_2fa(user_id):
    db = get_db()
    cursor = db.execute(
        '''
        UPDATE users
        SET is_2fa_enabled = 0,
            two_factor_secret = NULL
        WHERE id = ?
        ''',
        (user_id,),
    )
    db.commit()
    return cursor.rowcount


def set_user_active(user_id, is_active):
    db = get_db()
    cursor = db.execute(
        'UPDATE users SET is_active = ? WHERE id = ?',
        (1 if is_active else 0, user_id),
    )
    db.commit()
    return cursor.rowcount


def save_email_scan(user_id, result):
    db = get_db()
    should_quarantine = result['result_label'] in ['Phishing', 'Suspicious']
    quarantine_reason = None
    if should_quarantine:
        quarantine_reason = f"Automatically quarantined because result was {result['result_label']}."

    cursor = db.execute(
        '''
        INSERT INTO email_scans (
            user_id,
            sender,
            subject,
            reply_to,
            return_path,
            authentication_results,
            body_preview,
            urls,
            attachments,
            risk_score,
            result_label,
            result_color,
            reasons,
            safe_signals,
            confidence,
            is_quarantined,
            quarantine_reason,
            quarantined_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END)
        ''',
        (
            user_id,
            result['sender'],
            result['subject'],
            result['reply_to'],
            result['return_path'],
            result['authentication_results'],
            result['body_preview'],
            dumps_list(result['urls']),
            dumps_list(result['attachments']),
            result['risk_score'],
            result['result_label'],
            result['result_color'],
            dumps_list(result['reasons']),
            dumps_list(result['safe_signals']),
            result['confidence'],
            1 if should_quarantine else 0,
            quarantine_reason,
            1 if should_quarantine else 0,
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


def list_quarantined_email_scans(user_id):
    db = get_db()
    rows = db.execute(
        '''
        SELECT *
        FROM email_scans
        WHERE user_id = ? AND is_quarantined = 1
        ORDER BY quarantined_at DESC, created_at DESC
        ''',
        (user_id,),
    ).fetchall()
    return [format_scan(row) for row in rows]


def find_email_scan(scan_id, user_id):
    db = get_db()
    row = db.execute(
        '''
        SELECT *
        FROM email_scans
        WHERE id = ? AND user_id = ?
        ''',
        (scan_id, user_id),
    ).fetchone()
    if row is None:
        return None
    return format_scan(row)


def set_email_scan_quarantine(scan_id, user_id, is_quarantined, reason=None):
    db = get_db()
    cursor = db.execute(
        '''
        UPDATE email_scans
        SET is_quarantined = ?,
            quarantine_reason = ?,
            quarantined_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END
        WHERE id = ? AND user_id = ?
        ''',
        (
            1 if is_quarantined else 0,
            reason if is_quarantined else None,
            1 if is_quarantined else 0,
            scan_id,
            user_id,
        ),
    )
    db.commit()
    return cursor.rowcount


def find_any_email_scan(scan_id):
    db = get_db()
    row = db.execute(
        '''
        SELECT email_scans.*, users.email AS user_email
        FROM email_scans
        JOIN users ON users.id = email_scans.user_id
        WHERE email_scans.id = ?
        ''',
        (scan_id,),
    ).fetchone()
    if row is None:
        return None
    return format_scan(row)


def list_all_quarantined_email_scans():
    db = get_db()
    rows = db.execute(
        '''
        SELECT email_scans.*, users.email AS user_email
        FROM email_scans
        JOIN users ON users.id = email_scans.user_id
        WHERE email_scans.is_quarantined = 1
        ORDER BY email_scans.quarantined_at DESC, email_scans.created_at DESC
        '''
    ).fetchall()
    return [format_scan(row) for row in rows]


def set_any_email_scan_quarantine(scan_id, is_quarantined, reason=None):
    db = get_db()
    cursor = db.execute(
        '''
        UPDATE email_scans
        SET is_quarantined = ?,
            quarantine_reason = ?,
            quarantined_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END
        WHERE id = ?
        ''',
        (
            1 if is_quarantined else 0,
            reason if is_quarantined else None,
            1 if is_quarantined else 0,
            scan_id,
        ),
    )
    db.commit()
    return cursor.rowcount


def delete_email_scan(scan_id, user_id):
    db = get_db()
    cursor = db.execute(
        'DELETE FROM email_scans WHERE id = ? AND user_id = ?',
        (scan_id, user_id),
    )
    db.commit()
    return cursor.rowcount


def delete_all_email_scans(user_id):
    db = get_db()
    cursor = db.execute(
        'DELETE FROM email_scans WHERE user_id = ?',
        (user_id,),
    )
    db.commit()
    return cursor.rowcount


def get_scan_counts(user_id):
    scans = list_email_scans(user_id)
    return {
        'total': len(scans),
        'phishing': sum(1 for scan in scans if scan['result_label'] == 'Phishing'),
        'suspicious': sum(1 for scan in scans if scan['result_label'] == 'Suspicious'),
        'safe': sum(1 for scan in scans if scan['result_label'] == 'Safe'),
        'quarantined': sum(1 for scan in scans if scan['is_quarantined']),
    }


def list_all_email_scans(limit=25):
    db = get_db()
    query = '''
        SELECT email_scans.*, users.email AS user_email
        FROM email_scans
        JOIN users ON users.id = email_scans.user_id
        ORDER BY email_scans.created_at DESC
        '''
    params = ()
    if limit is not None:
        query += 'LIMIT ?'
        params = (limit,)

    rows = db.execute(query, params).fetchall()
    return [format_scan(row) for row in rows]


def delete_any_email_scan(scan_id):
    db = get_db()
    cursor = db.execute('DELETE FROM email_scans WHERE id = ?', (scan_id,))
    db.commit()
    return cursor.rowcount


def delete_all_scans_admin():
    db = get_db()
    cursor = db.execute('DELETE FROM email_scans')
    db.commit()
    return cursor.rowcount


def format_scan(row):
    scan = dict(row)
    scan['urls'] = loads_list(scan.get('urls'))
    scan['attachments'] = loads_list(scan.get('attachments'))
    scan['reasons'] = loads_list(scan.get('reasons'))
    scan['safe_signals'] = loads_list(scan.get('safe_signals'))
    scan['confidence'] = scan.get('confidence') or 0
    scan['is_quarantined'] = bool(scan.get('is_quarantined'))
    return scan
