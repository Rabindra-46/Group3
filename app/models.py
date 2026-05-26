from werkzeug.security import check_password_hash, generate_password_hash
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
