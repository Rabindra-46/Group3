from werkzeug.security import check_password_hash, generate_password_hash
from .database import get_db


def find_user_by_email(email):
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    return row


def create_user(email, password, role='user'):
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


# Future RBAC and 2FA support can be added here:
# - role checks (admin, analyst, user)
# - multi-factor authentication state
# - session permissions and user claims
