import os
import sqlite3
from flask import current_app, g


def get_db():
    if 'db' not in g:
        db_path = current_app.config['DATABASE']
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        g.db = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_2fa_enabled INTEGER NOT NULL DEFAULT 0,
            two_factor_secret TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        '''
    )

    existing_columns = {
        row['name'] for row in db.execute('PRAGMA table_info(users)').fetchall()
    }

    if 'password_hash' not in existing_columns:
        db.execute('ALTER TABLE users ADD COLUMN password_hash TEXT')
        if 'password' in existing_columns:
            db.execute('UPDATE users SET password_hash = password WHERE password_hash IS NULL')

    if 'role' not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")

    if 'is_2fa_enabled' not in existing_columns:
        db.execute('ALTER TABLE users ADD COLUMN is_2fa_enabled INTEGER NOT NULL DEFAULT 0')

    if 'two_factor_secret' not in existing_columns:
        db.execute('ALTER TABLE users ADD COLUMN two_factor_secret TEXT')

    if 'created_at' not in existing_columns:
        db.execute('ALTER TABLE users ADD COLUMN created_at TIMESTAMP')
        db.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")

    db.commit()
