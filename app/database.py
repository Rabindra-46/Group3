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
            is_active INTEGER NOT NULL DEFAULT 1,
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

    if 'is_active' not in existing_columns:
        db.execute('ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1')

    if 'is_2fa_enabled' not in existing_columns:
        db.execute('ALTER TABLE users ADD COLUMN is_2fa_enabled INTEGER NOT NULL DEFAULT 0')

    if 'two_factor_secret' not in existing_columns:
        db.execute('ALTER TABLE users ADD COLUMN two_factor_secret TEXT')

    if 'created_at' not in existing_columns:
        db.execute('ALTER TABLE users ADD COLUMN created_at TIMESTAMP')
        db.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")

    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS email_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sender TEXT,
            subject TEXT,
            reply_to TEXT,
            return_path TEXT,
            authentication_results TEXT,
            body_preview TEXT,
            urls TEXT,
            attachments TEXT,
            risk_score INTEGER NOT NULL,
            result_label TEXT NOT NULL,
            result_color TEXT NOT NULL,
            rule_score INTEGER,
            ml_probability REAL,
            ml_label TEXT,
            reasons TEXT,
            safe_signals TEXT,
            confidence INTEGER,
            is_quarantined INTEGER NOT NULL DEFAULT 0,
            quarantine_reason TEXT,
            quarantined_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        '''
    )

    scan_columns = {
        row['name'] for row in db.execute('PRAGMA table_info(email_scans)').fetchall()
    }

    if 'reply_to' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN reply_to TEXT')

    if 'return_path' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN return_path TEXT')

    if 'authentication_results' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN authentication_results TEXT')

    if 'safe_signals' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN safe_signals TEXT')

    if 'confidence' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN confidence INTEGER')

    if 'rule_score' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN rule_score INTEGER')
        db.execute('UPDATE email_scans SET rule_score = risk_score WHERE rule_score IS NULL')

    if 'ml_probability' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN ml_probability REAL')

    if 'ml_label' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN ml_label TEXT')

    if 'is_quarantined' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN is_quarantined INTEGER NOT NULL DEFAULT 0')
        db.execute(
            '''
            UPDATE email_scans
            SET is_quarantined = 1
            WHERE result_label IN ('Phishing', 'Suspicious')
            '''
        )

    if 'quarantine_reason' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN quarantine_reason TEXT')
        db.execute(
            '''
            UPDATE email_scans
            SET quarantine_reason = 'Automatically quarantined because the scan was flagged.'
            WHERE is_quarantined = 1 AND quarantine_reason IS NULL
            '''
        )

    if 'quarantined_at' not in scan_columns:
        db.execute('ALTER TABLE email_scans ADD COLUMN quarantined_at TIMESTAMP')
        db.execute(
            '''
            UPDATE email_scans
            SET quarantined_at = created_at
            WHERE is_quarantined = 1 AND quarantined_at IS NULL
            '''
        )

    db.commit()
