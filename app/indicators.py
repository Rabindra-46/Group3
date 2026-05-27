from .database import get_db

PHISHING_KEYWORDS = [
    'verify now',
    'urgent',
    'account suspended',
    'immediate action',
    'limited time',
    'act now',
    'payment',
    'bank',
    'invoice',
    'refund',
    'credit card',
    'password',
    'login',
]

SUSPICIOUS_DOMAINS = [
    'bit.ly',
    'tinyurl.com',
    't.co',
    'goo.gl',
    'ow.ly',
    'is.gd',
    'buff.ly',
]

DANGEROUS_EXTENSIONS = [
    '.exe',
    '.scr',
    '.bat',
    '.cmd',
    '.js',
    '.vbs',
    '.zip',
    '.rar',
]

DEFAULT_INDICATORS = {
    'keyword': PHISHING_KEYWORDS,
    'domain': SUSPICIOUS_DOMAINS,
    'extension': DANGEROUS_EXTENSIONS,
}


def seed_default_indicators(db):
    for indicator_type, values in DEFAULT_INDICATORS.items():
        for value in values:
            db.execute(
                '''
                INSERT OR IGNORE INTO malicious_indicators (indicator_type, value)
                VALUES (?, ?)
                ''',
                (indicator_type, value.lower()),
            )


def get_malicious_indicators():
    try:
        db = get_db()
        rows = db.execute(
            '''
            SELECT indicator_type, value
            FROM malicious_indicators
            WHERE is_active = 1
            '''
        ).fetchall()
    except Exception:
        return DEFAULT_INDICATORS

    indicators = {'keyword': [], 'domain': [], 'extension': []}
    for row in rows:
        if row['indicator_type'] in indicators:
            indicators[row['indicator_type']].append(row['value'])

    for indicator_type, defaults in DEFAULT_INDICATORS.items():
        if not indicators[indicator_type]:
            indicators[indicator_type] = defaults

    return indicators
