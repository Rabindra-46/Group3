import csv
from io import StringIO


def build_scan_csv(scan):
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Field', 'Value'])

    for label, value in get_scan_fields(scan):
        writer.writerow([label, value])

    writer.writerow([])
    writer.writerow(['Reasons'])
    for reason in scan['reasons']:
        writer.writerow([reason])

    writer.writerow([])
    writer.writerow(['Safe signals'])
    for signal in scan['safe_signals']:
        writer.writerow([signal])

    writer.writerow([])
    writer.writerow(['Extracted URLs'])
    for url in scan['urls']:
        writer.writerow([url])

    writer.writerow([])
    writer.writerow(['Attachments'])
    for attachment in scan['attachments']:
        writer.writerow([attachment])

    return output.getvalue()


def build_scans_csv(scans):
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Report ID',
        'User',
        'Created',
        'Sender',
        'Subject',
        'Result',
        'Risk score',
        'Rule score',
        'ML phishing probability',
        'ML label',
        'Confidence',
        'Quarantine status',
        'Quarantine reason',
        'Quarantined at',
        'URL count',
        'Attachment count',
        'Reasons',
    ])

    for scan in scans:
        writer.writerow([
            scan.get('id'),
            scan.get('user_email', ''),
            scan.get('created_at'),
            scan.get('sender'),
            scan.get('subject'),
            scan.get('result_label'),
            scan.get('risk_score'),
            scan.get('rule_score'),
            scan.get('ml_probability') if scan.get('ml_probability') is not None else '',
            scan.get('ml_label') or 'Model not available',
            scan.get('confidence'),
            'Quarantined' if scan.get('is_quarantined') else 'Clear',
            scan.get('quarantine_reason') or '',
            scan.get('quarantined_at') or '',
            len(scan.get('urls') or []),
            len(scan.get('attachments') or []),
            ' | '.join(scan.get('reasons') or []),
        ])

    return output.getvalue()


def get_scan_fields(scan):
    return [
        ('Report ID', scan.get('id')),
        ('Submitted by', scan.get('user_email', 'Current user')),
        ('Created', scan.get('created_at')),
        ('Sender', scan.get('sender')),
        ('Subject', scan.get('subject')),
        ('Reply-To', scan.get('reply_to')),
        ('Return-Path', scan.get('return_path')),
        ('Result', scan.get('result_label')),
        ('Risk score', f"{scan.get('risk_score')}/100"),
        ('Rule-based score', f"{scan.get('rule_score')}/100"),
        ('ML phishing probability', '' if scan.get('ml_probability') is None else f"{scan.get('ml_probability')}%"),
        ('ML label', scan.get('ml_label') or 'Model not available'),
        ('Confidence', f"{scan.get('confidence')}%"),
        ('Quarantine status', 'Quarantined' if scan.get('is_quarantined') else 'Clear'),
        ('Quarantine reason', scan.get('quarantine_reason') or ''),
        ('Quarantined at', scan.get('quarantined_at') or ''),
        ('Authentication-Results', scan.get('authentication_results')),
    ]
