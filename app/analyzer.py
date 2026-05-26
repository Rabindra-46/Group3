import json
import re
from html import unescape
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from urllib.parse import urlparse

URGENCY_WORDS = [
    'verify now',
    'urgent',
    'account suspended',
    'immediate action',
    'limited time',
    'act now',
]

FINANCIAL_WORDS = [
    'payment',
    'bank',
    'invoice',
    'refund',
    'credit card',
    'password',
    'login',
]

SHORTENED_DOMAINS = {
    'bit.ly',
    'tinyurl.com',
    't.co',
    'goo.gl',
    'ow.ly',
    'is.gd',
    'buff.ly',
}

UNUSUAL_TLDS = {
    'click',
    'country',
    'download',
    'gq',
    'link',
    'party',
    'review',
    'ru',
    'stream',
    'tk',
    'top',
    'work',
    'xyz',
}

KNOWN_BRANDS = {
    'amazon',
    'apple',
    'bank',
    'dhl',
    'facebook',
    'google',
    'microsoft',
    'netflix',
    'paypal',
}

SUSPICIOUS_EXTENSIONS = {
    '.exe',
    '.scr',
    '.bat',
    '.cmd',
    '.js',
    '.vbs',
    '.zip',
    '.rar',
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
IP_HOST_PATTERN = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def analyze_email(raw_email):
    parsed = Parser(policy=policy.default).parsestr(raw_email)
    sender = parsed.get('From', 'Unknown sender')
    subject = parsed.get('Subject', 'No subject')
    reply_to = parsed.get('Reply-To', '')
    return_path = parsed.get('Return-Path', '')
    authentication_results = parsed.get('Authentication-Results', '')
    body = extract_body(parsed, raw_email)
    urls = extract_urls(raw_email)
    attachments = extract_attachments(parsed, raw_email)

    score = 0
    reasons = []
    safe_signals = []
    sender_domain = get_email_domain(sender)

    score += detect_keywords(body, subject, URGENCY_WORDS, 15, 'Urgency wording found', reasons)
    score += detect_keywords(body, subject, FINANCIAL_WORDS, 10, 'Financial wording found', reasons)
    score += detect_suspicious_urls(urls, sender_domain, reasons)
    score += detect_suspicious_attachments(attachments, reasons)
    score += detect_header_mismatches(sender, reply_to, return_path, reasons)
    score += detect_spoofed_sender(sender, reasons)
    score += detect_authentication_failures(authentication_results, reasons)
    safe_signals += detect_safe_signals(sender, reply_to, return_path, authentication_results, urls, attachments)

    score = min(score, 100)
    result_label, result_color = get_result(score)
    confidence = get_confidence(raw_email, authentication_results, urls, attachments)

    return {
        'sender': sender,
        'subject': subject,
        'reply_to': reply_to or 'Not found',
        'return_path': return_path or 'Not found',
        'authentication_results': authentication_results or 'Not found',
        'body': body,
        'body_preview': body[:500],
        'urls': urls,
        'attachments': attachments,
        'risk_score': score,
        'result_label': result_label,
        'result_color': result_color,
        'confidence': confidence,
        'reasons': reasons or ['No major phishing indicators were found.'],
        'safe_signals': safe_signals,
    }


def extract_body(parsed, raw_email):
    if parsed.is_multipart():
        parts = []
        for part in parsed.walk():
            if part.get_content_type() == 'text/plain' and not part.get_filename():
                parts.append(part.get_content())
            elif part.get_content_type() == 'text/html' and not part.get_filename():
                parts.append(strip_html(part.get_content()))
        return '\n'.join(parts).strip() or raw_email.strip()

    if parsed.get_content_type() == 'text/plain':
        return parsed.get_content().strip()

    if parsed.get_content_type() == 'text/html':
        return strip_html(parsed.get_content()).strip()

    return raw_email.strip()


def strip_html(html_text):
    text = re.sub(r'<br\s*/?>', '\n', html_text, flags=re.IGNORECASE)
    text = re.sub(r'</div>|</p>|</li>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = unescape(text)
    return re.sub(r'\n\s*\n+', '\n\n', text).strip()


def extract_urls(text):
    urls = []
    for url in URL_PATTERN.findall(text):
        cleaned_url = url.rstrip('.,);]')
        if cleaned_url not in urls:
            urls.append(cleaned_url)
    return urls


def extract_attachments(parsed, raw_email):
    attachments = []
    for part in parsed.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)

    if attachments:
        return attachments

    matches = re.findall(r'attachment(?: name| filename)?[:=]\s*["\']?([^"\'\n\r]+)', raw_email, re.IGNORECASE)
    return [match.strip() for match in matches]


def detect_keywords(body, subject, keywords, points, reason_prefix, reasons):
    text = f'{subject}\n{body}'.lower()
    matched = [word for word in keywords if word in text]
    if not matched:
        return 0

    reasons.append(f'{reason_prefix}: {", ".join(matched)}.')
    return min(len(matched) * points, 30)


def detect_suspicious_urls(urls, sender_domain, reasons):
    score = 0
    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname or ''
        clean_domain = domain.lower().removeprefix('www.')

        if parsed_url.scheme == 'http':
            score += 12
            reasons.append(f'URL uses insecure HTTP instead of HTTPS: {url}')

        if IP_HOST_PATTERN.match(clean_domain):
            score += 25
            reasons.append(f'URL uses an IP address instead of a domain: {url}')

        if clean_domain in SHORTENED_DOMAINS:
            score += 20
            reasons.append(f'URL uses a shortened link service: {url}')

        if is_unusual_domain(clean_domain):
            score += 15
            reasons.append(f'URL uses an unusual-looking domain: {clean_domain}')

        if sender_domain and clean_domain and sender_domain not in clean_domain:
            score += 15
            reasons.append(f'URL domain does not match sender domain: {url}')

    return min(score, 55)


def detect_suspicious_attachments(attachments, reasons):
    score = 0
    for attachment in attachments:
        lower_name = attachment.lower()
        if any(lower_name.endswith(extension) for extension in SUSPICIOUS_EXTENSIONS):
            score += 25
            reasons.append(f'Suspicious attachment type found: {attachment}')

    return min(score, 40)


def detect_header_mismatches(sender, reply_to, return_path, reasons):
    score = 0
    sender_domain = get_email_domain(sender)
    reply_domain = get_email_domain(reply_to)
    return_domain = get_email_domain(return_path)

    if sender_domain and reply_domain and sender_domain != reply_domain:
        score += 15
        reasons.append(f'Reply-To domain does not match sender domain: {reply_domain}')

    if sender_domain and return_domain and sender_domain != return_domain:
        score += 15
        reasons.append(f'Return-Path domain does not match sender domain: {return_domain}')

    return min(score, 25)


def detect_spoofed_sender(sender, reasons):
    display_name, email_address = parseaddr(sender)
    sender_domain = get_email_domain(sender)
    if not display_name or not sender_domain:
        return 0

    display_text = display_name.lower()
    for brand in KNOWN_BRANDS:
        if brand in display_text and brand not in sender_domain:
            reasons.append(
                f'Sender name mentions "{brand}" but the email domain is {sender_domain}.'
            )
            return 20

    if email_address and sender_domain not in email_address.lower():
        reasons.append('Sender header looks unusual or possibly spoofed.')
        return 10

    return 0


def detect_authentication_failures(authentication_results, reasons):
    if not authentication_results:
        return 0

    text = authentication_results.lower()
    score = 0
    for check_name in ['spf', 'dkim', 'dmarc']:
        if f'{check_name}=fail' in text or f'{check_name}=softfail' in text:
            score += 20
            reasons.append(f'Email authentication check failed: {check_name.upper()}')

    return min(score, 45)


def detect_safe_signals(sender, reply_to, return_path, authentication_results, urls, attachments):
    signals = []
    sender_domain = get_email_domain(sender)
    reply_domain = get_email_domain(reply_to)
    return_domain = get_email_domain(return_path)
    text = authentication_results.lower()

    if sender_domain:
        signals.append(f'Sender domain extracted successfully: {sender_domain}.')

    if reply_domain and sender_domain == reply_domain:
        signals.append('Reply-To domain matches the sender domain.')

    if return_domain and sender_domain == return_domain:
        signals.append('Return-Path domain matches the sender domain.')

    if 'spf=pass' in text:
        signals.append('SPF authentication passed.')

    if 'dmarc=pass' in text:
        signals.append('DMARC authentication passed.')

    if urls and all(urlparse(url).scheme == 'https' for url in urls):
        signals.append('Detected URLs use HTTPS.')

    if not urls:
        signals.append('No URLs were found in the email body.')

    if not attachments:
        signals.append('No attachments were found.')

    return signals


def is_unusual_domain(domain):
    if not domain:
        return False

    labels = domain.split('.')
    tld = labels[-1]
    domain_without_tld = '.'.join(labels[:-1])

    if domain.startswith('xn--') or '.xn--' in domain:
        return True
    if tld in UNUSUAL_TLDS:
        return True
    if len(labels) >= 4:
        return True
    if domain_without_tld.count('-') >= 2:
        return True
    if sum(character.isdigit() for character in domain_without_tld) >= 4:
        return True

    return False


def get_email_domain(sender):
    match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', sender)
    if not match:
        return ''
    return match.group(1).lower().removeprefix('www.')


def get_confidence(raw_email, authentication_results, urls, attachments):
    confidence = 55
    if 'From:' in raw_email and 'Subject:' in raw_email:
        confidence += 15
    if authentication_results:
        confidence += 15
    if urls:
        confidence += 10
    if attachments:
        confidence += 5
    return min(confidence, 95)


def get_result(score):
    if score >= 66:
        return 'Phishing', 'red'
    if score >= 31:
        return 'Suspicious', 'yellow'
    return 'Safe', 'green'


def dumps_list(items):
    return json.dumps(items)


def loads_list(value):
    if not value:
        return []
    return json.loads(value)
