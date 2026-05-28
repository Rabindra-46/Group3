from app import create_app
from app.config import Config
from app.models import create_user, find_user_by_email, list_email_scans


def make_test_app(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, 'DATABASE', str(tmp_path / 'test_app.db'))
    monkeypatch.setattr(Config, 'SECRET_KEY', 'test-secret-key')

    app = create_app()
    app.config.update(TESTING=True)
    return app


def test_protected_dashboard_redirects_without_login(tmp_path, monkeypatch):
    app = make_test_app(tmp_path, monkeypatch)
    client = app.test_client()

    response = client.get('/dashboard')

    assert response.status_code == 302
    assert '/login' in response.headers['Location']


def test_normal_user_cannot_access_admin_dashboard(tmp_path, monkeypatch):
    app = make_test_app(tmp_path, monkeypatch)
    client = app.test_client()

    with app.app_context():
        create_user('user@example.com', 'Password123!')
        user = find_user_by_email('user@example.com')

    with client.session_transaction() as session:
        session['admin_auth'] = {
            'user_id': user['id'],
            'user_email': user['email'],
            'user_role': user['role'],
            'is_2fa_verified': True,
        }

    response = client.get('/admin/dashboard')

    assert response.status_code == 302
    assert '/dashboard' in response.headers['Location']


def test_authenticated_user_can_scan_phishing_email(tmp_path, monkeypatch):
    app = make_test_app(tmp_path, monkeypatch)
    client = app.test_client()

    with app.app_context():
        create_user('analyst@example.com', 'Password123!')
        user = find_user_by_email('analyst@example.com')

    with client.session_transaction() as session:
        session['user_auth'] = {
            'user_id': user['id'],
            'user_email': user['email'],
            'user_role': user['role'],
            'is_2fa_verified': True,
        }

    suspicious_email = """From: PayPal Support <security@evil-example.xyz>
Subject: urgent verify now
Reply-To: attacker@example.ru
Authentication-Results: spf=fail dkim=fail dmarc=fail

Your account is suspended. Verify now at http://192.168.1.10/login and update your password.
"""

    response = client.post(
        '/analyze',
        data={'raw_email': suspicious_email},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app.app_context():
        scans = list_email_scans(user['id'])
        assert len(scans) == 1
        assert scans[0]['result_label'] in ['Suspicious', 'Phishing']
        assert scans[0]['is_quarantined'] is True
