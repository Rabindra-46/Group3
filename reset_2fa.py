import sys

from app import create_app
from app.database import get_db


def main():
    if len(sys.argv) != 2:
        print('Usage: python reset_2fa.py user@example.com')
        return

    email = sys.argv[1].strip().lower()
    app = create_app()

    with app.app_context():
        db = get_db()
        cursor = db.execute(
            '''
            UPDATE users
            SET is_2fa_enabled = 0,
                two_factor_secret = NULL
            WHERE email = ?
            ''',
            (email,),
        )
        db.commit()

    if cursor.rowcount:
        print(f'2FA reset for {email}. Log in again to scan a new QR code.')
    else:
        print(f'No user found for {email}.')


if __name__ == '__main__':
    main()
