# Phishing Email Detector

A beginner-friendly Flask web application scaffold for a phishing email detection dashboard.

## Features

- Python Flask application structure
- SQLite database support
- Simple login flow
- Home page, login page, registration page, and dashboard page
- Prepared for future RBAC and 2FA integration

## Authentication

- User registration with email and password
- Secure password hashing with `werkzeug.security`
- Session-based login/logout flow

## Project structure

- `app/` - Flask application package
- `templates/` - HTML templates for pages
- `static/css/` - CSS styling
- `run.py` - Application entry point
- `requirements.txt` - Python dependencies
- `.gitignore` - Files and folders to ignore in Git

## Setup

1. Create a Python virtual environment:
   ```bash
   python -m venv venv
   ```
2. Activate the environment:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the app:
   ```bash
   python run.py
   ```

## Notes

- The database file is created automatically in `data/app.db`.
- Authentication and user management are intentionally simple so the app is easy to extend.
- Future enhancements may include advanced RBAC roles and 2FA flows.
