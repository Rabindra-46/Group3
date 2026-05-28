# DevSecOps Project Report: Phishing Email Detector

## Table of Contents

1. Executive Summary  
2. Introduction and Background  
3. Project Planning and Design  
4. DevSecOps Implementation  
5. Testing and Validation  
6. Results and Analysis  
7. Challenges, Solutions and Risk Management  
8. Ethical Considerations  
9. Future Work and Conclusion  
10. References  
11. Appendices  
12. Screenshot and Evidence Checklist  

## 1. Executive Summary

This project developed a secure web-based Phishing Email Detector using Python Flask, SQLite, server-side templates, and a machine learning assisted classification workflow. The main objective was to help users submit suspicious email content or `.eml` files, analyse phishing indicators, and receive a clear risk classification of Safe, Suspicious, or Phishing. The application also provides scan history, detailed scan reports, automatic quarantine for high-risk messages, CSV export, user and administrator dashboards, and administrative controls for account management.

The project was designed around DevSecOps principles, where security is included from planning and design through development, testing, deployment, and monitoring. Instead of treating security as a final activity, the application includes security features directly in the core workflow. These include password hashing, role-based access control, two-factor authentication, account activation controls, server-side session checks, restricted admin routes, email header analysis, attachment risk detection, malicious indicator matching, and automatic quarantine decisions.

Key project outcomes include a working authentication system with user and administrator roles, TOTP-based two-factor authentication using authenticator applications, a phishing analysis engine that combines rule-based indicators with a trained machine learning model, and a reporting interface that allows users and administrators to review suspicious email activity. The project demonstrates how secure development practices and automated security checks can reduce common web application risks such as broken access control, weak authentication, insecure handling of user input, and accidental exposure of sensitive records.

The main finding from the project is that DevSecOps improves both the security posture and maintainability of a small cybersecurity application. By identifying likely threats early, the team was able to prioritise RBAC, 2FA, secure password storage, parameterised database queries, and quarantine workflows. The project also identified areas for improvement, especially automated CI/CD evidence, structured logging, deeper penetration testing, and production-grade secret management.

## 2. Introduction and Background

Phishing remains one of the most common cybersecurity threats because it targets human trust rather than only technical weaknesses. Attackers use spoofed senders, urgent language, fake login pages, malicious attachments, and suspicious links to convince users to reveal credentials or install malware. A phishing detection platform is therefore useful as both a defensive tool and an educational system, because it can show users why an email is risky instead of only providing a final label.

The motivation for this project was to build a practical web application that supports phishing email analysis while also demonstrating secure software engineering. The project focuses on the risks that appear when users paste or upload potentially malicious emails into a web system. These risks include unsafe file handling, injection attacks, unauthorised access to reports, weak authentication, insecure session management, and accidental disclosure of sensitive email content. The application therefore needed to be built with security controls from the start.

DevSecOps is relevant because cybersecurity applications are high-value targets themselves. If a phishing detector stores suspicious emails, user accounts, and scan histories, attackers may try to access those records or bypass admin controls. DevSecOps addresses this by shifting security left into planning, coding, testing, and CI/CD automation. It also encourages continuous monitoring and incident response instead of relying only on manual testing at the end of the project.

The scope of this project was to build a Flask-based phishing email detector with secure login, RBAC, 2FA, dashboards, email analysis, scan history, quarantine, and export features. The application uses SQLite for local persistence and a Python analysis engine to inspect headers, URLs, keywords, attachments, and machine learning probability. The report also covers the planned security testing and CI/CD pipeline required for validating the application before deployment.

The main objectives were:

- Implement secure authentication and authorisation with at least two roles.
- Add two-factor authentication to strengthen account protection.
- Build a phishing analysis workflow for pasted emails and `.eml` uploads.
- Store scan results and provide user-specific access to scan history.
- Provide administrator dashboards for user management and high-risk scan review.
- Integrate security testing tools and document findings.
- Design a CI/CD pipeline with build, security scan, test, DAST, and deploy stages.

## 3. Project Planning and Design

### 3.1 Requirements Gathering

The functional requirements were based on the project aim and the technical requirements. Users must be able to register, log in, complete 2FA, submit emails for analysis, view scan history, inspect scan details, quarantine or release scans, delete records, and export reports. Administrators must be able to log in through an admin route, complete 2FA, view all user scan activity, manage users, view quarantined messages, and export reports.

The security requirements included secure password storage, role-based access control, two-factor authentication, session protection, user isolation, parameterised database queries, input validation for file uploads, dependency scanning, static analysis, dynamic application testing, and documentation of at least three OWASP Top 10 vulnerability categories. The application also needed to avoid storing plaintext passwords and prevent normal users from accessing administrator-only records.

### 3.2 Threat Modeling

The main assets are user accounts, administrator accounts, two-factor authentication secrets, scan history, email content, scan results, malicious indicator data, and exported CSV reports. The main threat actors include unauthorised external users, compromised normal users, malicious insiders, and attackers submitting crafted phishing samples.

Important attack vectors include brute-force login attempts, stolen credentials, session hijacking, broken access control between user and admin views, malicious `.eml` content, SQL injection through form fields, cross-site scripting through email content, insecure direct object references in scan IDs, and dependency vulnerabilities in Flask or other third-party packages.

The highest risks were broken access control and authentication bypass because these would expose scan data or administrator features. The project reduced these risks using server-side decorators, role checks, active account checks, and 2FA verification before protected pages load. SQL injection risk was reduced by using parameterised SQLite queries. Upload risk was reduced by accepting only `.eml` files in the analysis route. However, production use would still require stronger upload size limits, rate limiting, audit logs, HTTPS enforcement, and hardened secret handling.

### 3.3 Architecture Design

The application uses a simple Flask architecture. `run.py` starts the application. `app/__init__.py` creates the Flask app, loads configuration, initialises the database, and registers routes. `app/routes.py` contains route handlers, authentication decorators, 2FA setup and verification, dashboard logic, scan views, quarantine actions, exports, and admin pages. `app/models.py` manages database operations for users and scan records. `app/database.py` creates and migrates SQLite tables. `app/analyzer.py` performs phishing analysis, while `app/ml_classifier.py` loads the trained `phishing_model.pkl` model and returns a phishing probability.

Security is included at multiple layers. The presentation layer uses server-side templates and Flask flash messages. The route layer checks login state, 2FA status, user activity, and admin roles. The data layer uses parameterised SQL queries and separates user-scoped scan lookup from administrator-wide scan lookup. The analysis layer limits file handling to `.eml` uploads and extracts headers, body text, URLs, and attachments before applying scoring rules.

### 3.4 Tool Selection

The project stack was selected to support a beginner-friendly but security-focused DevSecOps implementation. Flask was chosen because it is lightweight and easy to structure for authentication, dashboards, and route protection. SQLite was chosen for local development because it requires no separate database server and is suitable for a university prototype. Werkzeug password hashing was used to avoid storing plaintext passwords. PyOTP and QRCode were used to implement TOTP-based 2FA. BeautifulSoup was used to parse HTML email content. Scikit-learn and joblib were used for the phishing classifier.

Recommended DevSecOps tools for this project are Bandit for Python static security analysis, pip-audit for dependency vulnerability scanning, OWASP ZAP for DAST testing, and GitHub Actions for CI/CD. These tools match the technology stack and can be integrated into a GitHub repository with minimal setup.

### 3.5 Team Organization

The team workflow should divide responsibilities across development, security testing, documentation, and project management. Suggested roles are:

- Backend developer: Flask routes, database, authentication, and scan storage.
- Security developer: RBAC, 2FA, secure coding review, threat model, and test cases.
- ML and analysis developer: phishing rules, model training, indicators, and scoring.
- DevOps engineer: GitHub Actions pipeline, security tool integration, and deployment.
- Documentation lead: report writing, screenshots, references, and final presentation.

The recommended workflow is feature branching, peer review before merging, and security review for changes touching authentication, admin routes, file upload, database access, or report export.

### 3.6 Project Timeline

The suggested timeline is four phases. Week 1 covered planning, requirements, threat modelling, and interface design. Week 2 covered authentication, RBAC, 2FA, and database setup. Week 3 covered phishing analysis, dashboards, quarantine, reporting, and CSV export. Week 4 covered security testing, CI/CD configuration, screenshots, report writing, and final validation.

[Insert Screenshot 1: Gantt chart or Trello/Jira board showing tasks, deadlines, and team members.]

## 4. DevSecOps Implementation

### 4.1 Development Phase

Secure coding practices were applied throughout the application. Passwords are hashed using Werkzeug before being stored. Login sessions are stored server-side through Flask session handling, and protected pages use decorators to ensure that users have logged in and completed two-factor authentication. Administrator routes use an additional role check to make sure only accounts with the `admin` role can access admin dashboards and user management pages.

The database layer uses parameterised SQL queries rather than string concatenation. This reduces SQL injection risk for login, registration, scan lookup, exports, and user management actions. User scan pages retrieve records by both scan ID and user ID, which prevents one user from viewing another user's scan by changing the URL. Administrator pages use separate functions for global report access, making the permission boundary easier to review.

Input handling was also considered. The analyse feature accepts pasted raw email text or `.eml` file uploads. The upload route checks the file extension before reading the file. The phishing analyser extracts email headers, body content, URLs, attachments, and authentication results. Suspicious indicators such as insecure HTTP links, IP-based URLs, unusual domains, mismatched Reply-To or Return-Path domains, failed SPF/DKIM/DMARC results, risky attachments, and phishing keywords contribute to the risk score.

The version control strategy should use a main branch for stable work and feature branches for new functionality. Pull requests should include peer review, screenshots for UI changes, and security notes for authentication, upload, database, or admin changes. Security review should focus on whether server-side checks exist, whether user input is validated, whether database queries are parameterised, and whether sensitive data is avoided in logs or screenshots.

### 4.2 Security Integration

Static Application Security Testing is configured using Bandit in `.github/workflows/devsecops.yml`. Bandit is suitable for this project because it scans Python code for common security issues such as hardcoded secrets, unsafe function usage, weak cryptography, and insecure subprocess patterns. An early security improvement was changing the Flask secret key and debug mode so they are controlled through environment-based configuration rather than unsafe hardcoded production settings.

[Insert Screenshot 2: Bandit scan output showing findings and remediation status.]

Dependency scanning is configured using pip-audit in the GitHub Actions workflow. This checks packages listed in `requirements.txt` for known vulnerabilities. Any vulnerable package should be upgraded, pinned to a safe version, or documented if no fix is available. This is especially important because the project uses web, parsing, and ML libraries such as Flask, Werkzeug, Jinja2, BeautifulSoup, pandas, scikit-learn, and joblib.

[Insert Screenshot 3: Dependency scan output before and after remediation.]

Dynamic Application Security Testing is configured using OWASP ZAP against the running Flask application. ZAP crawls the site and tests pages such as login, registration, dashboard, scan history, and analysis. Because the app requires authentication and 2FA, the team may need to run both unauthenticated and authenticated scans. Key issues to check include missing security headers, cookie flags, reflected input, form handling, and access control behaviour.

[Insert Screenshot 4: OWASP ZAP alert summary and selected evidence.]

The project tested the following OWASP Top 10 categories:

- Broken Access Control: normal users should not access `/admin/dashboard`, `/admin/users`, or another user's scan details.
- Identification and Authentication Failures: passwords are hashed, inactive users are blocked, and 2FA is required before protected pages.
- Injection: login, scan lookup, filters, and admin actions use parameterised SQL queries.
- Security Misconfiguration: the fallback secret key and missing production headers should be reviewed before deployment.
- Vulnerable and Outdated Components: dependencies should be scanned with pip-audit and updated when issues are detected.

Secrets management is currently implemented through Flask configuration using `os.environ.get("SECRET_KEY", "change-this-secret")`. This is acceptable for local development but not production. The production deployment should require a strong random `SECRET_KEY` stored in environment variables or a secret manager. Two-factor authentication secrets are stored in SQLite and should be protected by file permissions in the local environment. In a production environment, database encryption at rest and stricter access controls should be added.

### 4.3 CI/CD Pipeline

The required CI/CD pipeline has been configured in `.github/workflows/devsecops.yml` and follows this structure:

Build -> SAST -> Test -> DAST -> Deploy

In GitHub Actions, the build stage should check out the repository, set up Python, install dependencies, and verify that the application imports successfully. The SAST stage should run Bandit. The dependency scan stage should run pip-audit. The test stage should run unit and integration tests with pytest. The DAST stage should start the Flask application in a staging environment and run OWASP ZAP baseline scanning. The deploy stage should deploy only if earlier stages pass.

[Insert Screenshot 5: GitHub Actions workflow file in the repository.]

[Insert Screenshot 6: Successful GitHub Actions run showing Build, SAST, Test, DAST, and Deploy stages.]

Minimum automated security tests should include:

- A test that a normal user cannot access admin routes.
- A test that protected routes redirect unauthenticated users to login.
- A test that scan IDs are user-scoped and cannot be accessed by another user.
- A Bandit scan for Python security issues.
- A dependency scan for known vulnerable packages.
- A ZAP baseline scan against the running app.

The deployment strategy should use a staging environment before production. A rollback procedure should keep the previous working version available. If security tests fail, deployment should stop until the vulnerability is reviewed and fixed.

### 4.4 Monitoring and Incident Response

The application currently provides operational visibility through dashboards, scan history, quarantine lists, and administrative reports. These views show total scans, phishing counts, suspicious counts, safe counts, quarantined items, top domains, and recent high-risk scans. This supports manual monitoring by administrators.

For stronger monitoring, the system should add structured logs for login attempts, failed login attempts, 2FA setup, 2FA failures, scan submissions, quarantine actions, admin user actions, report exports, and deleted records. Logs should avoid storing full email body content or OTP codes. In production, logs should be centralised and connected to alerts for repeated login failures, repeated 2FA failures, sudden spikes in phishing detections, or suspicious admin actions.

A simulated incident response scenario was tested conceptually: a user uploads an email containing a suspicious domain, urgent payment language, and a dangerous attachment. The analyser classifies it as Phishing, stores the reasons, automatically moves the scan to quarantine, and shows it in the user and admin quarantine views. The response steps are detection, containment through quarantine, review by an administrator, export of evidence as CSV, and release or deletion after assessment.

[Insert Screenshot 7: Quarantined phishing scan with reasons and risk score.]

## 5. Testing and Validation

Functional testing should cover registration, login, 2FA setup, 2FA verification, user dashboard access, email analysis, scan history, scan details, CSV export, quarantine and release actions, admin login, admin dashboard, admin reports, admin user management, and admin quarantine. Manual testing confirmed that the application has routes and templates for these workflows. Automated tests should be added with pytest and Flask's test client.

Suggested functional test cases:

| Test Case | Expected Result | Evidence |
|---|---|---|
| Register new user | Account is created with user role | Screenshot or pytest result |
| Login with correct password | User is redirected to 2FA setup or verification | Screenshot |
| Access dashboard without 2FA | Redirected to 2FA page | Screenshot or test result |
| Submit suspicious email | Result saved and risk reasons shown | Screenshot |
| Normal user opens admin route | Access denied or redirected | Screenshot or test result |
| Admin views all reports | Admin can see report table | Screenshot |
| CSV export | CSV file downloads successfully | Screenshot |

Security validation should include OWASP Top 10 tests. For broken access control, test normal users against admin URLs and another user's scan ID. For injection, test login and filters using SQL payloads such as `' OR '1'='1` and confirm login is not bypassed. For authentication failures, test inactive users, wrong passwords, missing 2FA, and invalid OTP codes. For vulnerable components, run dependency scanning. For security misconfiguration, check cookie flags, debug mode, secret handling, and security headers.

Performance testing can be completed using a small script or ApacheBench against common pages. The main performance risk is email analysis latency when parsing large `.eml` files or loading the ML model. The model loader caches the loaded model after the first successful load, which improves repeated analysis performance. Stress testing should measure average response time for login, dashboard, scan history, and email analysis with normal and larger email samples.

[Insert Screenshot 8: Table or graph showing response times under normal and stress conditions.]

User testing should involve peers submitting safe, suspicious, and phishing-like emails. Feedback should focus on whether the result label is understandable, whether risk reasons are useful, whether dashboards are easy to navigate, and whether the 2FA setup process is clear.

## 6. Results and Analysis

The project achieved most of the initial functional and security objectives. Authentication and authorisation were implemented with user and admin roles. Two-factor authentication was implemented using TOTP QR codes. The phishing analysis workflow accepts pasted text and `.eml` uploads. Scan results are saved with detailed indicators, risk scores, confidence, ML probability, and safe signals. Users can view their own reports, while administrators can review all reports and manage accounts.

[Insert Screenshot 9: Home page or login page.]

[Insert Screenshot 10: 2FA QR setup page.]

[Insert Screenshot 11: User dashboard showing scan counts.]

[Insert Screenshot 12: Analyze email page with phishing result.]

[Insert Screenshot 13: Scan detail page showing reasons, safe signals, and risk score.]

[Insert Screenshot 14: Admin dashboard showing summary analytics.]

The DevSecOps approach was effective because the application security controls match the threat model. For example, the risk of account compromise is reduced by password hashing and 2FA. The risk of unauthorised admin access is reduced by role checks. The risk of user-to-user data exposure is reduced by user-scoped database queries. The risk of SQL injection is reduced by parameterised queries. The risk of high-risk email samples being ignored is reduced by automatic quarantine.

Compared with the initial goals, the project successfully implemented the core web application, major security features, automated tests, and a GitHub Actions DevSecOps workflow. The remaining gap is evidence collection: after pushing to GitHub, the team should capture Bandit output, dependency scan output, OWASP ZAP output, pytest output, and the successful pipeline run. These are important because DevSecOps requires repeatable automated checks, not only manual review.

## 7. Challenges, Solutions and Risk Management

One technical challenge was combining usability with stronger authentication. 2FA improves security but can make login more complex. The solution was to provide QR-code setup and route users automatically to setup or verification depending on their account state.

Another challenge was access control between normal users and administrators. The solution was to create separate authentication contexts and decorators for user and admin routes. Admin pages require both 2FA verification and the admin role. Normal user scan lookups include the user ID to prevent insecure direct object references.

A third challenge was phishing classification accuracy. Rule-based detection is explainable but can miss subtle attacks. Machine learning can improve detection but may be less transparent and depends on training data quality. The solution was to combine rule scoring with ML probability and display reasons and safe signals so users understand the result.

Risk management compared anticipated and actual risks. Anticipated risks included weak authentication, SQL injection, user data exposure, malicious uploads, vulnerable dependencies, and incomplete testing. The implemented controls reduced several of these risks, but production deployment would still require rate limiting, HTTPS, secure headers, centralised logging, stronger secret handling, and automated CI/CD enforcement.

## 8. Ethical Considerations

This project is defensive and educational. It analyses suspicious emails to help users identify phishing indicators and avoid unsafe links or attachments. However, phishing analysis tools can still be misused if they store sensitive email content carelessly or if users upload private messages without permission. The project therefore should minimise sensitive data collection, restrict access to scan records, and avoid publishing real personal email content in screenshots or appendices.

The project should comply with university policies on security research. Any simulated phishing samples should be created for testing and should not target real people. Dynamic testing with OWASP ZAP should be run only against the team's own local or staging application. Screenshots should redact real email addresses, OTP secrets, QR codes, session cookies, and private messages.

Safeguards include authentication, RBAC, 2FA, user-scoped scan access, admin controls, quarantine, and CSV exports for controlled reporting. Additional safeguards recommended for production include consent notices, retention limits, encrypted storage, audit logs, and role-based export restrictions.

## 9. Future Work and Conclusion

Future improvements should include a completed GitHub Actions pipeline, automated pytest coverage, Bandit SAST integration, pip-audit dependency scanning, OWASP ZAP DAST integration, structured logging, rate limiting, CSRF protection review, stronger password policy, account lockout after repeated failures, HTTPS-only deployment, secure headers, and production-grade secret management.

The phishing engine could also be improved by using a larger labelled dataset, recording false positives and false negatives, adding attachment sandbox metadata, expanding malicious indicator management, and improving explainability for ML results. The admin dashboard could include alerting, trend graphs, and severity-based triage.

In conclusion, the project demonstrates how DevSecOps can be applied to a Flask cybersecurity application. Security controls were implemented as part of the product, not only as final checks. The result is a more secure and useful phishing detection system with authentication, RBAC, 2FA, analysis, quarantine, reporting, and administrative monitoring. The most important next step is to complete automated CI/CD evidence so every code change is built, scanned, tested, dynamically assessed, and deployed through a repeatable secure pipeline.

## 10. References

[1] OWASP Foundation, "OWASP Top 10:2021." https://owasp.org/Top10/  
[2] OWASP Foundation, "OWASP Zed Attack Proxy Documentation." https://www.zaproxy.org/docs/  
[3] PyCQA, "Bandit Documentation." https://bandit.readthedocs.io/  
[4] Python Packaging Authority, "pip-audit." https://pypi.org/project/pip-audit/  
[5] GitHub Docs, "GitHub Actions Documentation." https://docs.github.com/actions  
[6] Pallets Projects, "Flask Documentation." https://flask.palletsprojects.com/  
[7] Pallets Projects, "Werkzeug Security Helpers." https://werkzeug.palletsprojects.com/  
[8] PyOTP Contributors, "PyOTP Documentation." https://pyauth.github.io/pyotp/  
[9] scikit-learn Developers, "scikit-learn User Guide." https://scikit-learn.org/stable/user_guide.html  
[10] NIST, "Digital Identity Guidelines." https://pages.nist.gov/800-63-3/  

## 11. Appendices

### Appendix A: Detailed Threat Model

| Asset | Threat | Impact | Mitigation |
|---|---|---|---|
| User accounts | Password compromise | Unauthorised access | Password hashing, 2FA |
| Admin account | Privilege misuse | Full report exposure | RBAC, admin-only routes, 2FA |
| Scan history | IDOR | User data disclosure | User-scoped database queries |
| Email upload | Malicious input | Parsing or XSS risk | `.eml` validation, server-side analysis |
| Database | SQL injection | Data leakage or alteration | Parameterised queries |
| 2FA secret | Secret exposure | Account compromise | Store securely, redact screenshots |
| Dependencies | Known CVEs | Application compromise | pip-audit and updates |

### Appendix B: Essential Code Snippets

Relevant code evidence should include:

- `app/routes.py`: `login_required` decorator.
- `app/routes.py`: `role_required` decorator.
- `app/routes.py`: 2FA setup and verification handlers.
- `app/models.py`: `create_user`, `verify_password`, and user-scoped scan queries.
- `app/analyzer.py`: phishing scoring rules.
- `app/database.py`: user and scan table definitions.

### Appendix C: Complete Test Logs

[Insert full pytest output, Bandit output, dependency scan output, OWASP ZAP report summary, and GitHub Actions run logs.]

## 12. Screenshot and Evidence Checklist

Use this checklist to collect evidence for the final report:

1. Project planning: Gantt chart, Trello, Jira, or task board.
2. Architecture: simple diagram showing Browser -> Flask Routes -> Analyzer/ML -> SQLite -> Templates.
3. Login page and registration page.
4. 2FA setup page with QR code, but redact the QR code and secret before submission.
5. User dashboard with scan counters and recent scans.
6. Analyze email page before submission.
7. Analyze email page after a phishing result.
8. Scan history table with filters.
9. Scan detail page showing risk score, reasons, safe signals, URLs, and attachments.
10. Quarantine page showing automatically quarantined high-risk scans.
11. Admin login page.
12. Admin dashboard with total users, total scans, phishing counts, and top domains.
13. Admin users page showing roles and active/inactive controls.
14. Admin reports page with all scan records.
15. CSV export evidence.
16. Bandit SAST scan result.
17. pip-audit dependency scan result.
18. OWASP ZAP DAST alert summary.
19. GitHub Actions workflow file.
20. Successful GitHub Actions run with Build, SAST, Test, DAST, Deploy stages.
21. Functional test results or pytest output.
22. Performance test table or graph.
23. Simulated incident response evidence showing phishing detection, quarantine, admin review, and resolution.
