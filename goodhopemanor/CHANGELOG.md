# Security & Quality Release 2.0.0

## Resolved code-level findings

- Replaced monolithic, minified backend with modular HTTP routing, security, database, file validation, email, response and configuration modules.
- Replaced JSON records and memory sessions with a transactional SQLite database and persistent, hashed session IDs; supports a **single-instance deployment with mounted private persistent storage**.
- Introduced documented offline database/file backup, SHA-256 integrity manifests, verified restore and owner-approved offline account recovery.
- Implemented role-based access for Administrator, Editor and Approver, including safe last-admin retention, account disable and session revocation.
- Replaced shared/default passwords for new users with secure single-use expiring invitation links; added scrypt password hashing and 14-character password policy.
- Added first-login password change, logout, session idle and absolute expiration, password reset and self-service password change.
- Added file-content signature checks, bounded DOCX ZIP inspection, 20 MB limit, extension allowlist and **antivirus scan enforcement before approval**.
- Added default-private documents, approval/expiry/archive rules, version history, audit events, and SHA-256 integrity checks before download.
- Added CSRF checks, origin checks, secure session cookies, response security headers, script/CSS-only static serving, rate limiting and structured request logs.
- Replaced dynamic HTML templating of user content with safe DOM text APIs, improved photo overlay accessibility and mobile navigation keyboard behavior.
- Added unit, integration and negative security tests, coverage reporting, GitHub Actions validation/CodeQL, and dependency-update configuration.
- Preserved approved Good Hope Manor text and photos; removed the client-rejected referral-page developer note.

## Operational prerequisites not completed inside source code

Deploy on a real **single-instance durable volume**, configure HTTPS and an installed updated ClamAV executable, verify SendGrid settings (if used), and arrange external pen testing, offsite backup scheduling and owner acceptance. Multi-instance / Autoscale requires a different managed database/object-storage adapter.
