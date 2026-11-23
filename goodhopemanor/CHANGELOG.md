# Changelog

## Unreleased

### Fixed

- Removed an internal note ("photographs … should be actual Good Hope Manor photographs") that was visible on the Home and Life pages.
- Removed a duplicated copy of the homepage introduction; every page now has exactly one `<h1>`, and homepage sub-headings are `<h3>`.
- The admin audit view no longer fails when an audit entry's details were too long. Long details used to be cut part-way through the JSON.
- Login rate limiting now uses the real client address behind a reverse proxy (`TRUST_PROXY_HOPS`). Before, every visitor shared the proxy's address, so 30 failed logins from anyone locked out all staff.
- Download integrity checks hash the file in streamed chunks instead of reading it whole, so large downloads no longer block other requests.
- The mock virus scanner and shell scripts are now executable on Linux.

### Changed

- CI, CodeQL and Dependabot configuration moved to the repository root so that they run.
- Added ESLint and Prettier, enforced in CI; JavaScript, CSS, JSON and YAML were reformatted.
- The 12 public pages are generated from one shared layout in `site/` (`npm run build:pages`). CI fails if a generated page is out of date.
- Images are 42% smaller; every image has `width`/`height`, so the layout no longer shifts while they load.
- Added canonical URLs and absolute link-preview (`og:`) tags; the 404 page is `noindex`; the homepage has a descriptive title.
- Documents page: category filters are toggle buttons with `aria-pressed`, and document details are edited in an inline form with date pickers instead of browser prompts.
- Scripts load from `<head>` with `defer`.
- Documentation moved to `docs/`.

### Removed

- `scripts/validate_site.py`, a broken, unused duplicate of the static check.
- `TESTING_VALIDATION_REPORT.md` and `GITHUB_UPLOAD_GUIDE.md`, one-off documents that had gone out of date.

### Corrections to the 2.0.0 notes below

- "GitHub Actions validation/CodeQL" were added as files but **did not run**: they lived outside the repository root. The test results reported at the time were not produced by this repository's CI.
- "Coverage reporting" was not configured in any script.
- The backend was split into modules, but the code was still written in a minified style until ESLint and Prettier were added.

## Security & Quality Release 2.0.0

### Resolved code-level findings

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

### Operational prerequisites not completed inside source code

Deploy on a real **single-instance durable volume**, configure HTTPS and an installed updated ClamAV executable, verify SendGrid settings (if used), and arrange external pen testing, offsite backup scheduling and owner acceptance. Multi-instance / Autoscale requires a different managed database/object-storage adapter.
