# Good Hope Manor — Secure Website & Documents Portal

An accessible, responsive assisted-living information website with approved public documents and protected staff administration. The site preserves the client-approved Good Hope Manor copy, the Exterior & Arrival homepage image, approved interior photography, and the facility logo favicon. The public **Documents** tab shows only files that have been reviewed, approved, and are currently effective. A staff portal is linked at the bottom of the Documents page.

## System requirements

- **Node.js 22.13+** (the built-in `node:sqlite` runtime; experimental in Node 22)
- Python 3 for static validation
- A **single-instance host with private, durable persistent storage** for production. Do not deploy this SQLite build on ephemeral or multi-instance Autoscale hosting.
- Updated antivirus scanner such as **ClamAV** installed on the host to scan *every* document before approval. Production startup fails closed if AV is missing.
- HTTPS for production (production cookies use Secure, HttpOnly, SameSite=Strict)

No third-party runtime npm dependencies are required. ESLint and Prettier are development-only dependencies; run `npm ci` once before validating.

## Start and test locally

1. Set the private environment variable `INITIAL_ADMIN_PASSWORD` to a unique 14+ character password (do **not** use `password01`). Do not place it in source control.
2. Optionally set `GOODHOPE_DATA_DIR` to a private directory. The default development directory is `data/` (git-ignored).
3. Run `npm start`; browse to `http://127.0.0.1:3000` and open **Documents** at the top or **Admin Portal** at the bottom.
4. Log in with `admin` and the private initial password. The application forces a password change before administration.
5. Run `npm run validate` for site checks, ESLint, Prettier and automated security/API tests. Run `npm run format` to fix formatting. The test suite uses an explicitly marked fake scanner; it is **not** an antivirus certification. Upload tests need Linux or macOS, because the fake scanner is a `#!/usr/bin/env node` script that Windows cannot execute directly; CI runs them on Linux.

## Production configuration

Set secrets and deployment variables through your hosting provider, **not in the repository**.

| Setting | Requirement |
|---|---|
| `NODE_ENV` | `production` |
| `GOODHOPE_DATA_DIR` | **Absolute private mounted persistent volume**, outside the application checkout |
| `DEPLOYMENT_MODE` | `single-instance` (this version does not support multi-instance Autoscale) |
| `PUBLIC_BASE_URL` | `https://` URL of the final deployment |
| `AV_SCANNER` | Absolute path to installed, maintained executable such as ClamAV `clamscan` |
| `INITIAL_ADMIN_PASSWORD` | One-time private 14+ character bootstrap password; only required if no accounts exist |
| `INITIAL_ADMIN_EMAIL` | Owner-designated administrator email (defaults to facility contact) |
| `TRUST_PROXY_HOPS` | Number of trusted reverse proxies in front of the app (`1` on Replit and most hosts; `0`, the default, when reached directly). Without it, login rate limiting sees every visitor as the proxy's address |
| `EMAIL_PROVIDER` | Optional: `sendgrid` |
| `SENDGRID_API_KEY` / `FROM_EMAIL` | Optional, needed for automatic staff invitation emails |

The application **refuses production startup** without external persistent disk, HTTPS, explicitly selected single-instance mode, and an executable antivirus scanner. Simply setting `NODE_ENV=production` does **not** provision these services; your host must provide them. A writable file path alone is not proof the disk survives a redeploy. Verify that the chosen hosting plan has persistent volume guarantees and restore procedures.

## Roles and workflows

| Role | Access |
|---|---|
| Administrator | Staff accounts, roles, invites, audit history, upload/replace, approval, archive, delete |
| Editor | Upload, replace, archive, update metadata; **cannot approve** |
| Approver | View private documents and approve/unapprove; **cannot upload** |
| Guest | View/download only approved, effective, unarchived, unexpired documents |

- Uploads start **unapproved**. Validation checks file signature and safe format, limits size to 20 MB, and calls the configured malware scanner. Approved files become downloadable under a controlled API route. Direct upload directory access is blocked.
- A replacement creates a **new version** and automatically removes guest approval until reapproved. Old versions stay private for audit history.
- Administrators invite staff by a short-lived **one-time password-setup link**, rather than emailing plaintext passwords. Automatic email uses the optional SendGrid provider; without it the admin must securely deliver the displayed link.
- User disabling, password reset, password change and logout revoke sessions. Sessions live in the private SQLite database, not process memory.
- Audit events capture document approval, upload, replacement, metadata edits and user changes.

## Backup / disaster recovery

**Stop the web process before an offline backup** so documents and DB metadata are captured in a consistent state. Set `GOODHOPE_DATA_DIR` to the private storage root and run:

`node scripts/backup.js /absolute/path/to/new-backup-folder`

Backups include the SQLite database, every private file and a SHA-256 verification manifest. The destination must not exist. To restore into an empty data location **while the service is stopped**:

`node scripts/restore.js /absolute/backup-folder /absolute/empty-data-folder`

Keep encrypted offsite backups with retention and restore drills. Do not commit them. The backup utility is tested locally but doesn't schedule offsite backups for you.

For loss of the final administrator account, an authorized host operator can stop the site, set the private environment variables `GOODHOPE_DATA_DIR` and `RECOVERY_PASSWORD` (new long unique password), and run `node scripts/reset_admin.js admin`. This invalidates existing sessions and forces a fresh password change; it never prints the secret.

## Security limits and launch readiness

- This build is for a **single-instance, volume-backed deployment**. If you need Autoscale/multi-instance, migrate to a managed relational database + private object storage and replace the storage adapter before launch.
- Real antivirus availability and signatures, production TLS, DNS, upstream proxy settings, host backups, email delivery, and penetration testing **cannot be verified from the source package**.
- Do not publish real resident health/financial records or confidential materials via the guest Documents section. Owner and compliance approval remain necessary for the site's real content and records handling.
- GitHub workflows run automated tests and CodeQL on compatible repositories. Monitoring logs contain response status, route class and request duration without credentials. Connect logs to your production alerting platform.
- Do not assume previous `users.json` / `documents.json` are automatically migrated to the new SQLite database. Preserve an encrypted backup of old uploads and contact the developer to plan an explicit migration; do not place private legacy data in GitHub.

See `SECURITY_READINESS.md`, `TESTING_VALIDATION_REPORT.md`, and `DEPLOYMENT_CHECKLIST.md`.
