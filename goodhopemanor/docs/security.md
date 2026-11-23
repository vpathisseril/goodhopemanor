# Code Quality & Security Remediation Matrix

This matrix documents **source-level controls**. It is not a third-party audit, legal compliance determination, proof of deployed infrastructure security, or a claim that all operational risks are eliminated.

| Prior finding | Remediation in this version | Verification | Residual deployment requirement |
|---|---|---|---|
| JSON/in-memory sessions and unreliable disk | Transactional SQLite WAL database for users, metadata, persistent sessions and audit; private file storage; offline backup/restore with hashes | Persistence and backup/restore tests | Mount a host-guaranteed persistent volume on **single-instance** deployment; schedule offsite backups |
| Spoofed `.pdf` accepted | Validate actual magic/signatures, DOCX safe ZIP entries and bounded decompression; allowlist formats; require AV success before approval | Negative tests for forged extension and infected file | Install updated ClamAV (or compatible scanner) and test it on deployed host |
| Every new user was an admin | Role-restricted admin/editor/approver routes and UI with explicit role choice | Permission boundary tests | Facility must assign and periodically review user roles |
| Session revocation missing | DB-backed hashed session IDs, 30-minute idle and 8-hour absolute limits, logout, reset/change/disable revocation | Session and persistence tests | TLS, secure cookies and periodic account reviews |
| Password recovery weak | High-entropy one-time expiring invite/reset tokens, scrypt hashes, 14-character password policy, first-use reset | Token replay and password tests | Configure a verified SendGrid sender for automatic delivery (manual secure handoff otherwise) |
| Missing document versioning/audit | Immutable version rows, approval reset upon replacement or edit, audit history | Versioning and approval tests | Agree on retention/deletion policy with owner |
| Insufficient security tests | Unit+HTTP end-to-end positive and negative tests, static checks, CI workflow and CodeQL workflow. (The workflows sat outside the repository root and did not run until they were moved there.) | `npm run validate` in GitHub Actions | Independent external security review and production tests |
| Minified/monolithic JS | Server split into config/database/security/uploads/responses/email modules. Code was still written in a compressed, minified style until ESLint and Prettier were added and enforced in CI | ESLint, Prettier check, syntax and static checks | Code review |
| Dependency risk | No third-party runtime packages; Dependabot for GitHub Actions and any future npm packages | `npm ls --all` | Update Node runtime and ClamAV definitions; monitor CVEs |
| Lack of observability | Structured status/duration/request ID logs, admin audit history, health endpoint | Local tests | Attach log forwarding, alarms and retention on hosting provider |

## Explicit residual risks / constraints

- **Multi-instance/AUTOSCALE is not supported** with file-backed SQLite+local blobs. Production startup rejects deployment modes other than `single-instance`. Host-durable volumes must actually persist across upgrades; this cannot be established in local tests.
- Antivirus testing uses a **mock test scanner**; actual ClamAV signature freshness, behavior and platform deployment must be validated before go-live.
- `node:sqlite` is available in Node 22 but has an experimental status there. Pin and test the runtime; consider moving to a stable managed database for higher-scale use.
- No independent pentest, dynamic dependency vulnerability scan or third-party accessibility audit was run. Run them before handling real facility documents.
- This website must not be used as a public repository of residents' protected medical or financial data.
