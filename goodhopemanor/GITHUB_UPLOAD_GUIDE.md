# Good Hope Manor GitHub / Replit deployment

- Upload the contents of this folder into the `goodhopemanor` repository root or put the folder under `goodhopemanor/` inside an existing repository.
- Preserve `.gitignore`; never include `.env`, `data/`, private uploads, backups, passwords or user records.
- GitHub Actions validates the static site and Node tests. CodeQL scans JavaScript when the repository supports it.
- In the Replit project, use Node 22 and configure a **single-instance durable persistent volume**; an ephemeral filesystem or Autoscale is **not supported** by this build.
- Configure HTTPS, `PUBLIC_BASE_URL`, `GOODHOPE_DATA_DIR`, `DEPLOYMENT_MODE=single-instance`, a maintained real `AV_SCANNER`, and the private first-use admin password.
- Upload public documents only after staff approval and production gate verification. See `DEPLOYMENT_CHECKLIST.md`.
