# Good Hope Manor — Production Launch Gates

- [ ] Review the 12 public HTML pages, exact document wording, approved photos, map and favicon with the facility owner
- [ ] Confirm assisted-living license and published hours are current
- [ ] Select a **single-instance host** with a guaranteed persistent volume (no ephemeral Autoscale). Mount outside application source
- [ ] Configure Node.js >=22.13, HTTPS, HTTPS base URL, deployment mode and private persistent volume
- [ ] Install ClamAV and configure definition updates; set absolute `AV_SCANNER`. Confirm an infected test file is rejected **with the real scanner**
- [ ] Set a unique secret `INITIAL_ADMIN_PASSWORD`; never share it in email or commit it. Force first login password change
- [ ] Configure SendGrid key and verified sender to send invitation links, or document the secure manual invitation process
- [ ] Create separate Editor and Approver accounts; verify least-privilege permissions
- [ ] Upload approved facility Visitation Policy, Monthly Activity Calendars, Menu and Resident Notices (no private resident records)
- [ ] Confirm uploads remain private until approved, and expiration/archive/replacement remove public access
- [ ] Review privacy policy, written records retention and consent with facility compliance advisor
- [ ] Run `npm run validate`, manually test desktop/tablet/mobile, and test real browser keyboard accessibility
- [ ] Perform external vulnerability and penetration testing on the actual deployed host
- [ ] Test password recovery, session invalidation, per-role access, rate limits and logs in production
- [ ] Run a backup and **restore drill** to a separate location; schedule encrypted offsite backups and verify recovery timing
- [ ] Route production request logs and security alerts to an owner; investigate repeated failures and uploads rejected by AV
- [ ] Verify domain, SSL, links, sitemap, public document download, and mobile nav
- [ ] Have facility owner authorize go-live after all launch gates pass
