'use strict';
const fs = require('node:fs');
const path = require('node:path');

function loadConfig(env = process.env) {
  const root = path.resolve(__dirname, '..');
  const production = env.NODE_ENV === 'production';
  const dataDir = path.resolve(env.GOODHOPE_DATA_DIR || path.join(root, 'data'));
  const publicBaseUrl = env.PUBLIC_BASE_URL || `http://127.0.0.1:${env.PORT || 3000}`;
  const trustProxyHops = Number(env.TRUST_PROXY_HOPS || 0);
  if (!Number.isInteger(trustProxyHops) || trustProxyHops < 0 || trustProxyHops > 5) {
    throw new Error('TRUST_PROXY_HOPS must be a whole number from 0 to 5.');
  }
  if (production) {
    if (
      !env.GOODHOPE_DATA_DIR ||
      !path.isAbsolute(env.GOODHOPE_DATA_DIR) ||
      dataDir === root ||
      dataDir.startsWith(root + path.sep)
    ) {
      throw new Error(
        'Production requires GOODHOPE_DATA_DIR on a private, mounted persistent volume outside the application directory.',
      );
    }
    if (env.DEPLOYMENT_MODE !== 'single-instance') {
      throw new Error(
        'SQLite-backed deployment requires DEPLOYMENT_MODE=single-instance (not Autoscale).',
      );
    }
    if (!publicBaseUrl.startsWith('https://'))
      throw new Error('PUBLIC_BASE_URL must use HTTPS in production.');
    if (!env.AV_SCANNER || !path.isAbsolute(env.AV_SCANNER))
      throw new Error(
        'Production requires an installed AV_SCANNER with an absolute executable path.',
      );
    if (env.AV_SCANNER.includes('mock-clamscan'))
      throw new Error('The test malware scanner cannot be used in production.');
    try {
      fs.accessSync(env.AV_SCANNER, fs.constants.X_OK);
    } catch {
      throw new Error('Production AV_SCANNER is not installed or executable.');
    }
  }
  const storageDir = path.join(dataDir, 'private-files');
  for (const dir of [dataDir, storageDir]) {
    fs.mkdirSync(dir, {recursive: true, mode: 0o700});
    fs.chmodSync(dir, 0o700);
  }
  return {
    root,
    dataDir,
    storageDir,
    dbFile: path.join(dataDir, 'goodhope.sqlite'),
    port: Number(env.PORT || 3000),
    publicBaseUrl,
    trustProxyHops,
    production,
    bootstrapPassword: env.INITIAL_ADMIN_PASSWORD || '',
    bootstrapEmail: env.INITIAL_ADMIN_EMAIL || 'info@goodhopemanor.com',
    avScanner: env.AV_SCANNER || '',
    emailProvider: env.EMAIL_PROVIDER || '',
    sendgridKey: env.SENDGRID_API_KEY || '',
    fromEmail: env.FROM_EMAIL || '',
    maxUpload: 20 * 1024 * 1024,
  };
}
module.exports = {loadConfig};
