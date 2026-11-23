'use strict';
async function sendInvitation(config, recipient, username, link) {
  if (config.emailProvider !== 'sendgrid') return {sent: false};
  if (!config.sendgridKey || !config.fromEmail) throw new Error('SendGrid settings are incomplete');
  const body = {
    personalizations: [{to: [{email: recipient}]}],
    from: {email: config.fromEmail},
    subject: 'Your Good Hope Manor account invitation',
    content: [
      {
        type: 'text/plain',
        value: `Hello ${username},\n\nYour Good Hope Manor portal account is ready. Use this one-time link to set your password:\n${link}\n\nThis link expires in 30 minutes. If you did not request this access, ignore this email.\n\nGood Hope Manor`,
      },
    ],
  };
  const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {Authorization: 'Bearer ' + config.sendgridKey, 'Content-Type': 'application/json'},
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 202) throw new Error('Email delivery provider rejected the invitation');
  return {sent: true};
}
module.exports = {sendInvitation};
