'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {sendInvitation} = require('../src/email');
test('staff email invitations do not report delivery unless provider confirms', async () => {
  assert.deepEqual(
    await sendInvitation(
      {emailProvider: ''},
      'a@example.com',
      'staff',
      'https://example.com/#reset=token',
    ),
    {sent: false},
  );
  const original = global.fetch;
  const captured = [];
  try {
    global.fetch = async (url, opts) => {
      captured.push({url, opts});
      return {status: 202};
    };
    const config = {
      emailProvider: 'sendgrid',
      sendgridKey: 'TEST_NEVER_REAL',
      fromEmail: 'info@goodhopemanor.com',
    };
    const outcome = await sendInvitation(
      config,
      'a@example.com',
      'staff',
      'https://example.com/documents.html#reset=token',
    );
    assert.equal(outcome.sent, true);
    assert.equal(captured.length, 1);
    assert.equal(captured[0].url, 'https://api.sendgrid.com/v3/mail/send');
    const body = JSON.parse(captured[0].opts.body);
    assert.equal(body.personalizations[0].to[0].email, 'a@example.com');
    global.fetch = async () => ({status: 401});
    await assert.rejects(
      () => sendInvitation(config, 'a@example.com', 'staff', 'https://example.com/'),
      /rejected/,
    );
  } finally {
    global.fetch = original;
  }
});
