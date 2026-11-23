'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {clientIp} = require('../src/security');
const {loadConfig} = require('../src/config');

const request = (remoteAddress, forwardedFor) => ({
  socket: {remoteAddress},
  headers: forwardedFor === undefined ? {} : {'x-forwarded-for': forwardedFor},
});

test('clientIp uses the socket address when no proxy is trusted', () => {
  assert.equal(clientIp(request('10.0.0.1', '203.0.113.9'), 0), '10.0.0.1');
});

test('clientIp takes the entry added by the trusted proxy, not client-supplied ones', () => {
  // The client forged "1.1.1.1"; the trusted proxy appended the real address last.
  assert.equal(clientIp(request('10.0.0.1', '1.1.1.1, 203.0.113.9'), 1), '203.0.113.9');
  assert.equal(clientIp(request('10.0.0.1', '1.1.1.1, 203.0.113.9, 10.0.0.2'), 2), '203.0.113.9');
});

test('clientIp falls back safely when the header is missing or short', () => {
  assert.equal(clientIp(request('10.0.0.1'), 1), '10.0.0.1');
  assert.equal(clientIp(request('10.0.0.1', ''), 1), '10.0.0.1');
  assert.equal(clientIp(request('10.0.0.1', '203.0.113.9'), 3), '203.0.113.9');
  assert.equal(clientIp(request(undefined), 0), 'unknown');
});

test('TRUST_PROXY_HOPS must be a small whole number', () => {
  for (const value of ['-1', '1.5', 'yes', '6']) {
    assert.throws(
      () => loadConfig({NODE_ENV: 'test', TRUST_PROXY_HOPS: value}),
      /TRUST_PROXY_HOPS/,
    );
  }
});
