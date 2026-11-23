'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {magicType, isSafeDocx, parseMultipart, UploadError} = require('../src/uploads');
test('genuine DOCX, PNG and JPEG files are identified by contents', () => {
  const docx = fs.readFileSync(path.join(__dirname, 'fixtures/valid.docx'));
  assert.ok(isSafeDocx(docx));
  assert.ok(magicType(docx, '.docx'));
  for (const [filename, ext] of [
    ['favicon.png', '.png'],
    ['exterior-good-hope-manor.jpg', '.jpg'],
  ]) {
    assert.ok(
      magicType(fs.readFileSync(path.join(__dirname, '../assets/images', filename)), ext),
      filename,
    );
  }
  assert.equal(magicType(Buffer.from('PKfakezip'), '.docx'), false);
});
test('multipart parser rejects incomplete and duplicate fields', () => {
  assert.throws(() => parseMultipart(Buffer.from('hello'), 'multipart/form-data'), UploadError);
  assert.throws(
    () =>
      parseMultipart(
        Buffer.from(
          '--exampleboundary\r\nContent-Disposition: form-data; name="title"\r\n\r\nvalue\r\n--exampleboundary\r\nContent-Disposition: form-data; name="title"\r\n\r\nduplicate\r\n--exampleboundary--\r\n',
        ),
        'multipart/form-data; boundary=exampleboundary',
      ),
    UploadError,
  );
});
