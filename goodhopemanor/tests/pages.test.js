'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {buildPages, renderNav} = require('../scripts/build_pages');

const nav = [
  {href: 'index.html', label: 'Home'},
  {href: 'about.html', label: 'About Us'},
];

test('navigation marks only the current page as active', () => {
  assert.equal(
    renderNav(nav, 'about.html'),
    '<a class="nav-link" href="index.html">Home</a>' +
      '<a class="nav-link active" href="about.html" aria-current="page">About Us</a>',
  );
  assert.doesNotMatch(renderNav(nav, '404.html'), /active|aria-current/);
});

test('every generated page is complete and uses its own title', () => {
  const pages = buildPages();
  assert.equal(pages.length, 12);
  for (const {file, html} of pages) {
    assert.doesNotMatch(html, /\{\{\w+\}\}/, `${file} has an unfilled placeholder`);
    assert.equal(html.match(/<main id="main">/g).length, 1, `${file} must have one <main>`);
    assert.match(html, /<title>[^<]+\| Good Hope Manor<\/title>/, `${file} title`);
  }
});
