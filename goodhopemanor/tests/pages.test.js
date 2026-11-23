'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {buildPages, renderNav, renderSeo} = require('../scripts/build_pages');

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
  const titles = new Set();
  for (const {file, html} of pages) {
    assert.doesNotMatch(html, /\{\{\w+\}\}/, `${file} has an unfilled placeholder`);
    assert.equal(html.match(/<main id="main">/g).length, 1, `${file} must have one <main>`);
    const title = /<title>([^<]+)<\/title>/.exec(html)[1];
    assert.ok(title.includes('Good Hope Manor'), `${file} title names the facility`);
    assert.ok(!titles.has(title), `${file} title is not unique`);
    titles.add(title);
  }
});

test('pages use absolute URLs for search and link previews; 404 is not indexed', () => {
  const site = 'https://www.goodhopemanor.com';
  assert.match(renderSeo({}, 'index.html', site), /rel="canonical" href="https:\/\/[^"]+\/"/);
  assert.match(
    renderSeo({}, 'about.html', site),
    /href="https:\/\/www\.goodhopemanor\.com\/about\.html"/,
  );
  assert.equal(
    renderSeo({noindex: true}, '404.html', site),
    '<meta name="robots" content="noindex" />',
  );
  for (const {file, html} of buildPages()) {
    assert.match(
      html,
      /property="og:image" content="https:\/\//,
      `${file} og:image must be absolute`,
    );
  }
});
