#!/usr/bin/env node
'use strict';
/**
 * Builds the public HTML pages from one shared layout.
 *
 *   site/layout.html     shared <head>, header, navigation and footer
 *   site/pages.json      navigation links and per-page title, description and extra scripts
 *   site/pages/*.html    each page's own <main> content
 *
 * Output is written to the project root (e.g. about.html), where the server serves it.
 * Edit the files in site/, never the generated pages.
 *
 * Usage: node scripts/build_pages.js          write the pages
 *        node scripts/build_pages.js --check  exit 1 if any page is out of date
 */
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const siteDir = path.join(root, 'site');

function renderNav(nav, activeFile) {
  return nav
    .map(({href, label}) => {
      const active = href === activeFile;
      const current = active ? ' aria-current="page"' : '';
      return `<a class="nav-link${active ? ' active' : ''}" href="${href}"${current}>${label}</a>`;
    })
    .join('');
}

// Indexable pages get a canonical URL; pages marked "noindex" (e.g. 404) are kept out of search.
function renderSeo(page, file, siteUrl) {
  if (page.noindex) return '<meta name="robots" content="noindex" />';
  const url = `${siteUrl}/${file === 'index.html' ? '' : file}`;
  return [
    `<link rel="canonical" href="${url}" />`,
    `<meta property="og:url" content="${url}" />`,
  ].join('\n  ');
}

function fill(template, values) {
  return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    if (!Object.hasOwn(values, key)) throw new Error(`Layout placeholder {{${key}}} has no value`);
    return values[key];
  });
}

function buildPages() {
  const layout = fs.readFileSync(path.join(siteDir, 'layout.html'), 'utf8');
  const {siteUrl, nav, pages} = JSON.parse(
    fs.readFileSync(path.join(siteDir, 'pages.json'), 'utf8'),
  );
  return Object.entries(pages).map(([file, page]) => {
    const main = fs.readFileSync(path.join(siteDir, 'pages', file), 'utf8').replace(/\n$/, '');
    // Deferred scripts in <head> download early and run after parsing, in this order.
    const scripts = [...(page.scripts || []), 'script.js']
      .map((src) => `<script src="${src}" defer></script>`)
      .join('\n  ');
    const html = fill(layout, {
      title: page.title,
      description: page.description,
      siteUrl,
      seo: renderSeo(page, file, siteUrl),
      nav: renderNav(nav, file),
      main,
      scripts,
    });
    return {file, html};
  });
}

function main() {
  const check = process.argv.includes('--check');
  const stale = [];
  for (const {file, html} of buildPages()) {
    const target = path.join(root, file);
    // Compare without carriage returns so a Windows checkout is not reported as stale.
    const current = fs.existsSync(target)
      ? fs.readFileSync(target, 'utf8').replace(/\r\n/g, '\n')
      : null;
    if (current === html) continue;
    if (check) stale.push(file);
    else fs.writeFileSync(target, html);
  }
  if (check && stale.length) {
    console.error(
      `Out of date: ${stale.join(', ')}. Run "npm run build:pages" and commit the result.`,
    );
    process.exitCode = 1;
  } else if (check) {
    console.log('Generated pages are up to date.');
  }
}

if (require.main === module) main();
module.exports = {buildPages, renderNav, renderSeo};
