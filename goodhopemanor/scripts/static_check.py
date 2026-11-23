#!/usr/bin/env python3
"""Dependency-free source, secrets, content and structural checks."""
from pathlib import Path
from html.parser import HTMLParser
import re, subprocess, sys, xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
required=['index.html','about.html','services.html','life.html','families.html','reviews.html','referrals.html','documents.html','contact.html','privacy.html','accessibility.html','404.html']
forbidden=['Community Photo','restaurant-style dining','24-hour nursing','hospital-level care','prototype/owner-review','owner-review','pending confirmation','confirm approval','confirm nursing oversight','Memory Care','Dementia Care','I deliberately removed language suggesting paid referrals','should be actual Good Hope Manor photographs']
class Scan(HTMLParser):
    def __init__(self):super().__init__();self.img=[];self.links=[];self.headings=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='img':self.img.append(a)
        if tag=='a' and 'href' in a:self.links.append(a['href'])
        if tag in ('h1','h2','h3'):self.headings.append(tag)
for name in required:
    file=root/name
    assert file.exists(),name+' missing'
    html=file.read_text(encoding='utf8')
    assert not any(x.lower() in html.lower() for x in forbidden),f'{name}: forbidden wording found'
    parsed=Scan();parsed.feed(html)
    assert parsed.headings and parsed.headings[0]=='h1', f'{name}: heading hierarchy incomplete'
    assert parsed.headings.count('h1')==1, f'{name}: page must have exactly one <h1>'
    for img in parsed.img:
        assert img.get('alt'),f'{name} missing img alt'
        if img.get('src','').startswith('assets/'):
            assert (root/img['src']).is_file(),f'{name} missing image {img["src"]}'
    for link in parsed.links:
        if link.endswith('.html') and not link.startswith(('http','#')):
            assert (root/link).exists(),f'{name} dead link {link}'
    assert 'Assisted Living Facility License #8627' in html or name=='404.html',f'{name} lacks correct license'
assert 'exterior-good-hope-manor.jpg' in (root/'index.html').read_text(), 'Exterior homepage hero missing'
assert (root/'assets/images/favicon.png').exists()
ET.parse(root/'sitemap.xml')
for file in [root/'server.js',root/'script.js',root/'documents.js',*(root/'src').glob('*.js'),*(root/'scripts').glob('*.js'),*(root/'tests').glob('*.js')]:
    subprocess.run(['node','--check',str(file)],check=True,capture_output=True)
for file in root.rglob('*'):
    if not file.is_file():continue
    if any(x in file.parts for x in ['node_modules','data','private-files']):continue
    if file.suffix not in ('.js','.json','.md','.html','.yml','.yaml','.example'):continue
    contents=file.read_text(encoding='utf8')
    if file.name not in ('static_check.py','api.test.js'):
        assert not re.search(r'(?i)(?:INITIAL_ADMIN_PASSWORD|SENDGRID_API_KEY|SESSION_SECRET)\s*[:=]\s*["\'](?!(?:REPLACE_|YOUR_|TEST_))[^"\']{10,}["\']',contents),f'Possible embedded credential in {file}'
print(f'Static checks passed: {len(required)} pages, assets, license wording, sitemap, JS syntax, references, and secret patterns')
