
from pathlib import Path
from html.parser import HTMLParser
import subprocess, tempfile, shutil, time, urllib.request, json, os, re, socket, urllib.error
ROOT=Path(__file__).resolve().parents[1]
REQUIRED_PAGES=['index.html','about.html','services.html','life.html','families.html','reviews.html','referrals.html','documents.html','contact.html','privacy.html','accessibility.html','404.html']
FORBIDDEN=['Community Photo','restaurant-style dining','24-hour nursing','hospital-level care','prototype/owner-review','owner-review','pending confirmation','confirm approval','confirm nursing oversight','Memory Care','Dementia Care']
class Parser(HTMLParser):
    def __init__(self): super().__init__(); self.links=[]; self.imgs=[]; self.titles=[]
    def handle_starttag(self, tag, attrs):
        d=dict(attrs)
        if tag=='a' and d.get('href'): self.links.append(d['href'])
        if tag=='img': self.imgs.append(d)
        if tag in ['h1','h2','h3']: self.titles.append(tag)

def assert_true(x,msg):
    if not x: raise AssertionError(msg)

for p in REQUIRED_PAGES:
    f=ROOT/p
    assert_true(f.exists(), f'{p} missing')
    html=f.read_text(encoding='utf-8')
    for bad in FORBIDDEN:
        assert_true(bad.lower() not in html.lower(), f'Forbidden phrase {bad} found in {p}')
    assert_true('Assisted Living Facility License #8627' in html or p in ['privacy.html','accessibility.html','404.html'], f'License wording missing in {p}')
    parser=Parser(); parser.feed(html)
    for img in parser.imgs:
        assert_true(img.get('alt'), f'Image missing alt text in {p}')
        src=img.get('src','')
        if src.startswith('assets/'): assert_true((ROOT/src).exists(), f'Missing image {src} in {p}')
assert_true('exterior-good-hope-manor.jpg' in (ROOT/'index.html').read_text(encoding='utf-8'), 'Homepage hero exterior image missing')
assert_true((ROOT/'assets/images/favicon.png').exists(), 'Favicon missing')
# XML parse
import xml.etree.ElementTree as ET
ET.parse(ROOT/'sitemap.xml')
# JS syntax
subprocess.check_call(['node','--check',str(ROOT/'server.js')])
subprocess.check_call(['node','--check',str(ROOT/'script.js')])
subprocess.check_call(['node','--check',str(ROOT/'documents.js')])
# E2E server tests on a temp copy to avoid mutating seed data
with tempfile.TemporaryDirectory() as td:
    tmp=Path(td)/'site'; shutil.copytree(ROOT,tmp)
    env=os.environ.copy(); env['PORT']='39281'; env['INITIAL_ADMIN_PASSWORD']='LocalTestSecret#2026'
    proc=subprocess.Popen(['node','server.js'],cwd=tmp,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        time.sleep(1.5)
        base='http://127.0.0.1:39281'
        def req(path, method='GET', data=None, headers=None, cookie=None):
            body=None
            if data is not None and not isinstance(data, bytes):
                body=json.dumps(data).encode(); headers={**(headers or {}),'Content-Type':'application/json'}
            else:
                body=data
            if cookie: headers={**(headers or {}),'Cookie':cookie}
            r=urllib.request.Request(base+path,data=body,method=method,headers=headers or {})
            try:
                with urllib.request.urlopen(r,timeout=5) as resp:
                    return resp.status, dict(resp.headers), resp.read()
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers), e.read()
        for route in ['/','/index.html','/documents.html','/contact.html','/assets/images/exterior-good-hope-manor.jpg','/assets/images/favicon.png']:
            code,_,_=req(route); assert_true(code==200, f'{route} returned {code}')
        code,_,body=req('/api/documents/public'); assert_true(code==200, 'Public docs API failed')
        code,h,body=req('/api/auth/login','POST',{'username':'admin','password':'LocalTestSecret#2026'}); assert_true(code==200, 'Admin login failed')
        data=json.loads(body); assert_true(data.get('forcePasswordChange') is True, 'First login force password change missing')
        cookie=h.get('Set-Cookie','').split(';')[0]; csrf=data['csrfToken']
        code,_,body=req('/api/admin/documents', cookie=cookie); assert_true(code==403, 'Admin docs should require password change')
        code,_,body=req('/api/auth/change-password','POST',{'newPassword':'StrongPass01!'},headers={'x-csrf-token':csrf},cookie=cookie); assert_true(code==200, 'Password change failed')
        code,_,body=req('/api/admin/users','POST',{'username':'manager','email':'manager@example.com','tempPassword':'TempPass01!'},headers={'x-csrf-token':csrf},cookie=cookie); assert_true(code==200, 'Create user failed')
        boundary='----ghmtest'
        sample=b'Approved sample file'
        parts=[]
        fields={'title':'October Menu','category':'Menu','effectiveDate':'2026-10-01','expirationDate':'2026-12-31','approved':'on'}
        for k,v in fields.items(): parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="menu.pdf"\r\nContent-Type: application/pdf\r\n\r\n'.encode()+sample+b'\r\n')
        parts.append(f'--{boundary}--\r\n'.encode())
        code,_,body=req('/api/admin/documents','POST',b''.join(parts),headers={'Content-Type':'multipart/form-data; boundary='+boundary,'x-csrf-token':csrf},cookie=cookie); assert_true(code==200, 'Upload approved document failed: '+body.decode(errors='ignore'))
        code,_,body=req('/api/documents/public'); assert_true(code==200 and b'October Menu' in body, 'Approved document not visible to guests')
        docs=json.loads(body)['documents']; did=docs[0]['id']
        code,_,body=req(f'/api/documents/{did}/download'); assert_true(code==200 and body==sample, 'Guest download failed')
    finally:
        proc.kill()
print('Validation passed: pages, assets, forbidden phrases, accessibility basics, APIs, admin login, password change, user creation, upload, approval, guest view, guest download.')
