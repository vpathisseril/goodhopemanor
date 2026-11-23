#!/usr/bin/env node
'use strict';
/** Offline restore into an EMPTY destination. Stop the site first. */
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const hash=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function run(){
  const [source,target]=process.argv.slice(2);
  if(!source||!target||!path.isAbsolute(source)||!path.isAbsolute(target))throw new Error('Usage: node scripts/restore.js /backups/backup-YYYY-MM-DD /empty/private-data');
  if(!fs.existsSync(path.join(source,'MANIFEST.json')))throw new Error('Backup manifest missing');
  if(fs.existsSync(target)&&fs.readdirSync(target).length)throw new Error('Restore target must be empty');
  const manifest=JSON.parse(fs.readFileSync(path.join(source,'MANIFEST.json'),'utf8'));
  if(manifest.version!==1||!Array.isArray(manifest.files)||!manifest.files.some(f=>f.name==='goodhope.sqlite'))throw new Error('Invalid backup manifest');
  for(const f of manifest.files){
    if(!/^goodhope\.sqlite$|^private-files\/[a-f\d-]{36}\.(?:pdf|doc|docx|png|jpg|jpeg)$/i.test(f.name))throw new Error('Unsafe backup filename');
    const file=path.join(source,f.name);
    if(!fs.existsSync(file)||fs.statSync(file).size!==f.bytes||hash(file)!==f.sha256)throw new Error('Corrupt backup file: '+f.name);
  }
  fs.mkdirSync(target,{recursive:true,mode:0o700});fs.mkdirSync(path.join(target,'private-files'),{recursive:true,mode:0o700});
  for(const f of manifest.files){const dst=path.join(target,f.name);fs.copyFileSync(path.join(source,f.name),dst);fs.chmodSync(dst,0o600);}
  console.log(`Restore verified: ${manifest.files.length} file(s). Set GOODHOPE_DATA_DIR to the restored private directory.`);
}
try{run();}catch(error){console.error('Restore aborted:',error.message);process.exitCode=1;}
