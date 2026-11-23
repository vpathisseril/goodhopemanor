'use strict';
const fs = require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {execFile} = require('node:child_process');
const {promisify} = require('node:util');
const execFileAsync=promisify(execFile);
const {safeFilename}=require('./security');
const MIME={'.pdf':'application/pdf','.doc':'application/msword','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg'};
class UploadError extends Error {constructor(message,status=400){super(message);this.status=status;}}
function magicType(bytes,extension){
  if(bytes.length<20) return false;
  if(extension==='.pdf'){
    const begin=bytes.subarray(0,8).toString('latin1');
    const end=bytes.subarray(Math.max(0,bytes.length-4096)).toString('latin1');
    return /^%PDF-\d\.\d/.test(begin)&&end.includes('%%EOF');
  }
  if(extension==='.png'){
    if(!bytes.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex')))return false;
    if(bytes.readUInt32BE(8)!==13||bytes.subarray(12,16).toString('ascii')!=='IHDR')return false;
    const w=bytes.readUInt32BE(16),h=bytes.readUInt32BE(20);
    return w>0&&h>0&&w<=16000&&h<=16000&&bytes.includes(Buffer.from('IEND'));
  }
  if(extension==='.jpg'||extension==='.jpeg')return bytes[0]===255&&bytes[1]===216&&bytes[2]===255&&bytes[bytes.length-2]===255&&bytes[bytes.length-1]===217;
  if(extension==='.doc')return bytes.subarray(0,8).equals(Buffer.from('d0cf11e0a1b11ae1','hex'));
  if(extension==='.docx')return isSafeDocx(bytes);
  return false;
}
function isSafeDocx(bytes){
  if(bytes[0]!==0x50||bytes[1]!==0x4b||bytes[2]!==3||bytes[3]!==4)return false;
  const eocd=bytes.lastIndexOf(Buffer.from([0x50,0x4b,0x05,0x06]));
  if(eocd<0||eocd+22>bytes.length)return false;
  const count=bytes.readUInt16LE(eocd+10),cdStart=bytes.readUInt32LE(eocd+16);
  if(count<1||count>3000||cdStart>=eocd)return false;
  let i=cdStart,totalUncompressed=0;const names=new Set();
  for(let n=0;n<count;n++){
    if(i+46>bytes.length||bytes.readUInt32LE(i)!==0x02014b50)return false;
    const flags=bytes.readUInt16LE(i+8), method=bytes.readUInt16LE(i+10);
    const comp=bytes.readUInt32LE(i+20), uncomp=bytes.readUInt32LE(i+24);
    const nameLen=bytes.readUInt16LE(i+28),extra=bytes.readUInt16LE(i+30),comment=bytes.readUInt16LE(i+32);
    if(i+46+nameLen+extra+comment>bytes.length||(flags&1)||![0,8].includes(method))return false;
    const name=bytes.subarray(i+46,i+46+nameLen).toString('utf8').replace(/\\/g,'/');
    if(name.startsWith('/')||name.includes('..')||/\u0000/.test(name)||!name) return false;
    if(/vbaProject\.bin|activeX\/|embeddings\/|oleObject/i.test(name))return false;
    if(comp>0&&uncomp/comp>150)return false;
    totalUncompressed+=uncomp;if(totalUncompressed>60*1024*1024)return false;
    names.add(name);i+=46+nameLen+extra+comment;
  }
  return names.has('[Content_Types].xml')&&names.has('word/document.xml');
}
function parseMultipart(buffer,header){
  const match=/\bboundary=(?:"([^"]+)"|([^;\s]+))/i.exec(header||'');
  if(!match)throw new UploadError('Missing multipart boundary');
  const text=match[1]||match[2];if(text.length>70||text.length<8)throw new UploadError('Invalid multipart boundary');
  const delimiter=Buffer.from('--'+text),search=Buffer.from('\r\n--'+text);
  let pos=0;let fields={};let file=null;let count=0;
  if(!buffer.subarray(0,delimiter.length).equals(delimiter))throw new UploadError('Malformed multipart data');
  pos=delimiter.length;
  while(pos<buffer.length){
    if(buffer.subarray(pos,pos+2).toString('ascii')==='--')break;
    if(buffer.subarray(pos,pos+2).toString('ascii')!=='\r\n')throw new UploadError('Malformed multipart framing');
    pos+=2;
    const sep=buffer.indexOf(Buffer.from('\r\n\r\n'),pos);
    if(sep<0||sep-pos>4000)throw new UploadError('Invalid multipart headers');
    const hdr=buffer.subarray(pos,sep).toString('utf8');
    const fieldMatch=/Content-Disposition:\s*form-data;\s*name="([a-zA-Z]+)"(?:;\s*filename="([^"]*)")?/i.exec(hdr);
    if(!fieldMatch)throw new UploadError('Missing upload field name');
    const start=sep+4,end=buffer.indexOf(search,start);
    if(end<0)throw new UploadError('Unterminated multipart payload');
    const body=buffer.subarray(start,end);
    const [,name,filename]=fieldMatch;
    if(++count>12)throw new UploadError('Too many form fields');
    if(filename!==undefined){if(name!=='file'||file)throw new UploadError('Only one file may be uploaded');file={filename,buffer:body};}
    else {if(Object.hasOwn(fields,name)||body.length>1500)throw new UploadError('Invalid form field');fields[name]=body.toString('utf8').trim();}
    pos=end+2+delimiter.length;
  }
  if(pos>=buffer.length||buffer.subarray(pos,pos+2).toString('ascii')!=='--')throw new UploadError('Incomplete multipart closing boundary');
  return {fields,file};
}
async function processUpload(file,config){
  if(!file||!file.filename)throw new UploadError('Choose a file to upload');
  const originalName=safeFilename(file.filename);const extension=path.extname(originalName).toLowerCase();
  if(!Object.hasOwn(MIME,extension))throw new UploadError('File type not allowed');
  if(!file.buffer.length||file.buffer.length>config.maxUpload)throw new UploadError('Upload must be 1 byte to 20 MB');
  if(!magicType(file.buffer,extension))throw new UploadError('File contents do not match an allowed document format');
  if(extension==='.doc'&&!config.avScanner)throw new UploadError('Legacy .doc files require antivirus scanning; use PDF or DOCX instead');
  const storedName=crypto.randomUUID()+extension;
  const filepath=path.join(config.storageDir,storedName);
  fs.writeFileSync(filepath,file.buffer,{mode:0o600,flag:'wx'});
  try{
    let scannedAt=null;
    if(config.avScanner){
      try{await execFileAsync(config.avScanner,['--no-summary','--',filepath],{timeout:30000,maxBuffer:200000,windowsHide:true});scannedAt=new Date().toISOString();}
      catch(e){throw new UploadError(e.code===1?'Antivirus identified an unsafe file':'Virus scan unavailable; upload rejected',422);}
    } else if(config.production){throw new UploadError('Antivirus scanner unavailable',503);}
    return {storedName,originalName,mime:MIME[extension],fileSize:file.buffer.length,fileHash:crypto.createHash('sha256').update(file.buffer).digest('hex'),scannedAt};
  }catch(err){fs.rmSync(filepath,{force:true});throw err;}
}
module.exports={UploadError,MIME,magicType,isSafeDocx,parseMultipart,processUpload};
