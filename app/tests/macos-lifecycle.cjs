// Real-core ownership tests. No system proxy, DNS, TUN, account, or live servers.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const {spawn} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const exe = process.env.AKIMOV_TEST_EXE || path.join(root, 'app/src-tauri/target/debug/akimov-vpn');
const core = path.join(root, 'app/src-tauri/core/mihomo');
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
async function port() { const server = net.createServer(); await new Promise(r=>server.listen(0,'127.0.0.1',r)); const port=server.address().port; await new Promise(r=>server.close(r)); return port; }
async function until(fn, message) { for(let i=0;i<100;i++){if(await fn())return;await wait(75);}throw Error(message); }
const children = [];
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'akimov-macos-lifecycle-'));
(async()=>{
 for (const crash of [false,true]) {
  const ctl=await port();
  const cfg=path.join(directory,`${crash}.json`), log=path.join(directory,`${crash}.log`);
  fs.writeFileSync(cfg,JSON.stringify({'mixed-port':0,'external-controller':`127.0.0.1:${ctl}`,secret:'fixture-only',dns:{enable:false},tun:{enable:false},rules:['MATCH,DIRECT']}));
  const args=['--core-supervisor',core,directory,cfg,log];
  let child;
  if(crash){
   const parentCode=`const {spawn}=require('node:child_process'); const child=spawn(${JSON.stringify(exe)},${JSON.stringify(args)},{stdio:['pipe','ignore','ignore']}); child.on('error',e=>{throw e}); setInterval(()=>{},1000);`;
   child=spawn(process.execPath,['-e',parentCode],{stdio:'ignore'});
  } else { child=spawn(exe,args,{stdio:['pipe','ignore','ignore']}); }
  children.push(child);
  let launchError; child.on('error',error=>launchError=error);
  const endpoint=`http://127.0.0.1:${ctl}/version`;
  await until(async()=>{if(launchError)throw launchError;try{return (await fetch(endpoint,{headers:{Authorization:'Bearer fixture-only'},signal:AbortSignal.timeout(300)})).ok}catch{return false}},'Core controller did not start');
  assert.equal((await fetch(endpoint,{headers:{Authorization:'Bearer wrong'}})).status,401);
  if(crash)child.kill('SIGKILL');else child.stdin.end();
  await until(async()=>{try{await fetch(endpoint,{signal:AbortSignal.timeout(300)});return false}catch{return true}},'Owned core survived its parent connection');
  console.log(`PASS: ${crash?'forced parent termination':'normal pipe close'} closes the real core controller`);
 }
})().catch(error=>{console.error(error);process.exitCode=1}).finally(()=>{for(const child of children)if(child.exitCode===null)child.kill();fs.rmSync(directory,{recursive:true,force:true})});
