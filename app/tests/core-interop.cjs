// Local Xray REALITY/VLESS interoperability; no system proxy, TUN or live user credentials.
const fs=require('fs'),path=require('path'),net=require('net'),http=require('http'),https=require('https'),crypto=require('crypto'),{spawn}=require('child_process'),assert=require('assert/strict');
const root=path.resolve(__dirname,'../..'),dir=path.join(root,'.tools/interop');
const core=path.resolve(process.argv.slice(2).find(a=>!a.startsWith('--'))||path.join(root,'app/src-tauri/core/mihomo'));
const expectFailure=process.argv.includes('--expect-failure');
const children=[];let fallback,target;
async function listen(server){await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));return server.address().port}
async function freePort(){const s=net.createServer(),p=await listen(s);await new Promise(r=>s.close(r));return p}
async function ready(port,child){const end=Date.now()+8000;while(Date.now()<end){if(child.launchError)throw child.launchError;if(child.exitCode!==null)throw Error('Fixture process stopped');try{await new Promise((resolve,reject)=>{const s=net.connect(port,'127.0.0.1',()=>{s.destroy();resolve()});s.on('error',reject)});return}catch{await new Promise(r=>setTimeout(r,40))}}throw Error('Fixture startup timeout')}
async function dataReady(port,child){
 const end=Date.now()+8000;
 while(Date.now()<end){
  if(child.exitCode!==null)throw Error('Fixture process stopped');
  try{const response=await fetch(`http://127.0.0.1:${port}/version`,{headers:{Authorization:'Bearer interop-fixture'},signal:AbortSignal.timeout(500)});if(response.ok&&(await response.json()).ready===true)return}catch{}
  await new Promise(r=>setTimeout(r,40));
 }
 throw Error('Fixture data plane did not become ready');
}
function run(exe,args,log){const output=fs.openSync(path.join(dir,log),'w');const child=spawn(exe,args,{windowsHide:true,stdio:['ignore',output,output]});child.on('error',e=>child.launchError=e);fs.closeSync(output);children.push(child);return child}
process.on('exit',()=>{for(const child of children)if(child.exitCode===null)child.kill()});
function getThroughProxy(port,targetPort){return new Promise((resolve,reject)=>{const r=http.get({host:'127.0.0.1',port,path:`http://127.0.0.1:${targetPort}/interop`,headers:{Host:`127.0.0.1:${targetPort}`},timeout:5000},response=>{let text='';response.on('data',c=>text+=c);response.on('end',()=>response.statusCode===200?resolve(text):reject(Error('Proxy HTTP '+response.statusCode)))});r.on('timeout',()=>r.destroy(Error('Proxy request timeout')));r.on('error',reject)})}
(async()=>{
 fs.mkdirSync(dir,{recursive:true});
 fallback=https.createServer({key:fs.readFileSync(path.join(dir,'key.pem')),cert:fs.readFileSync(path.join(dir,'cert.pem')),minVersion:'TLSv1.3'},(_,res)=>res.end('fallback'));
 target=http.createServer((req,res)=>{if(req.url==='/rules')return setTimeout(()=>res.end("payload:\n- '+.example.invalid'\n"),500);console.log('Fixture HTTP request received');res.end('local-xray-interop-ok')});target.on('connection',()=>console.log('Fixture target TCP accepted'));
 const fallbackPort=await listen(fallback),targetPort=await listen(target),xrayPort=await freePort();
 const keys=crypto.generateKeyPairSync('x25519'),privateKey=keys.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32).toString('base64url'),publicKey=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64url');
 const uuid=crypto.randomUUID();
 fs.writeFileSync(path.join(dir,'xray.json'),JSON.stringify({log:{loglevel:'debug'},inbounds:[{listen:'127.0.0.1',port:xrayPort,protocol:'vless',settings:{clients:[{id:uuid,flow:'xtls-rprx-vision'}],decryption:'none'},streamSettings:{network:'tcp',security:'reality',realitySettings:{target:`127.0.0.1:${fallbackPort}`,serverNames:['localhost'],privateKey,shortIds:['0123456789abcdef'],minClientVer:'26.3.27'}}}],outbounds:[{protocol:'freedom',settings:{finalRules:[{action:'allow',ip:['127.0.0.1/32'],port:String(targetPort)}]}}]}));
 const xray=run(path.join(root,'.tools/xray/xray'),['run','-config',path.join(dir,'xray.json')],'xray.log');await ready(xrayPort,xray);
 for(const fingerprint of ['chrome','firefox']){
  const port=await freePort(),ctl=await freePort(),config={ 'mixed-port':port,'external-controller':`127.0.0.1:${ctl}`,secret:'interop-fixture','allow-lan':false,'log-level':'debug',proxies:[{name:'fixture',type:'vless',server:'127.0.0.1',port:xrayPort,uuid,network:'tcp',tls:true,flow:'xtls-rprx-vision',servername:'localhost','client-fingerprint':fingerprint,'reality-opts':{'public-key':publicKey,'short-id':'0123456789abcdef'}}],rules:['MATCH,fixture']};
  if(!expectFailure){config['rule-providers']={delayed:{type:'http',behavior:'domain',url:`http://127.0.0.1:${targetPort}/rules`,path:`providers/${fingerprint}-${uuid}.yaml`,interval:86400,proxy:'DIRECT'}};config.rules.unshift('RULE-SET,delayed,fixture')}
  const file=path.join(dir,'mihomo-'+fingerprint+'.json');fs.writeFileSync(file,JSON.stringify(config));const mihomo=run(core,['-d',dir,'-f',file],fingerprint+'.log');await ready(port,mihomo);
  // shortcut: stock v1.19.33 lacks readiness; use its API here if upstream adds it.
  if(!expectFailure)await dataReady(ctl,mihomo);
  let value,error;try{value=await getThroughProxy(port,targetPort)}catch(e){error=e}
  mihomo.kill();await new Promise(resolve=>mihomo.exitCode!==null?resolve():mihomo.once('exit',resolve));
  if(expectFailure){assert(error,'Unpatched core unexpectedly passed modern minimum-client version');console.log('Confirmed stock failure: '+fingerprint)}else{assert.ifError(error);assert.equal(value,'local-xray-interop-ok');console.log('PASS: Xray 26.10.31 REALITY/Vision, minimum client 26.3.27, '+fingerprint)}
 }
})().catch(e=>{console.error(e.stack||e);for(const name of ['chrome.log','firefox.log','xray.log']){const file=path.join(dir,name);if(fs.existsSync(file))console.error(name+'\n'+fs.readFileSync(file,'utf8').split('\n').slice(-30).join('\n'))}process.exitCode=1}).finally(async()=>{for(const child of children)if(child.exitCode===null)child.kill();if(target)target.closeAllConnections();if(fallback)fallback.closeAllConnections();target?.close();fallback?.close()});
