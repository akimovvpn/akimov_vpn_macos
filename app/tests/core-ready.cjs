// A controller responding must not count as a usable data plane while providers load.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),net=require('node:net'),{spawn}=require('node:child_process');
const core=path.resolve(__dirname,'../src-tauri/core/mihomo'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'akimov-ready-'));
let child,server,release;const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function port(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p}
async function until(fn){for(let i=0;i<100;i++){try{const v=await fn();if(v)return v}catch{}await wait(30)}throw Error('Fixture timed out')}
(async()=>{let providerRequests=0;server=http.createServer((req,res)=>{if(req.url==='/rules'){providerRequests++;release=()=>res.end("payload:\n- '+.example.invalid'\n")}else res.end('ready-fixture')});await new Promise(r=>server.listen(0,'127.0.0.1',r));const web=server.address().port,mixed=await port(),ctl=await port();
 const config={'mixed-port':mixed,'external-controller':`127.0.0.1:${ctl}`,'log-level':'silent',dns:{enable:false},tun:{enable:false},'rule-providers':{delayed:{type:'http',behavior:'domain',url:`http://127.0.0.1:${web}/rules`,path:'providers/delayed.yaml',interval:86400}},rules:['RULE-SET,delayed,DIRECT','MATCH,DIRECT']};
 fs.writeFileSync(path.join(dir,'config.json'),JSON.stringify(config));
 const start=()=>{child=spawn(core,['-d',dir,'-f',path.join(dir,'config.json')],{stdio:'ignore'})};
 const version=async()=>{const r=await fetch(`http://127.0.0.1:${ctl}/version`,{signal:AbortSignal.timeout(500)});return r.json()};
 const stop=async()=>{child.kill();await new Promise(r=>child.exitCode!==null?r():child.once('exit',r))};
 start();await until(()=>typeof release==='function');const initial=await until(version);assert.equal(initial.ready,false,'API appears before rule providers finish; readiness must stay false');release();await until(async()=>(await version()).ready===true);
 const response=await new Promise((resolve,reject)=>{http.get({host:'127.0.0.1',port:mixed,path:`http://127.0.0.1:${web}/target`,headers:{Host:`127.0.0.1:${web}`}},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>resolve(body))}).on('error',reject)});assert.equal(response,'ready-fixture');await stop();
 const before=providerRequests;start();await until(async()=>(await version()).ready===true);assert.equal(providerRequests,before,'fresh cached rules must avoid a blocking download on restart');await stop();const old=new Date(1000);fs.utimesSync(path.join(dir,'providers/delayed.yaml'),old,old);const staleCount=providerRequests;start();await until(()=>providerRequests>staleCount);release();await until(async()=>(await version()).ready===true);await stop();console.log('PASS: readiness waits for providers; fresh cache skips download; stale cache refreshes');
})().catch(e=>{console.error(e);process.exitCode=1}).finally(()=>{release?.();child?.kill();server?.closeAllConnections();server?.close();fs.rmSync(dir,{recursive:true,force:true})});
