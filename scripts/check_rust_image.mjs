// Smoke the release Dockerfile with read-only root and no host configuration.
import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';import {randomUUID} from 'node:crypto';import {readFileSync} from 'node:fs';
const docker=process.env.DOCKER??'docker',image=process.argv[2]??'grantline-rust-ci:local',name='grantline-native-smoke-'+randomUUID().slice(0,8);
function command(args){const r=spawnSync(docker,args,{encoding:'utf8',timeout:30000});if(r.status!==0)throw Error(r.stderr||r.stdout);return r.stdout.trim();}
try{
 command(['run','--detach','--name',name,'--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-p','127.0.0.1::8420',image]);
 const port=command(['port',name,'8420/tcp']).split(':').at(-1),origin='http://127.0.0.1:'+port;let ready=false;
 for(let i=0;i<100;i++){try{if((await fetch(origin+'/health')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}assert(ready,command(['logs',name]));
 for(const page of ['/','/accounts','/resources','/services','/matrix','/changes','/history','/act','/approvals']){const r=await fetch(origin+page);assert.equal(r.status,200,page);const html=await r.text();assert(html.includes('native-boot.js'));assert(!html.includes('Interactive bundle unavailable'));}
 const wasm=await fetch(origin+'/static/pkg/grantline_ui_bg.wasm');assert.equal(wasm.headers.get('content-type'),'application/wasm');const bytes=new Uint8Array(await wasm.arrayBuffer());assert.deepEqual(Array.from(bytes.slice(0,4)),[0,97,115,109]);
 const r=await fetch(origin+'/api/requests',{method:'POST',headers:{'content-type':'application/json',Origin:origin},body:'{"csrf":"","system":"s3","subject":"fixture","resource":"bucket:demo","privilege":"Read","action":"grant"}'});assert.equal(r.status,401);
 const crates=new Set(readFileSync('rust/Cargo.lock','utf8').split('[[package]]').filter(s=>s.includes('registry+https://github.com/rust-lang/crates.io-index')).map(s=>s.match(/^name = "([^"]+)"/m)[1]+'-'+s.match(/^version = "([^"]+)"/m)[1]));
 const notices=command(['exec',name,'find','/app/third-party-licenses','-type','f']).split('\n');assert(notices.length>0);for(const path of notices){const match=path.match(/\/index\.crates\.io-[^/]+\/([^/]+)\//);assert(match&&crates.has(match[1]),'License outside public lockfile crates');}command(['exec',name,'test','-s','/app/LOGO-NOTICES.txt']);
 assert.equal(command(['exec',name,'id','-u']),'10001');command(['exec',name,'sh','-c','! command -v python && ! command -v python3 && ! command -v node']);
 assert.equal(command(['inspect','--format','{{.HostConfig.ReadonlyRootfs}}',name]),'true');
 console.log('PASS: native release image, 9 SSR pages, valid WASM, read-only API, UID 10001, no Python/Node, read-only filesystem.');
}finally{spawnSync(docker,['rm','--force',name],{stdio:'ignore'});}
