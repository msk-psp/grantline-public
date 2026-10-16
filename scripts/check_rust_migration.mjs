// Copy-only state migration and post-crash recovery, using fictional private records.
import assert from 'node:assert/strict';
import {mkdtemp,realpath,mkdir,writeFile,readFile,readdir,stat,rm,symlink,link,unlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join,resolve} from 'node:path';import {spawn,spawnSync} from 'node:child_process';import {createServer} from 'node:net';
const root=await realpath(await mkdtemp(join(tmpdir(),'grantline-migration-'))),bin=resolve('rust/target/debug/grantline-rs');let child;
const source=join(root,'old'),destination=join(root,'new');const id='a'.repeat(32),nativeId='b'.repeat(32),grant={system:'s3',subject:'fixture',resource:'bucket:demo',priv:'Read'};
const legacy={id,ts:'2026-01-01T00:00:00Z',requester:'requester',action:'grant',...grant,required:{reviewer:'synthetic-secret-token'},approved:{reviewer:'2026-01-01T00:01:00Z'},status:'approved',cmd:'never import command',code_plan:{token:'never import plan'}};
const native={version:1,id:nativeId,created_at:1,requester:'requester',requester_approval_identity:'requester',action:'grant',grant,required:['reviewer'],approved:['reviewer'],status:'publishing',plan_hash:'fixture',policy_hash:'fixture',code:{base_commit:'0'.repeat(40),base_tree:'1'.repeat(40),before_blob:'2'.repeat(40),before:'',after:'',sha256:'x',repository:'fixture/repo',path:'intent.toml',branch:'main'},pr_url:null,events:[],notifications:'sending'};
function run(args,ok=true){const r=spawnSync(bin,args,{encoding:'utf8',timeout:10000});assert.notEqual(r.status,null,'CLI timed out');assert.equal(r.status===0,ok,r.stderr);return r.status===0?JSON.parse(r.stdout):r.stderr;}
async function put(p,v){await writeFile(p,JSON.stringify(v),{mode:0o600});}
async function stop(){if(child){const done=new Promise(r=>child.once('exit',r));child.kill('SIGTERM');await done;child=undefined;}}
try{
 await mkdir(source,{mode:0o700});await put(join(source,id+'.json'),legacy);await put(join(source,nativeId+'.json'),native);const original=await readFile(join(source,id+'.json'),'utf8');
 const args=['migrate','--source',source,'--destination',destination];assert.equal(run(args).written,false);await assert.rejects(stat(destination));run([...args,'--write'],false);
 const result=run([...args,'--write','--offline']);assert.equal(result.manifest.legacy_archives,1);assert.equal(result.manifest.native_records,1);assert.equal((await stat(destination)).mode&0o777,0o700);assert.equal(await readFile(join(source,id+'.json'),'utf8'),original);
 const archive=await readFile(join(destination,'archive',id+'.json'),'utf8');assert(!archive.includes('secret-token')&&!archive.includes('never import'));assert.equal((await stat(join(destination,'archive',id+'.json'))).mode&0o777,0o600);
 const copied=JSON.parse(await readFile(join(destination,nativeId+'.json'),'utf8'));assert.equal(copied.status,'publish_unknown');assert.equal(copied.notifications,'unknown');run([...args,'--write','--offline'],false);
 await chmod(join(source,id+'.json'),0o644);run(['migrate','--source',source,'--destination',join(root,'unsafe')],false);await chmod(join(source,id+'.json'),0o600);
 await link(join(source,id+'.json'),join(root,'hardlink'));run(['migrate','--source',source,'--destination',join(root,'unsafe')],false);await unlink(join(root,'hardlink'));
 const approvedSource=join(root,'approved-source');await mkdir(approvedSource,{mode:0o700});await put(join(approvedSource,nativeId+'.json'),{...native,status:'approved',notifications:'sent'});
 const approvedDest=join(root,'approved-dest');run(['migrate','--source',approvedSource,'--destination',approvedDest,'--write','--offline']);const pending=JSON.parse(await readFile(join(approvedDest,nativeId+'.json'),'utf8'));assert.equal(pending.status,'migration_review');assert.deepEqual(pending.approved,[]);
 // A versioned output is itself upgradeable, including sanitized archives.
 assert.equal(run(['migrate','--source',destination,'--destination',join(root,'next'),'--write','--offline']).manifest.legacy_archives,1);
 await symlink(source,join(root,'alias'));run(['migrate','--source',join(root,'alias'),'--destination',join(root,'bad')],false);
 await put(join(source,nativeId+'.json'),{...native,version:99});run(['migrate','--source',source,'--destination',join(root,'bad')],false);await put(join(source,nativeId+'.json'),native);
 // Startup reconciles an interrupted native publication without external retry.
 await put(join(destination,nativeId+'.json'),native);
 const socket=createServer();await new Promise(r=>socket.listen(0,'127.0.0.1',r));const port=socket.address().port;await new Promise(r=>socket.close(r));const origin='http://127.0.0.1:'+port;
 await writeFile(join(root,'intent.toml'),'');await writeFile(join(root,'config.toml'),`intent="intent.toml"\n[web]\npublic_url="${origin}/"\n[web.auth]\nmode="proxy"\n[approvals]\nstore="new"\nadmin=["reviewer"]\n`);
 child=spawn(bin,['-c',join(root,'config.toml'),'serve','--port',String(port)],{stdio:'ignore'});let ready=false;for(let i=0;i<100;i++){try{if((await fetch(origin+'/health')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,50));}assert(ready);
 async function identity(who){const headers={'X-Forwarded-Email':who};const login=await fetch(origin+'/auth/login',{headers,redirect:'manual'});const cookie=login.headers.getSetCookie().map(s=>s.split(';')[0]).join('; ');headers.cookie=cookie;return headers;}
 run(['-c',join(root,'config.toml'),'serve','--port','0','--public-preview'],false);
 await writeFile(join(root,'preview.toml'),'intent="intent.toml"\n');run(['-c',join(root,'preview.toml'),'serve','--host','0.0.0.0','--port','0'],false);run(['-c',join(root,'preview.toml'),'serve','--port','0','--live','--public-preview'],false);
 const requester=await identity('requester'),outsider=await identity('outsider');let r=await fetch(origin+'/api/requests/legacy-'+id,{headers:requester});assert.equal(r.status,200);assert.equal((await r.json()).readonly,true);assert.equal((await fetch(origin+'/api/requests/legacy-'+id,{headers:outsider})).status,404);
 const rows=await(await fetch(origin+'/api/requests',{headers:requester})).json();assert(rows.some(r=>r.id===nativeId&&r.status==='publish_unknown'));assert(rows.some(r=>r.status==='legacy'));
 console.log('PASS: dry-run, private copy, token/command removal, schema rejection, no overwrite, repeat migration, original preservation, scoped archive API and interrupted publication recovery.');
}finally{await stop();await rm(root,{recursive:true,force:true});}
