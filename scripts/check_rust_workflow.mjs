// Isolated Slack/GitHub endpoints and native proxy sessions; no external writes.
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {createServer} from 'node:http';
import {mkdtemp,writeFile,readFile,readdir,stat,realpath,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
const sha=c=>c.repeat(40),base=sha('a'),tree=sha('b'),blob=sha('c'),commit=sha('f');
const source='managed_subjects = ["demo"]\n';let messages=[],writes=[],fault='',currentBase=base,slowNotify=false,slowPublish=false,notifyReady,publishReady;
const external=createServer(async(req,res)=>{
  let text='';for await(const b of req)text+=b;const input=text?JSON.parse(text):{};
  const json=v=>{res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(v));};
  assert.ok(req.headers.authorization?.startsWith('Bearer synthetic-'));
  if(req.url==='/github/user')return json({id:12345,login:fault==='identity'?'wrong':'fixture-bot'});
  if(req.url==='/github/repos/fixture/repo')return json({private:fault!=='public'});
  if(req.url==='/github/repos/fixture/repo/git/ref/heads/main')return json({object:{sha:currentBase}});
  if(req.url==='/github/repos/fixture/repo/git/commits/'+currentBase)return json({tree:{sha:tree}});
  if(req.url==='/github/repos/fixture/repo/git/trees/'+tree)return json({tree:[{path:'intent.toml',mode:'100644',type:'blob',sha:blob}]});
  if(req.url==='/github/repos/fixture/repo/git/blobs/'+blob)return json({encoding:'base64',content:Buffer.from(source).toString('base64')});
  if(req.url==='/slack/conversations.open')return json({ok:true,channel:{id:'dm-'+input.users}});
  if(req.url==='/slack/chat.postMessage'){messages.push(input);if(slowNotify){slowNotify=false;notifyReady();await new Promise(r=>setTimeout(r,4000));}return json({ok:true,ts:'1.0'});}
  writes.push({method:req.method,path:req.url,body:input});
  if(slowPublish&&req.url.endsWith('/git/refs')){slowPublish=false;publishReady();await new Promise(r=>setTimeout(r,4000));}
  if(fault==='publication'){res.writeHead(500);return res.end('synthetic-private-error');}
  if(req.url.endsWith('/git/refs')){assert.equal(input.sha,base);assert.match(input.ref,/^refs\/heads\/grantline\/[0-9a-f]{32}$/);return json({object:{sha:base}});}
  if(req.url.endsWith('/git/blobs')){const after=Buffer.from(input.content,'base64').toString();assert.match(after,/managed_subjects/);assert.match(after,/bucket:probe\/team/);return json({sha:sha('d')});}
  if(req.url.endsWith('/git/trees')){assert.equal(input.base_tree,tree);assert.equal(input.tree.length,1);assert.equal(input.tree[0].path,'intent.toml');return json({sha:sha('e')});}
  if(req.url.endsWith('/git/commits')){assert.deepEqual(input.parents,[base]);assert.equal(input.author.email,'12345+fixture-bot@users.noreply.github.com');assert.deepEqual(input.author,input.committer);return json({sha:commit});}
  if(req.method==='PATCH'){assert.equal(input.force,false);assert.equal(input.sha,commit);return json({object:{sha:commit}});}
  if(req.url.endsWith('/pulls')){assert.equal(input.base,'main');assert.match(input.body,/## 변경 요약/);assert.match(input.body,/실제 IAM 권한을 적용하지/);return json({number:1,html_url:'https://github.com/fixture/repo/pull/1',head:{sha:commit}});}
  res.writeHead(404);res.end('{}');
});
await new Promise(r=>external.listen(0,'127.0.0.1',r));const api='http://127.0.0.1:'+external.address().port;
const free=createServer();await new Promise(r=>free.listen(0,'127.0.0.1',r));const port=free.address().port;await new Promise(r=>free.close(r));
const root=await realpath(await mkdtemp(join(tmpdir(),'grantline-workflow-'))),origin='http://127.0.0.1:'+port;let child,output='';
async function boot(){
  child=spawn(resolve('rust/target/debug/grantline-rs'),['-c',join(root,'config.toml'),'serve','--port',String(port)],{env:{...process.env,GL_GH_FIXTURE:'synthetic-github',GL_SLACK_FIXTURE:'synthetic-slack',GL_SIGN_FIXTURE:'synthetic-signing-fixture'},stdio:['ignore','pipe','pipe']});child.stdout.on('data',d=>output+=d);child.stderr.on('data',d=>output+=d);
  for(let i=0;i<100;i++){try{if((await fetch(origin+'/health')).ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw Error('Native workflow failed: '+output);
}
async function stop(){const exited=new Promise(r=>child.once('exit',r));child.kill('SIGTERM');await exited;}
async function login(who){const h={'X-Forwarded-Email':who};const r=await fetch(origin+'/auth/login',{headers:h,redirect:'manual'});assert.equal(r.status,303);const cookie=r.headers.getSetCookie().map(v=>v.split(';')[0]).join('; ');const headers={...h,cookie,origin,'content-type':'application/json'};const identity=await(await fetch(origin+'/api/session',{headers})).json();return{headers,csrf:identity.csrf};}
async function post(path,actor,payload={},ok=true){const r=await fetch(origin+path,{method:'POST',headers:actor.headers,body:JSON.stringify({...payload,csrf:actor.csrf})});assert.equal(r.ok,ok,await r.clone().text());return r.ok?await r.json():null;}
async function signCallback(value,user,{team='fixture-team',age=0,signature=true}={}){
  const body=new URLSearchParams({payload:JSON.stringify({type:'block_actions',team:{id:team},user:{id:user},actions:[{value:JSON.stringify(value)}]})}).toString();const timestamp=String(Math.floor(Date.now()/1000)+age);const digest='v0='+createHmac('sha256','synthetic-signing-fixture').update('v0:'+timestamp+':'+body).digest('hex');
  return fetch(origin+'/api/slack/actions',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded','X-Slack-Request-Timestamp':timestamp,'X-Slack-Signature':signature?digest:'v0=wrong'},body});
}
try{
  await writeFile(join(root,'intent.toml'),'');await writeFile(join(root,'fixture.json'),'{"identities":[]}');
  await writeFile(join(root,'config.toml'),`intent="intent.toml"\n[adapters.s3]\ntype="s3"\n[adapters.s3.planes.static]\nfile="fixture.json"\n[web]\npublic_url="${origin}/"\n[web.auth]\nmode="proxy"\n[approvals]\nstore="state"\nadmin=["reviewer","owner"]\n[approvals.code_writer]\nrepository="fixture/repo"\nintent_path="intent.toml"\ntoken_env="GL_GH_FIXTURE"\nexpected_login="fixture-bot"\napi_url="${api}/github/"\n[approvals.slack]\nbot_token_env="GL_SLACK_FIXTURE"\nsigning_secret_env="GL_SIGN_FIXTURE"\nteam_id="fixture-team"\napi_url="${api}/slack/"\n`);
  await boot();let requester=await login('requester'),reviewer=await login('reviewer'),owner=await login('owner'),outsider=await login('outsider');
  await post('/api/snapshots',requester);const snapshotNames=await readdir(join(root,'snapshots'));const header=JSON.parse((await readFile(join(root,'snapshots',snapshotNames[0]),'utf8')).split('\n')[0]);assert.equal(header.run.user,'requester');
  const input={system:'s3',subject:'demo',resource:'bucket:probe/team',privilege:'Read',action:'grant'};
  await post('/api/requests',reviewer,input,false);assert.equal(messages.length,0);
  for(const kind of ['identity','public']){fault=kind;await post('/api/requests',requester,input,false);}fault='';
  const request=await post('/api/requests',requester,input);assert.equal(request.status,'pending');assert.equal(request.applied,false);assert.deepEqual(request.required,['owner','reviewer']);assert.equal(messages.length,2);assert.ok(messages.every(m=>m.text.includes('does not apply IAM')));
  assert.equal((await post('/api/requests',requester,input)).id,request.id);assert.equal(messages.length,2,'duplicate request repeated notification');
  assert.equal((await(await fetch(origin+'/api/requests',{headers:outsider.headers})).json()).length,0);
  await post('/api/requests/'+request.id+'/publish',requester,{},false);assert.equal(writes.length,0);
  await post('/api/requests/'+request.id+'/decide',requester,{plan_hash:request.plan_hash,decision:'approve'},false);
  await post('/api/requests/'+request.id+'/decide',owner,{plan_hash:'wrong',decision:'approve'},false);
  const first=await post('/api/requests/'+request.id+'/decide',owner,{plan_hash:request.plan_hash,decision:'approve'});assert.equal(first.status,'pending');
  await post('/api/requests/'+request.id+'/decide',owner,{plan_hash:request.plan_hash,decision:'approve'},false);
  const action={id:request.id,decision:'approve',plan_hash:request.plan_hash};
  for(const opts of [{signature:false},{team:'wrong'},{age:-600}])assert.equal((await signCallback(action,'reviewer',opts)).status,409);
  assert.equal((await signCallback(action,'outsider')).status,409);
  assert.equal((await signCallback(action,'reviewer')).status,200);assert.equal((await signCallback(action,'reviewer')).status,409);
  const record=join(root,'state',request.id+'.json');assert.equal((await stat(record)).mode&0o777,0o600);assert.equal((await stat(join(root,'state'))).mode&0o777,0o700);
  await stop();await boot();requester=await login('requester');reviewer=await login('reviewer');owner=await login('owner');
  const persisted=await(await fetch(origin+'/api/requests',{headers:reviewer.headers})).json();assert.equal(persisted[0].status,'approved');
  const notificationStarted=new Promise(r=>notifyReady=r);slowNotify=true;
  const otherPromise=post('/api/requests',requester,{...input,resource:'bucket:probe/concurrent'});await notificationStarted;
  const actionDuringNotify=JSON.parse(messages.at(-1).blocks[1].elements.find(e=>e.action_id==='approve').value);
  let started=Date.now();const ack=await signCallback(actionDuringNotify,'owner');assert.equal(ack.status,200);assert.equal(await ack.text(),'');const ackMs=Date.now()-started;assert(ackMs<2500,'Slack ack blocked by an outbound DM');
  const other=await otherPromise;assert(other.approved.includes('owner'),'DM completion overwrote a callback approval');
  const publicationStarted=new Promise(r=>publishReady=r);slowPublish=true;
  const publication=post('/api/requests/'+request.id+'/publish',requester);await publicationStarted;
  started=Date.now();await post('/api/requests/'+other.id+'/decide',reviewer,{plan_hash:other.plan_hash,decision:'approve'});const decisionMs=Date.now()-started;assert(decisionMs<2500,'Independent decision blocked by GitHub publication');console.log(`PASS: 4s external delays; Slack ack ${ackMs}ms, independent decision ${decisionMs}ms, concurrent approval preserved`);
  const published=await publication;assert.equal(published.status,'proposed');assert.equal(published.pr_url,'https://github.com/fixture/repo/pull/1');assert.equal(published.applied,false);assert.equal(writes.length,6);
  await post('/api/requests/'+request.id+'/publish',requester,{},false);assert.equal(writes.length,6,'publication retried');
  // Stale source and uncertain external failures stay durable and cannot auto-retry.
  const configText=await readFile(join(root,'config.toml'),'utf8');
  currentBase=sha('9');const stale=await post('/api/requests',requester,input);for(const actor of [reviewer,owner])await post('/api/requests/'+stale.id+'/decide',actor,{plan_hash:stale.plan_hash,decision:'approve'});currentBase=base;
  await post('/api/requests/'+stale.id+'/publish',requester,{},false);assert.equal(writes.length,6);assert.equal(JSON.parse(await readFile(join(root,'state',stale.id+'.json'),'utf8')).status,'publish_unknown');
  currentBase=sha('7');const uncertain=await post('/api/requests',requester,input);for(const actor of [reviewer,owner])await post('/api/requests/'+uncertain.id+'/decide',actor,{plan_hash:uncertain.plan_hash,decision:'approve'});fault='publication';
  await post('/api/requests/'+uncertain.id+'/publish',requester,{},false);assert.equal(writes.length,7);await post('/api/requests/'+uncertain.id+'/publish',requester,{},false);assert.equal(writes.length,7);fault='';
  assert.equal(JSON.parse(await readFile(join(root,'state',uncertain.id+'.json'),'utf8')).status,'publish_unknown');
  currentBase=sha('8');const policy=await post('/api/requests',requester,input);await stop();await writeFile(join(root,'config.toml'),configText.replace('admin=["reviewer","owner"]','admin=["reviewer","owner","new-owner"]'));await boot();reviewer=await login('reviewer');
  await post('/api/requests/'+policy.id+'/decide',reviewer,{plan_hash:policy.plan_hash,decision:'approve'},false);
  assert.ok(!output.includes('synthetic-github')&&!output.includes('synthetic-slack'));
  assert.equal((await readdir(join(root,'state'))).filter(n=>n.endsWith('.json')).length,5);assert.ok(configText.includes('fixture/repo'));
  console.log('PASS: authenticated requester, all independent approvals, duplicate-submit/replay/CSRF guards, signed workspace-bound Slack DMs/callback, restart persistence, exact Git scope/patch/base and single PR, stale-source refusal and no IAM application');
}finally{if(child?.exitCode===null)await stop();await new Promise(r=>external.close(r));await rm(root,{recursive:true,force:true});}
