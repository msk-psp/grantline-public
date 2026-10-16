// A disposable signed OIDC provider. No external account, callback or token is used.
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomUUID} from 'node:crypto';
import {createServer} from 'node:http';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';

const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk={...publicKey.export({format:'jwk'}),kid:'fixture',use:'sig',alg:'RS256'};
const b64=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
const codes=new Map();let fault='';let exchanges=0;let issuer='';
const provider=createServer(async(req,res)=>{
  const u=new URL(req.url,issuer);
  const json=v=>{res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(v));};
  if(u.pathname==='/.well-known/openid-configuration')return json({issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],subject_types_supported:['public'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['none']});
  if(u.pathname==='/keys')return json({keys:[jwk]});
  if(u.pathname==='/authorize'){
    assert.equal(u.searchParams.get('code_challenge_method'),'S256');
    const code=randomUUID();codes.set(code,Object.fromEntries(u.searchParams));
    const next=new URL(u.searchParams.get('redirect_uri'));next.searchParams.set('code',code);next.searchParams.set('state',u.searchParams.get('state'));res.writeHead(302,{location:next.href});return res.end();
  }
  if(u.pathname==='/token'){
    exchanges++;let data='';for await(const chunk of req)data+=chunk;
    const q=new URLSearchParams(data),p=codes.get(q.get('code'));codes.delete(q.get('code'));
    if(!p||createHash('sha256').update(q.get('code_verifier')??'').digest('base64url')!==p.code_challenge){res.writeHead(400);return res.end('{}');}
    const now=Math.floor(Date.now()/1000);
    const claims={iss:fault==='issuer'?'https://wrong.example':issuer,sub:fault==='subject'?'intruder':'reviewer',aud:fault==='audience'?'wrong':'fixture-console',exp:now+(fault==='expiry'?-300:300),iat:now,nonce:fault==='nonce'?'wrong':p.nonce};
    const body=b64({alg:'RS256',kid:'fixture'})+'.'+b64(claims);
    let signature=sign('RSA-SHA256',Buffer.from(body),privateKey).toString('base64url');if(fault==='signature')signature='x'+signature.slice(1);
    return json({access_token:'synthetic-oidc-access',token_type:'Bearer',expires_in:300,id_token:body+'.'+signature});
  }
  res.writeHead(404);res.end();
});
await new Promise(r=>provider.listen(0,'127.0.0.1',r));issuer='http://127.0.0.1:'+provider.address().port;
const portServer=createServer();await new Promise(r=>portServer.listen(0,'127.0.0.1',r));const port=portServer.address().port;await new Promise(r=>portServer.close(r));
const root=await mkdtemp(join(tmpdir(),'grantline-oidc-'));let child;
try{
  const origin='http://127.0.0.1:'+port;
  await writeFile(join(root,'intent.toml'),'');
  await writeFile(join(root,'config.toml'),`intent="intent.toml"\n[web]\npublic_url="${origin}/"\n[web.auth]\nmode="oidc"\nissuer="${issuer}"\nclient_id="fixture-console"\nallowed_subjects=["reviewer"]\n`);
  child=spawn(resolve('rust/target/debug/grantline-rs'),['-c',join(root,'config.toml'),'serve','--port',String(port)],{stdio:['ignore','pipe','pipe']});let output='';child.stdout.on('data',d=>output+=d);child.stderr.on('data',d=>output+=d);
  for(let i=0;i<100;i++){try{if((await fetch(origin+'/health')).ok)break;}catch{}if(i===99)throw Error('Native console failed: '+output);await new Promise(r=>setTimeout(r,100));}
  assert.equal((await fetch(origin+'/api/catalog')).status,401);
  const cookie=r=>r.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
  async function start(){const a=await fetch(origin+'/auth/login?rd=%2Fmatrix',{redirect:'manual'});assert.equal(a.status,303);const b=await fetch(a.headers.get('location'),{redirect:'manual'});return{callback:b.headers.get('location'),cookie:cookie(a)};}
  const lost=await start();assert.equal((await fetch(lost.callback,{redirect:'manual'})).status,401);
  for(const kind of ['nonce','issuer','audience','expiry','signature','subject']){
    fault=kind;const a=await start();const r=await fetch(a.callback,{headers:{cookie:a.cookie},redirect:'manual'});assert.ok([401,403].includes(r.status),kind+': '+r.status);
  }
  fault='';const a=await start();const r=await fetch(a.callback,{headers:{cookie:a.cookie},redirect:'manual'});assert.equal(r.status,303);assert.equal(r.headers.get('location'),'/matrix');
  const sessionCookie=cookie(r);assert.match(r.headers.get('set-cookie'),/HttpOnly/);assert.match(r.headers.get('set-cookie'),/SameSite=Lax/);
  const identity=await(await fetch(origin+'/api/session',{headers:{cookie:sessionCookie}})).json();assert.equal(identity.subject,'reviewer');assert.equal(identity.authenticated,true);assert.ok(identity.csrf.length>=32);
  const count=exchanges;assert.equal((await fetch(a.callback,{headers:{cookie:a.cookie},redirect:'manual'})).status,401);assert.equal(exchanges,count,'replay contacted token endpoint');
  assert.equal((await fetch(origin+'/api/catalog',{headers:{cookie:sessionCookie}})).status,200);
  const logout=(csrf,from)=>fetch(origin+'/auth/logout',{method:'POST',headers:{cookie:sessionCookie,origin:from,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf}),redirect:'manual'});
  assert.equal((await logout(identity.csrf,'https://evil.example')).status,403);assert.equal((await logout('wrong',origin)).status,403);assert.equal((await logout(identity.csrf,origin)).status,303);assert.equal((await fetch(origin+'/api/session',{headers:{cookie:sessionCookie}})).status,401);
  assert.ok(!output.includes('synthetic-oidc-access'));
  console.log('PASS: signed OIDC login with browser-bound state/PKCE; issuer/audience/nonce/expiry/signature/allowlist refusal, callback replay, private session, origin/CSRF and logout');
}finally{child?.kill('SIGTERM');await new Promise(r=>provider.close(r));await rm(root,{recursive:true,force:true});}
