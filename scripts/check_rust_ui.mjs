// HTTP contract for the real native SSR/WASM console; no external services.
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {spawn} from 'node:child_process';
import {resolve} from 'node:path';
const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
const origin=`http://127.0.0.1:${port}`;
const child=spawn(resolve('rust/target/debug/grantline-rs'),['-c',resolve('examples/demo/grantline.toml'),'serve','--port',String(port)],{stdio:['ignore','ignore','pipe']});
let errors='';child.stderr.on('data',b=>errors+=b);const pages=['/','/accounts','/resources','/services','/matrix','/changes','/history','/approvals','/act'];
try {
  let ready=false;for(let i=0;i<200;i++){if(child.exitCode!==null)throw Error(errors);try{ready=(await fetch(origin+'/api/catalog')).ok;if(ready)break;}catch{}await new Promise(r=>setTimeout(r,50));}assert(ready,'native console ready');
  for(const page of pages){const response=await fetch(origin+page);assert.equal(response.status,200,page);assert.match(response.headers.get('content-security-policy'),/wasm-unsafe-eval/);assert.equal(response.headers.get('cache-control'),'no-store');const html=await response.text();assert.match(html,/id=grantline-app/);assert.match(html,/native-boot.js/);const data=JSON.parse(html.match(/<script id=grantline-data type=application\/json>(.*?)<\/script>/s)[1]);assert.equal(data.interactive,true);assert.equal(data.error,null,page);assert(data.data.services.includes('s3'));assert.equal(data.data.service_kinds.s3,'s3');if(page==='/')assert(data.data.graph.edges.length>0);if(page==='/act')assert.match(html,/fieldset disabled/);}
  for(const [lang,label]of [['en','Services'],['ko','서비스'],['ja','サービス'],['zh-CN','服务']]){const r=await fetch(origin+'/services?lang='+lang);const html=await r.text();assert.match(html,new RegExp(`<html lang="${lang}"`));assert(html.includes(label));assert.match(r.headers.get('set-cookie'),new RegExp(`grantline_lang=${lang}`));assert(html.includes('postgres-staging'));}
  const attack='</script><script>alert(1)</script>';const html=await(await fetch(origin+'/?q='+encodeURIComponent(attack))).text();assert(!html.includes(attack));assert(html.includes('\\u003c/script\\u003e'));
  const dark=await(await fetch(origin+'/changes',{headers:{cookie:'grantline_lang=ja; grantline_theme=dark'}})).text();assert.match(dark,/<html lang="ja" data-theme="dark"/);
  for(const [path,mime]of [['/static/grantline.css','text/css'],['/static/native-boot.js','text/javascript'],['/static/pkg/grantline_ui.js','text/javascript'],['/static/pkg/grantline_ui_bg.wasm','application/wasm'],['/static/postgresql.png','image/png'],['/static/seaweedfs.png','image/png']]){const r=await fetch(origin+path);assert.equal(r.status,200,path);assert(r.headers.get('content-type').startsWith(mime));const etag=r.headers.get('etag');assert(etag);assert.equal((await fetch(origin+path,{headers:{'if-none-match':etag}})).status,304);}
  assert.equal((await fetch(origin+'/static/pkg/nope.js')).status,404);
  const r=await fetch(origin+'/api/snapshots',{method:'POST',headers:{'content-type':'application/json',Origin:origin},body:'{"csrf":""}'});assert.equal(r.status,401);
  console.log('Native UI: 9 SSR pages, 4 locales, escaped bootstrap, private caching/CSP, WASM MIME/ETag, official icons and read-only mutation guard passed.');
}finally{child.kill('SIGTERM');await new Promise(r=>child.once('exit',r));}
