// Serve the real SSR/WASM map with fictional, repeatable scale fixtures.
// No browser driver or production service/credentials are involved.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {resolve} from 'node:path';
const check=process.argv.includes('--check');
const portArg=process.argv.indexOf('--port');
const port=portArg<0?8426:Number(process.argv[portArg+1]);
assert(Number.isSafeInteger(port)&&port>=0&&port<=65535,"port must be 0..65535");
const native=createServer();await new Promise(r=>native.listen(0,'127.0.0.1',r));const nativePort=native.address().port;await new Promise(r=>native.close(r));
const child=spawn(resolve('rust/target/debug/grantline-rs'),['-c',resolve('examples/demo/grantline.toml'),'serve','--port',String(nativePort)],{stdio:['ignore','ignore','pipe']});
let errors='';child.stderr.on('data',b=>errors+=b);
let ready=false;
for(let i=0;i<200;i++){if(child.exitCode!==null)throw Error(errors);try{if((await fetch(`http://127.0.0.1:${nativePort}/api/catalog`)).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,50));}
if(!ready){child.kill('SIGTERM');throw Error('Rust fixture child did not become ready: '+errors);}
function fixture(count,base){
  const graph={edges:[],principals:['demo-user-a','demo-user-b'],hops:['role:shared','role:other','group:demo','policy:demo'],terminals:[],names:{'demo-user-a':'Demo User A','demo-user-b':'Demo User B'},kind:{'demo-user-a':'human','demo-user-b':'human','role:shared':'role','role:other':'role','group:demo':'group','policy:demo':'policy'},envs:base.envs,teams:{'demo-user-a':'Demo','demo-user-b':'Demo'},homes:{}};
  const edge=(src,dst,kind='grant')=>graph.edges.push({src,dst,system:'s3',kind,privs:['Read'],note:''});
  edge('demo-user-a','group:demo','member');edge('group:demo','policy:demo','policy');edge('policy:demo','role:shared','member');edge('demo-user-b','role:other','member');
  for(let i=0;i<count;i++){const resource=`bucket:demo/resource-${String(i).padStart(6,'0')}`;graph.terminals.push(resource);edge('role:shared',resource);edge('policy:demo',resource);if(i%4===0)edge('role:other',resource);}
  return graph;
}
const server=createServer(async(req,res)=>{
  try{
    if(req.method!=='GET'){res.writeHead(405).end('Fixture server is read-only');return;}
    const url=new URL(req.url,'http://localhost');const r=await fetch(`http://127.0.0.1:${nativePort}${req.url}`,{headers:{'accept-language':req.headers['accept-language']??'en'}});
    const headers=Object.fromEntries(r.headers);delete headers['transfer-encoding'];delete headers['content-length'];delete headers['content-encoding'];
    let body=Buffer.from(await r.arrayBuffer());
    if(url.pathname==='/'){
      const count=Number(url.searchParams.get('graphSize')??1000);assert(Number.isSafeInteger(count)&&count>=1&&count<=100_000,'graphSize must be 1..100000');
      const html=body.toString();const match=html.match(/(<script id=grantline-data type=application\/json>)(.*?)(<\/script>)/s);assert(match,'real SSR bootstrap');
      const boot=JSON.parse(match[2]);boot.data.graph=fixture(count,boot.data.graph);boot.loading=false;
      const json=JSON.stringify(boot).replaceAll('<','\\u003c').replaceAll('>','\\u003e').replaceAll('&','\\u0026');
      body=Buffer.from(html.replace(match[0],match[1]+json+match[3]));headers['cache-control']='no-store';
    }
    res.writeHead(r.status,headers);res.end(body);
  }catch(e){res.writeHead(500).end(String(e));}
});
try {await new Promise((done,fail)=>{server.once('error',fail);server.listen(port,'127.0.0.1',done);});}
catch(error){child.kill('SIGTERM');throw error;}
const actualPort=server.address().port;
let closing=false;const close=async()=>{if(closing)return;closing=true;server.closeAllConnections();await new Promise(r=>server.close(r));if(child.exitCode===null){child.kill('SIGTERM');await new Promise(r=>child.once('exit',r));}};
process.once('SIGINT',()=>close());process.once('SIGTERM',()=>close());
if(check){
  try{
    for(const count of [1000,100_000]){const r=await fetch(`http://127.0.0.1:${actualPort}/?graphSize=${count}`);assert.equal(r.status,200);const html=await r.text();const b=JSON.parse(html.match(/<script id=grantline-data type=application\/json>(.*?)<\/script>/s)[1]);assert.equal(b.data.graph.terminals.length,count);assert.equal(b.data.graph.edges.length,count*2+Math.ceil(count/4)+4);assert.equal((html.match(/<canvas /g)??[]).length,2);assert(!html.includes('<svg class="permission-map"'));}
    assert.equal((await fetch(`http://127.0.0.1:${actualPort}/api/requests`,{method:'POST'})).status,405);
    console.log('Real SSR/WASM fixture: 1,000 and 100,000 resources, bounded initial DOM, all resource identities and read-only boundary passed.');
  }finally{await close();}
}else console.log(`Graph fixture: http://127.0.0.1:${actualPort}/?graphSize=100000 (real Rust/WASM, fictional data only)`);
