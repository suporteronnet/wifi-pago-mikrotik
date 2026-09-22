const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../public/ads-destination.js'),'utf8');

async function run(destination,states){
  const elements=Object.fromEntries(['status','destination','retry','title'].map(id=>[id,{hidden:true}]));
  const redirects=[],requests=[];let cleared=false;
  const context={URL,URLSearchParams,AbortController,Date,Error,
    document:{getElementById:id=>elements[id]},
    location:{hash:'#'+new URLSearchParams({token:'a'.repeat(64),destination}),pathname:'/ads-destination.html',replace:value=>redirects.push(value)},
    history:{replaceState:()=>{cleared=true;}},
    setTimeout:(fn,ms)=>{if(ms===1000)queueMicrotask(fn);return 1;},clearTimeout:()=>{},
    fetch:async(path,options)=>{requests.push({path,body:JSON.parse(options.body)});const state=states.shift();assert.ok(state,'unexpected poll');if(state instanceof Error)throw state;return {ok:true,status:200,json:async()=>({ok:true,status:state})};}
  };
  vm.runInNewContext(source,context);
  for(let i=0;i<30;i++)await new Promise(resolve=>setImmediate(resolve));
  return {elements,redirects,requests,cleared};
}
test('destination waits for actual router confirmation and preserves WhatsApp message',async()=>{
  const destination='https://wa.me/5569999999999?text=Tenho%20interesse%21';
  const result=await run(destination,['viewing','pending',new Error('network changed'),'applied']);
  assert.equal(result.requests.length,4);
  assert.deepEqual(result.redirects,[destination]);
  assert.equal(result.elements.destination.href,destination);
  assert.equal(result.elements.destination.hidden,false);
  assert.equal(result.cleared,true);
});
test('site opens after confirmation; expired or cancelled requests never redirect',async()=>{
  const destination='https://example.com/oferta?cupom=wifi';
  assert.deepEqual((await run(destination,['applied'])).redirects,[destination]);
  for(const status of ['expired','cancelled']){
    const result=await run(destination,[status]);
    assert.deepEqual(result.redirects,[]);
    assert.equal(result.elements.destination.hidden,true);
    assert.equal(result.elements.retry.hidden,false);
  }
});
test('unsafe destinations cannot open or start polling',async()=>{
  const result=await run('javascript:alert(1)',[]);
  assert.deepEqual(result.redirects,[]);
  assert.equal(result.requests.length,0);
});
