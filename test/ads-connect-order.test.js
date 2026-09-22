const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync(require.resolve('../public/ads-stories.js'),'utf8');
const start=source.indexOf('  async function connectAccess(');
const end=source.indexOf("  $('profileForm').addEventListener",start);
test('mobile offer requests access and waits for ACK before opening destination',async()=>{
  for(const [userAgent,destination] of [['Android','https://wa.me/5569999999999?text=Ola'],['iPhone','https://example.com/oferta'],['Android','']]){
    const calls=[],elements={};let checks=0;
    const context={connecting:false,profileSaved:true,token:'test',navigator:{userAgent},URL,Date,
      $:id=>elements[id]??=( {hidden:id==='offerScreen'?false:true,querySelectorAll:()=>[]} ),
      saveSession:()=>{},step:()=>{},message:()=>{},sleep:async()=>{},params:new URLSearchParams('linkOrig=https://portal.example/anuncios.html'),playlist:[],interests:new Set(),url:v=>v,
      location:{assign:()=>assert.fail('must not leave portal before access'),replace:url=>calls.push(url)},
      post:async path=>{calls.push(path);return path==='/api/ads/status'?{status:++checks===1?'pending':'applied'}:{ok:true};}
    };
    vm.createContext(context);vm.runInContext(source.slice(start,end),context);
    await context.connectAccess(destination);
    assert.deepEqual(calls,['/api/ads/access','/api/ads/status','/api/ads/status',destination||'http://neverssl.com/']);
  }
});
