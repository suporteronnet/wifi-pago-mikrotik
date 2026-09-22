const {test}=require('node:test');
const assert=require('node:assert/strict');
const express=require('express');
const Database=require('better-sqlite3');
const crypto=require('crypto');
const register=require('../lib/ad-stories');

test('lead migration preserves existing sessions, dependent Stories and indexes',()=>{
  const db=new Database(':memory:');
  try{
    db.exec(`CREATE TABLE events(id INTEGER PRIMARY KEY);CREATE TABLE ad_campaigns(id INTEGER PRIMARY KEY);
      INSERT INTO events VALUES(1);INSERT INTO ad_campaigns VALUES(1);
      CREATE TABLE ad_view_sessions(token_hash TEXT PRIMARY KEY,event_id INTEGER,router_id INTEGER,campaign_id INTEGER NOT NULL REFERENCES ad_campaigns(id) ON DELETE CASCADE,mac TEXT,created_at TEXT,expires_at TEXT,command_ref TEXT);
      CREATE INDEX session_expiry ON ad_view_sessions(expires_at);
      INSERT INTO ad_view_sessions VALUES('existing',1,1,1,'test','now','later',NULL);
      CREATE TABLE ad_story_runs(token_hash TEXT PRIMARY KEY REFERENCES ad_view_sessions(token_hash) ON DELETE CASCADE,playlist TEXT,current_index INTEGER,started_at INTEGER,completed INTEGER,settings_json TEXT);
      INSERT INTO ad_story_runs VALUES('existing','[]',0,0,0,'{}');`);
    const options={app:express(),db,adminAuth:(req,res,next)=>next(),requireRole:()=>((req,res,next)=>next()),normalizeMac:v=>v};
    register(options);register(options);
    assert.equal(db.prepare('SELECT COUNT(*) n FROM ad_view_sessions').get().n,1);
    assert.equal(db.prepare('SELECT COUNT(*) n FROM ad_story_runs').get().n,1);
    assert.equal(db.pragma('table_info(ad_view_sessions)').find(c=>c.name==='campaign_id').notnull,0);
    assert.equal(db.pragma('foreign_keys',{simple:true}),1);
    assert.deepEqual(db.pragma('foreign_key_check'),[]);
    assert.ok(db.prepare("SELECT name FROM sqlite_master WHERE name='session_expiry'").get());
  }finally{db.close();}
});

test('campaign albums, settings, server-side viewing gate and contacts',async t=>{
  const db=new Database(':memory:');
  db.exec(`CREATE TABLE events(id INTEGER PRIMARY KEY,event_key TEXT,name TEXT,portal_mode TEXT,status TEXT);
    CREATE TABLE routers(id INTEGER PRIMARY KEY,event_id INTEGER,router_key TEXT,status TEXT);
    CREATE TABLE ad_campaigns(id INTEGER PRIMARY KEY,event_id INTEGER,name TEXT,image_path TEXT,target_url TEXT,active INTEGER DEFAULT 1,starts_at TEXT,ends_at TEXT,created_at TEXT,updated_at TEXT,impressions INTEGER DEFAULT 0);
    CREATE TABLE ad_campaign_events(campaign_id INTEGER,event_id INTEGER);
    CREATE TABLE ad_view_sessions(token_hash TEXT PRIMARY KEY,event_id INTEGER,router_id INTEGER,campaign_id INTEGER REFERENCES ad_campaigns(id) ON DELETE CASCADE,mac TEXT,created_at TEXT,expires_at TEXT,command_ref TEXT);
    CREATE TABLE admin_commands(command_ref TEXT,status TEXT);
    INSERT INTO events VALUES(1,'ads','Ads','ads','active'),(2,'pix','PIX','pix','active'),(3,'other','Other','ads','active');
    INSERT INTO routers VALUES(1,1,'router','active');`);
  const app=express();app.use(express.json());
  const adminAuth=(req,res,next)=>req.headers['x-test-admin']==='yes'?next():res.status(401).json({ok:false});
  // A delayed presence report must not delay Story delivery; access stays gated separately.
  const service=register({app,db,adminAuth,requireRole:()=>((req,res,next)=>next()),normalizeMac:v=>/^([a-f0-9]{2}:){5}[a-f0-9]{2}$/i.test(v||'')?v:'',adRouterHasClient:()=>false});
  app.post('/api/ads/session',service.start);
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(()=>{server.closeAllConnections();server.close();db.close();});
  const base=`http://127.0.0.1:${server.address().port}`;
  async function request(path,method='GET',body,admin=true){const r=await fetch(base+path,{method,headers:{'Content-Type':'application/json',...(admin?{'x-test-admin':'yes'}:{})},body:body===undefined?undefined:JSON.stringify(body)});return {status:r.status,data:await r.json()};}
  const campaign={event_id:1,name:'Album',target_url:'https://example.com',position:2,active:true,slides:[{image_path:'/api/ad-images/first.jpg',duration:3,overlay_text:'Conheca nossas ofertas!'},{image_path:'/api/ad-images/second.png',duration:5}]};
  let r=await request('/admin/api/ad-story-campaigns','POST',campaign);assert.equal(r.status,201);const id=r.data.id;
  r=await request('/admin/api/ad-portals/1');assert.equal(r.data.campaigns[0].slides.length,2);
  assert.equal(r.data.campaigns[0].button_label,'Me interessa');
  assert.equal(r.data.campaigns[0].whatsapp_enabled,0);
  const buttons={button_label:'Visitar site',whatsapp_enabled:true,whatsapp_phone:'+55 (69) 99999-1234',whatsapp_message:'Olá! Vi o anúncio & quero saber mais.'};
  assert.equal((await request('/admin/api/ad-story-campaigns/'+id,'PUT',{...campaign,...buttons})).status,200);
  const configured=(await request('/admin/api/ad-portals/1')).data.campaigns[0];
  assert.equal(configured.button_label,buttons.button_label);
  assert.equal(configured.whatsapp_phone,'5569999991234');
  assert.equal(configured.whatsapp_message,buttons.whatsapp_message);
  assert.equal((await request('/admin/api/ad-story-campaigns/'+id,'PUT',{...campaign,...buttons,whatsapp_phone:''})).status,400);
  assert.equal((await request('/admin/api/ad-story-campaigns/'+id,'PUT',{...campaign,...buttons,whatsapp_phone:'javascript:1'})).status,400);
  assert.equal((await request('/admin/api/ad-story-campaigns/'+id,'PUT',{...campaign,...buttons,button_label:'x'.repeat(33)})).status,400);
  assert.equal((await request('/admin/api/ad-portals/1','GET',undefined,false)).status,401);
  assert.equal((await request('/admin/api/ad-story-campaigns','POST',{...campaign,event_id:2})).status,400);
  assert.equal((await request('/admin/api/ad-story-campaigns','POST',{...campaign,slides:[]})).status,400);
  assert.equal((await request('/admin/api/ad-story-campaigns','POST',{...campaign,target_url:'javascript:alert(1)'})).status,400);
  assert.equal((await request('/admin/api/ad-story-campaigns','POST',{...campaign,starts_at:'2026-01-02',ends_at:'2026-01-01'})).status,400);
  const config={...r.data.settings,email:'required',city:'optional',survey:'required',survey_question:'Feedback?',title:'Welcome',color:'#336699'};
  delete config.fields; // Compatibility with the previous settings payload.
  assert.equal((await request('/admin/api/ad-portals/1','PUT',config)).status,200);
  assert.equal((await request('/admin/api/ad-portals/1')).data.settings.title,'Welcome');
  const start=await request('/api/ads/session','POST',{event_key:'ads',router_key:'router',mac:'02:00:00:00:00:01'},false);
  assert.equal(start.status,200);assert.equal(start.data.playlist.length,2);assert.equal(start.data.playlist[1].image_path,campaign.slides[1].image_path);
  assert.equal(start.data.playlist[0].overlay_text,campaign.slides[0].overlay_text);
  assert.equal(start.data.playlist[1].overlay_text,'');
  assert.equal((await request('/admin/api/ad-story-campaigns/'+id,'PUT',{...campaign,slides:[{...campaign.slides[0],overlay_text:'x'.repeat(301)}]})).status,400);
  assert.equal(start.data.playlist[0].button_label,buttons.button_label);
  assert.equal(start.data.playlist[0].target_url,campaign.target_url);
  const wa=new URL(start.data.playlist[0].whatsapp_url);
  assert.equal(wa.hostname,'wa.me');assert.equal(wa.pathname,'/5569999991234');
  assert.equal(wa.searchParams.get('text'),buttons.whatsapp_message);
  const token=start.data.token,hash=crypto.createHash('sha256').update(token).digest('hex');
  const row=()=>db.prepare('SELECT * FROM ad_view_sessions WHERE token_hash=?').get(hash);
  assert.match(service.validateAccess(row()),/Stories/);
  assert.equal((await request('/api/ads/profile','POST',{token},false)).status,409);
  assert.equal((await request('/api/ads/story-next','POST',{token,index:0},false)).status,425);
  db.prepare('UPDATE ad_story_runs SET started_at=? WHERE token_hash=?').run(Date.now()-6000,hash);
  r=await request('/api/ads/story-next','POST',{token,index:0},false);assert.equal(r.data.index,1);assert.equal(r.data.completed,false);
  // A duplicate request must not skip the next Story.
  r=await request('/api/ads/story-next','POST',{token,index:0},false);assert.equal(r.data.index,1);
  assert.equal((await request('/api/ads/story-next','POST',{token,index:1},false)).status,425);
  db.prepare('UPDATE ad_story_runs SET started_at=? WHERE token_hash=?').run(Date.now()-6000,hash);
  assert.equal((await request('/api/ads/story-next','POST',{token,index:1},false)).data.completed,true);
  assert.match(service.validateAccess(row()),/cadastro/);
  const profile={token,name:'Test Visitor',phone:'(11) 99999-0000',email:'test@example.com',survey:'Great',terms_accepted:true,marketing_consent:false};
  assert.equal((await request('/api/ads/profile','POST',{...profile,email:''},false)).status,400);
  assert.equal((await request('/api/ads/profile','POST',{...profile,terms_accepted:false},false)).status,400);
  assert.equal((await request('/api/ads/profile','POST',profile,false)).status,200);
  assert.equal(service.validateAccess(row()),null);
  assert.equal((await request('/api/ads/profile','POST',profile,false)).status,200);
  r=await request('/admin/api/ad-contacts?event_id=1');assert.equal(r.data.total,1);assert.equal(r.data.contacts[0].marketing_consent,0);
  assert.equal((await request('/admin/api/ad-contacts?event_id=3')).data.total,0);
  assert.equal((await request('/admin/api/ad-contacts?event_id=1','GET',undefined,false)).status,401);
  // Editing/reordering an album is atomic and applies to subsequent visits.
  assert.equal((await request('/admin/api/ad-story-campaigns/'+id,'PUT',{...campaign,slides:[campaign.slides[1],campaign.slides[0]]})).status,200);
  const disabled=await request('/api/ads/session','POST',{event_key:'ads',router_key:'router',mac:'02:00:00:00:00:02'},false);
  assert.equal(disabled.data.playlist[0].whatsapp_url,null);
  r=await request('/admin/api/ad-portals/1');assert.equal(r.data.campaigns[0].slides[0].image_path,campaign.slides[1].image_path);
  assert.equal((await request('/admin/api/ad-story-campaigns/'+id,'PUT',{...campaign,slides:[{image_path:'/invalid',duration:0}]})).status,400);
  assert.equal((await request('/admin/api/ad-portals/1')).data.campaigns[0].slides.length,2);
  // Lead-only: no campaign, no mandatory name/phone, configurable answers.
  db.exec("INSERT INTO routers VALUES(3,3,'lead-router','active')");
  const leadConfig={...config,logo_path:'/api/ad-images/advertiser.png',mode:'lead',fields:[{id:'opinion',label:'Sua opinião',type:'textarea',enabled:true,required:true},{id:'secret',label:'Oculto',type:'text',enabled:false,required:true}]};
  assert.equal((await request('/admin/api/ad-portals/3','PUT',leadConfig)).status,200);
  const lead=await request('/api/ads/session','POST',{event_key:'other',router_key:'lead-router',mac:'02:00:00:00:00:03'},false);
  assert.equal(lead.data.settings.logo_path,leadConfig.logo_path);
  assert.equal((await request('/admin/api/ad-portals/3','PUT',{...leadConfig,logo_path:'https://external.example/logo.png'})).status,400);
  assert.equal((await request('/admin/api/ad-portals/3','PUT',{...leadConfig,logo_path:''})).status,200);
  assert.equal((await request('/admin/api/ad-portals/3')).data.settings.logo_path,'');
  assert.equal(lead.status,200);assert.deepEqual(lead.data.playlist,[]);
  const leadBody={token:lead.data.token,terms_accepted:true,answers:{secret:'Ignored'}};
  assert.equal((await request('/api/ads/profile','POST',leadBody,false)).status,400);
  leadBody.answers.opinion='Gostei';
  assert.equal((await request('/api/ads/profile','POST',leadBody,false)).status,200);
  const leadContact=(await request('/admin/api/ad-contacts?event_id=3')).data.contacts[0];
  assert.equal(leadContact.phone,'');assert.deepEqual(leadContact.answers,[{id:'opinion',label:'Sua opinião',value:'Gostei'}]);
  // Satisfaction persists as a labelled answer and only accepts defined choices.
  const satisfaction={id:'rating',label:'Como você avalia nosso atendimento?',type:'satisfaction',enabled:true,required:true};
  assert.equal((await request('/admin/api/ad-portals/3','PUT',{...leadConfig,fields:[satisfaction]})).status,200);
  assert.equal((await request('/admin/api/ad-portals/3')).data.settings.fields[0].type,'satisfaction');
  const ratingRun=await request('/api/ads/session','POST',{event_key:'other',router_key:'lead-router',mac:'02:00:00:00:00:05'},false);
  const ratingBody={token:ratingRun.data.token,terms_accepted:true,answers:{rating:''}};
  assert.equal((await request('/api/ads/profile','POST',ratingBody,false)).status,400);
  ratingBody.answers.rating='Qualquer texto';
  assert.equal((await request('/api/ads/profile','POST',ratingBody,false)).status,400);
  for(const value of ['Muito insatisfeito','Insatisfeito','Neutro','Satisfeito','Muito satisfeito']){
    ratingBody.answers.rating=value;
    assert.equal((await request('/api/ads/profile','POST',ratingBody,false)).status,200);
  }
  const ratingContact=(await request('/admin/api/ad-contacts?event_id=3')).data.contacts.find(c=>c.answers.some(a=>a.id==='rating'));
  assert.deepEqual(ratingContact.answers,[{id:'rating',label:satisfaction.label,value:'Muito satisfeito'}]);
  // Phone-only still requires completed Stories but does not require the old name field.
  assert.equal((await request('/admin/api/ad-portals/1','PUT',{...config,mode:'ads_phone'})).status,200);
  const phoneRun=await request('/api/ads/session','POST',{event_key:'ads',router_key:'router',mac:'02:00:00:00:00:04'},false);
  const phoneHash=crypto.createHash('sha256').update(phoneRun.data.token).digest('hex');
  const phoneBody={token:phoneRun.data.token,terms_accepted:true,answers:{phone:'11999990000'}};
  assert.equal((await request('/api/ads/profile','POST',phoneBody,false)).status,409);
  db.prepare('UPDATE ad_story_runs SET completed=1 WHERE token_hash=?').run(phoneHash);
  assert.equal((await request('/api/ads/profile','POST',phoneBody,false)).status,200);
  assert.equal((await request('/admin/api/ad-portals/3','PUT',{...leadConfig,fields:[]})).status,400);
  // Legacy single-image campaigns remain visible without destructive migration.
  db.prepare('INSERT INTO ad_campaigns(event_id,name,image_path) VALUES(1,?,?)').run('Legacy','/api/ad-images/legacy.jpg');
  assert.equal((await request('/admin/api/ad-portals/1')).data.campaigns.find(c=>c.name==='Legacy').slides.length,1);
  assert.equal((await request('/admin/api/ad-story-campaigns/'+id,'DELETE')).status,200);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM ad_campaign_slides WHERE campaign_id=?').get(id).n,0);
  assert.equal((await request('/admin/api/ad-contacts?event_id=1')).data.total,2);
});
