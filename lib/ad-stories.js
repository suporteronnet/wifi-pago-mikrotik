const crypto = require('crypto');

module.exports = function registerAdStories({app, db, adminAuth, requireRole, normalizeMac, adRouterHasClient}) {
  // Pesquisas independentes não precisam de uma campanha artificial.
  const sessionSchema=db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='ad_view_sessions'").get()?.sql;
  if(sessionSchema&&/campaign_id\s+INTEGER\s+NOT NULL/i.test(sessionSchema)){
    const indexes=db.prepare("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='ad_view_sessions' AND sql IS NOT NULL").all();
    const foreignKeys=db.pragma('foreign_keys',{simple:true});db.pragma('foreign_keys = OFF');
    try{db.transaction(()=>{
      db.exec(sessionSchema.replace(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?ad_view_sessions/i,'CREATE TABLE ad_view_sessions_new').replace(/campaign_id\s+INTEGER\s+NOT NULL/i,'campaign_id INTEGER'));
      db.exec('INSERT INTO ad_view_sessions_new SELECT * FROM ad_view_sessions; DROP TABLE ad_view_sessions; ALTER TABLE ad_view_sessions_new RENAME TO ad_view_sessions;');
      indexes.forEach(index=>db.exec(index.sql));
    })();}finally{db.pragma('foreign_keys = '+Number(foreignKeys));}
  }
  db.exec(`
    CREATE TABLE IF NOT EXISTS ad_contact_answers(token_hash TEXT PRIMARY KEY,answers_json TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ad_campaign_buttons (campaign_id INTEGER PRIMARY KEY REFERENCES ad_campaigns(id) ON DELETE CASCADE, label TEXT NOT NULL DEFAULT 'Me interessa', whatsapp_enabled INTEGER NOT NULL DEFAULT 0, whatsapp_phone TEXT NOT NULL DEFAULT '', whatsapp_message TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS ad_portal_settings (event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE, settings_json TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ad_story_settings (campaign_id INTEGER PRIMARY KEY REFERENCES ad_campaigns(id) ON DELETE CASCADE, duration INTEGER NOT NULL DEFAULT 8, position INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS ad_campaign_slides (id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES ad_campaigns(id) ON DELETE CASCADE, image_path TEXT NOT NULL, duration INTEGER NOT NULL DEFAULT 8, position INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS ad_campaign_slides_order ON ad_campaign_slides(campaign_id,position);
    CREATE TABLE IF NOT EXISTS ad_story_runs (token_hash TEXT PRIMARY KEY REFERENCES ad_view_sessions(token_hash) ON DELETE CASCADE, playlist TEXT NOT NULL, current_index INTEGER NOT NULL DEFAULT 0, started_at INTEGER NOT NULL, completed INTEGER NOT NULL DEFAULT 0, settings_json TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ad_contacts (id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, router_id INTEGER NOT NULL, mac TEXT NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT, city TEXT, survey_answer TEXT, marketing_consent INTEGER NOT NULL DEFAULT 0, terms_text TEXT NOT NULL, created_at TEXT NOT NULL, command_ref TEXT);
    CREATE INDEX IF NOT EXISTS ad_contacts_event ON ad_contacts(event_id, id);
  `);
  if(!db.pragma('table_info(ad_campaign_slides)').some(c=>c.name==='overlay_text'))db.exec("ALTER TABLE ad_campaign_slides ADD COLUMN overlay_text TEXT NOT NULL DEFAULT ''");
  const defaults = {title:'Internet grátis', color:'#f97316', email:'hidden', city:'hidden', survey:'hidden', survey_question:'Como foi sua experiência?', terms:'Aceito os termos de uso desta rede Wi-Fi.', marketing_label:'Quero receber novidades e ofertas deste estabelecimento.'};
  function settings(eventId) {
    const row=db.prepare('SELECT settings_json FROM ad_portal_settings WHERE event_id=?').get(eventId);
    const config={...defaults,mode:'lead_ads',...(row ? JSON.parse(row.settings_json) : {})};
    config.fields=config.fields||fields({...config,mode:'lead_ads'});return config;
  }
  function fields(config){
    if(config.mode==='ads_phone')return [{id:'phone',label:'WhatsApp com DDD',type:'tel',enabled:true,required:true}];
    return config.fields||[
      {id:'name',label:'Seu nome',type:'text',enabled:true,required:true},
      {id:'phone',label:'WhatsApp / telefone',type:'tel',enabled:true,required:true},
      ...['email','city','survey'].map(id=>({id,label:id==='email'?'E-mail':id==='city'?'Cidade':config.survey_question,type:id==='email'?'email':id==='survey'?'textarea':'text',enabled:config[id]!=='hidden',required:config[id]==='required'}))
    ];
  }
  function campaigns(eventId, active=true) {
    return db.prepare(`SELECT a.id,a.name,a.image_path,a.target_url,a.active,a.starts_at,a.ends_at,COALESCE(s.duration,8) AS duration,COALESCE(s.position,0) AS position
      FROM ad_campaigns a LEFT JOIN ad_story_settings s ON s.campaign_id=a.id
      WHERE (a.event_id=? OR EXISTS(SELECT 1 FROM ad_campaign_events x WHERE x.campaign_id=a.id AND x.event_id=?))
      ${active ? "AND a.active=1 AND (a.starts_at IS NULL OR a.starts_at='' OR a.starts_at<=?) AND (a.ends_at IS NULL OR a.ends_at='' OR a.ends_at>=?)" : ''}
      ORDER BY position,a.id`).all(eventId,eventId,...(active ? [new Date().toISOString(),new Date().toISOString()] : [])).map(c=>{
        const slides=db.prepare('SELECT id,image_path,duration,position,overlay_text FROM ad_campaign_slides WHERE campaign_id=? ORDER BY position,id').all(c.id);
        const buttons=db.prepare('SELECT label AS button_label,whatsapp_enabled,whatsapp_phone,whatsapp_message FROM ad_campaign_buttons WHERE campaign_id=?').get(c.id)||{button_label:'Me interessa',whatsapp_enabled:0,whatsapp_phone:'',whatsapp_message:''};
        return {...c,...buttons,slides:slides.length ? slides : [{id:null,image_path:c.image_path,duration:c.duration,position:0}]};
      });
  }
  const wrap=fn=>(req,res)=>{try{return fn(req,res);}catch(error){console.error('Stories:',error.message);return res.status(500).json({ok:false,error:'Não foi possível concluir a operação.'});}};
  const fail=(res,code,error)=>res.status(code).json({ok:false,error});
  function session(req,res) {
    const token=String(req.body?.token||'');
    if(!/^[a-f0-9]{64}$/.test(token)){fail(res,400,'Sessão inválida. Abra o portal novamente.');return null;}
    const hash=crypto.createHash('sha256').update(token).digest('hex');
    const row=db.prepare('SELECT v.*,r.playlist,r.current_index,r.started_at,r.completed,r.settings_json FROM ad_view_sessions v JOIN ad_story_runs r USING(token_hash) WHERE v.token_hash=?').get(hash);
    if(!row||Date.parse(row.expires_at)<=Date.now()){fail(res,410,'Sessão expirada. Abra o portal novamente.');return null;}
    return row;
  }
  const admin=[adminAuth,requireRole('admin')];
  function campaignBody(body,res){
    const button_label=String(body.button_label??'Me interessa').trim();
    const whatsapp_enabled=body.whatsapp_enabled===true;
    const rawPhone=String(body.whatsapp_phone||'').trim();
    const whatsapp_phone=rawPhone.replace(/[+\s().-]/g,'');
    const whatsapp_message=String(body.whatsapp_message||'').trim();
    if(!button_label||button_label.length>32){fail(res,400,'O texto do botão deve ter de 1 a 32 caracteres.');return null;}
    if((whatsapp_enabled&&!whatsapp_phone)||(whatsapp_phone&&!/^[1-9][0-9]{9,14}$/.test(whatsapp_phone))){fail(res,400,'Informe o WhatsApp com código do país e DDD, por exemplo: 5569999999999.');return null;}
    if(whatsapp_message.length>1000){fail(res,400,'A mensagem do WhatsApp deve ter até 1000 caracteres.');return null;}
    const name=String(body.name||'').trim(),target=String(body.target_url||'').trim(),position=Number(body.position||0);
    if(!name||name.length>100||!Number.isInteger(position)||position<0||position>999){fail(res,400,'Informe o nome e uma ordem entre 0 e 999.');return null;}
    if(target){try{if(!['http:','https:'].includes(new URL(target).protocol))throw Error();}catch{fail(res,400,'O link deve começar com https:// ou http://.');return null;}}
    if(!Array.isArray(body.slides)||body.slides.length<1||body.slides.length>20){fail(res,400,'Selecione de 1 a 20 imagens por campanha.');return null;}
    const slides=[];
    for(const slide of body.slides){
      const image=String(slide.image_path||''),duration=Number(slide.duration);
      let valid=/^\/api\/ad-images\/[a-zA-Z0-9-]+\.(jpg|jpeg|png|webp)$/.test(image);
      if(!valid){try{valid=['http:','https:'].includes(new URL(image).protocol);}catch{}}
      if(!valid||!Number.isInteger(duration)||duration<3||duration>30){fail(res,400,'Envie imagens válidas e informe duração de 3 a 30 segundos.');return null;}
      const overlay_text=String(slide.overlay_text||'').trim();
      if(overlay_text.length>300){fail(res,400,'Use até 300 caracteres no texto do Story.');return null;}
      slides.push({image_path:image,duration,overlay_text});
    }
    const dates={};
    for(const key of ['starts_at','ends_at']){
      dates[key]=body[key] ? new Date(body[key]) : null;
      if(dates[key]&&!Number.isFinite(dates[key].getTime())){fail(res,400,'Data inválida.');return null;}
    }
    if(dates.starts_at&&dates.ends_at&&dates.starts_at>=dates.ends_at){fail(res,400,'O fim precisa ser posterior ao início.');return null;}
    return {name,target,position,slides,button_label,whatsapp_enabled,whatsapp_phone,whatsapp_message,active:body.active===false?0:1,starts_at:dates.starts_at?.toISOString()||null,ends_at:dates.ends_at?.toISOString()||null};
  }
  function saveSlides(id,data){
    db.prepare('INSERT INTO ad_campaign_buttons(campaign_id,label,whatsapp_enabled,whatsapp_phone,whatsapp_message) VALUES (?,?,?,?,?) ON CONFLICT(campaign_id) DO UPDATE SET label=excluded.label,whatsapp_enabled=excluded.whatsapp_enabled,whatsapp_phone=excluded.whatsapp_phone,whatsapp_message=excluded.whatsapp_message').run(id,data.button_label,Number(data.whatsapp_enabled),data.whatsapp_phone,data.whatsapp_message);
    db.prepare('DELETE FROM ad_campaign_slides WHERE campaign_id=?').run(id);
    const insert=db.prepare('INSERT INTO ad_campaign_slides(campaign_id,image_path,duration,position,overlay_text) VALUES (?,?,?,?,?)');
    data.slides.forEach((s,i)=>insert.run(id,s.image_path,s.duration,i,s.overlay_text));
    db.prepare('INSERT INTO ad_story_settings VALUES (?,?,?) ON CONFLICT(campaign_id) DO UPDATE SET duration=excluded.duration,position=excluded.position').run(id,data.slides[0].duration,data.position);
  }
  app.post('/admin/api/ad-story-campaigns',...admin,wrap((req,res)=>{
    const eventId=Number(req.body?.event_id);
    if(!db.prepare("SELECT id FROM events WHERE id=? AND portal_mode='ads'").get(eventId))return fail(res,400,'Selecione um evento de anúncios.');
    const data=campaignBody(req.body,res);if(!data)return;
    const id=db.transaction(()=>{
      const now=new Date().toISOString();
      const result=db.prepare('INSERT INTO ad_campaigns(event_id,name,image_path,target_url,active,starts_at,ends_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)').run(eventId,data.name,data.slides[0].image_path,data.target,data.active,data.starts_at,data.ends_at,now,now);
      saveSlides(result.lastInsertRowid,data);return Number(result.lastInsertRowid);
    })();
    res.status(201).json({ok:true,id});
  }));
  app.delete('/admin/api/ad-story-campaigns/:id',...admin,wrap((req,res)=>{
    const id=Number(req.params.id);
    db.transaction(()=>{db.prepare('DELETE FROM ad_campaign_slides WHERE campaign_id=?').run(id);db.prepare('DELETE FROM ad_story_settings WHERE campaign_id=?').run(id);db.prepare('DELETE FROM ad_campaign_events WHERE campaign_id=?').run(id);db.prepare('DELETE FROM ad_campaigns WHERE id=?').run(id);})();
    res.json({ok:true});
  }));
  app.get('/admin/api/ad-portals/:id',...admin,wrap((req,res)=>{
    const event=db.prepare("SELECT id,name FROM events WHERE id=? AND portal_mode='ads'").get(Number(req.params.id));
    if(!event)return fail(res,404,'Evento de anúncios não encontrado.');
    res.json({ok:true,event,settings:settings(event.id),campaigns:campaigns(event.id,false)});
  }));
  app.put('/admin/api/ad-portals/:id',...admin,wrap((req,res)=>{
    const id=Number(req.params.id);
    if(!db.prepare("SELECT id FROM events WHERE id=? AND portal_mode='ads'").get(id))return fail(res,404,'Evento de anúncios não encontrado.');
    const body=req.body||{}, result={...defaults};
    result.mode=body.mode||'lead_ads';
    if(!['ads_phone','lead','lead_ads'].includes(result.mode))return fail(res,400,'Modo de portal inválido.');
    if(body.fields!==undefined){
      if(!Array.isArray(body.fields)||body.fields.length>15)return fail(res,400,'Use até 15 campos.');
      const ids=new Set();result.fields=[];
      for(const f of body.fields){
        if(!f||!/^([a-z][a-z0-9_]{0,39})$/.test(f.id)||ids.has(f.id)||!['text','tel','email','textarea','satisfaction'].includes(f.type)||!String(f.label||'').trim()||String(f.label).length>120)return fail(res,400,'Revise os títulos e tipos dos campos.');
        ids.add(f.id);result.fields.push({id:f.id,label:String(f.label).trim(),type:f.type,enabled:f.enabled===true,required:f.required===true});
      }
      if(result.mode!=='ads_phone'&&!result.fields.some(f=>f.enabled))return fail(res,400,'Ative pelo menos um campo da pesquisa.');
    }
    for(const key of ['email','city','survey']) {
      if(!['hidden','optional','required'].includes(body[key]))return fail(res,400,'Opção de cadastro inválida.');
      result[key]=body[key];
    }
    if(!/^#[a-f0-9]{6}$/i.test(body.color||''))return fail(res,400,'Cor inválida.');
    result.color=body.color;
    for(const [key,max] of [['title',80],['survey_question',180],['terms',2000],['marketing_label',250]]) {
      result[key]=String(body[key]||'').trim();
      if(!result[key]||result[key].length>max)return fail(res,400,'Preencha os textos dentro dos limites indicados.');
    }
    db.prepare('INSERT INTO ad_portal_settings VALUES (?,?) ON CONFLICT(event_id) DO UPDATE SET settings_json=excluded.settings_json').run(id,JSON.stringify(result));
    res.json({ok:true});
  }));
  app.put('/admin/api/ad-story-campaigns/:id',...admin,wrap((req,res)=>{
    if(req.body?.slides){
      const data=campaignBody(req.body,res);if(!data)return;
      const id=Number(req.params.id);
      if(!db.prepare('SELECT id FROM ad_campaigns WHERE id=?').get(id))return fail(res,404,'Campanha não encontrada.');
      db.transaction(()=>{db.prepare('UPDATE ad_campaigns SET name=?,image_path=?,target_url=?,active=?,starts_at=?,ends_at=?,updated_at=? WHERE id=?').run(data.name,data.slides[0].image_path,data.target,data.active,data.starts_at,data.ends_at,new Date().toISOString(),id);saveSlides(id,data);})();
      return res.json({ok:true});
    }
    const id=Number(req.params.id),duration=Number(req.body?.duration),position=Number(req.body?.position);
    if(!Number.isInteger(duration)||duration<3||duration>30||!Number.isInteger(position)||position<0||position>999)return fail(res,400,'Duração: 3 a 30 segundos. Ordem: 0 a 999.');
    if(!db.prepare('SELECT id FROM ad_campaigns WHERE id=?').get(id))return fail(res,404,'Campanha não encontrada.');
    db.prepare('INSERT INTO ad_story_settings VALUES (?,?,?) ON CONFLICT(campaign_id) DO UPDATE SET duration=excluded.duration,position=excluded.position').run(id,duration,position);
    res.json({ok:true});
  }));
  app.get('/admin/api/ad-contacts',...admin,wrap((req,res)=>{
    const eventId=Number(req.query.event_id),page=Math.max(1,Math.floor(Number(req.query.page)||1));
    if(!db.prepare("SELECT id FROM events WHERE id=? AND portal_mode='ads'").get(eventId))return fail(res,404,'Evento de anúncios não encontrado.');
    const contacts=db.prepare(`SELECT c.id,c.name,c.phone,c.email,c.city,c.survey_answer,c.marketing_consent,c.created_at,a.status AS access_status FROM ad_contacts c
      LEFT JOIN admin_commands a ON a.command_ref=c.command_ref
      WHERE c.event_id=? ORDER BY c.id DESC LIMIT 50 OFFSET ?`).all(eventId,(page-1)*50);
    contacts.forEach(c=>{const row=db.prepare('SELECT answers_json FROM ad_contact_answers WHERE token_hash=(SELECT token_hash FROM ad_contacts WHERE id=?)').get(c.id);c.answers=row?JSON.parse(row.answers_json):[];});
    res.set('Cache-Control','no-store').json({ok:true,contacts,page,total:db.prepare('SELECT COUNT(*) AS n FROM ad_contacts WHERE event_id=?').get(eventId).n});
  }));
  app.post('/api/ads/story-next',wrap((req,res)=>{
    const row=session(req,res);if(!row)return;
    const playlist=JSON.parse(row.playlist);
    if(row.completed)return res.json({ok:true,completed:true,index:playlist.length});
    const requested=Number(req.body?.index);
    if(requested!==row.current_index)return res.json({ok:true,completed:false,index:row.current_index});
    const wait=Math.ceil((row.started_at+playlist[row.current_index].duration*1000-Date.now())/1000);
    if(wait>0)return res.status(425).json({ok:false,error:'Aguarde este anúncio terminar.',retry_after:wait});
    const next=row.current_index+1,completed=next>=playlist.length;
    db.prepare('UPDATE ad_story_runs SET current_index=?,started_at=?,completed=? WHERE token_hash=?').run(next,Date.now(),Number(completed),row.token_hash);
    if(!completed)db.prepare('UPDATE ad_campaigns SET impressions=impressions+1 WHERE id=?').run(playlist[next].id);
    res.json({ok:true,index:next,completed});
  }));
  app.post('/api/ads/profile',wrap((req,res)=>{
    const row=session(req,res);if(!row)return;
    if(!row.completed)return fail(res,409,'Conclua os Stories antes do cadastro.');
    const config=JSON.parse(row.settings_json),body=req.body||{},values={},answers=[];
    for(const f of fields(config).filter(f=>f.enabled)){
      let value=String(body.answers?.[f.id]??body[f.id]??'').trim();
      if(f.type==='tel')value=value.replace(/\D/g,'');
      if((f.required&&!value)||value.length>(f.type==='textarea'?1000:254)||(value&&f.type==='tel'&&!/^\d{10,15}$/.test(value))||(value&&f.type==='email'&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)))return fail(res,400,'Revise o campo: '+f.label);
      if(value&&f.type==='satisfaction'&&!['Muito insatisfeito','Insatisfeito','Neutro','Satisfeito','Muito satisfeito'].includes(value))return fail(res,400,'Revise o campo: '+f.label);
      values[f.id]=value;answers.push({id:f.id,label:f.label,value});
    }
    const name=values.name||'Visitante',phone=values.phone||'';
    if(body.terms_accepted!==true)return fail(res,400,'Aceite os termos de uso para continuar.');
    const data={email:values.email||'',city:values.city||'',survey:values.survey||''};
    if(data.email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email))return fail(res,400,'Informe um e-mail válido.');
    db.prepare(`INSERT INTO ad_contacts(token_hash,event_id,router_id,mac,name,phone,email,city,survey_answer,marketing_consent,terms_text,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(token_hash) DO UPDATE SET name=excluded.name,phone=excluded.phone,email=excluded.email,city=excluded.city,survey_answer=excluded.survey_answer,marketing_consent=excluded.marketing_consent`)
      .run(row.token_hash,row.event_id,row.router_id,row.mac,name,phone,data.email,data.city,data.survey,Number(body.marketing_consent===true),config.terms,new Date().toISOString());
    db.prepare('INSERT INTO ad_contact_answers VALUES (?,?) ON CONFLICT(token_hash) DO UPDATE SET answers_json=excluded.answers_json').run(row.token_hash,JSON.stringify(answers));
    res.json({ok:true});
  }));
  return {
    start:wrap((req,res)=>{
      const body=req.body||{},mac=normalizeMac(body.mac);
      const event=db.prepare("SELECT id FROM events WHERE event_key=? AND portal_mode='ads' AND status='active'").get(String(body.event_key||''));
      if(!event||!mac)return fail(res,400,'Conecte-se ao Wi-Fi de um evento de anúncios.');
      const router=db.prepare("SELECT id FROM routers WHERE event_id=? AND router_key=? AND status='active'").get(event.id,String(body.router_key||''));
      if(!router)return fail(res,404,'MikroTik não encontrada.');
      // Os anúncios podem carregar enquanto o relatório de presença chega.
      // A confirmação do aparelho continua obrigatória em /api/ads/access.
      const config=settings(event.id);
      const playlist=config.mode==='lead'?[]:campaigns(event.id).flatMap(c=>c.slides.map(s=>({id:c.id,slide_id:s.id,name:c.name,target_url:c.target_url,button_label:c.button_label,whatsapp_url:c.whatsapp_enabled?`https://wa.me/${c.whatsapp_phone}?text=${encodeURIComponent(c.whatsapp_message)}`:null,image_path:s.image_path,duration:s.duration,overlay_text:s.overlay_text||''})));
      if(!playlist.length&&config.mode!=='lead')return fail(res,404,'Nenhum anúncio ativo neste evento.');
      if(playlist.length>60)return fail(res,409,'Este evento ultrapassou 60 Stories ativos. Avise o responsável pelo Wi-Fi.');
      const token=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(token).digest('hex'),now=new Date().toISOString();
      db.transaction(()=>{
        db.prepare('DELETE FROM ad_story_runs WHERE token_hash IN (SELECT token_hash FROM ad_view_sessions WHERE expires_at<?)').run(now);
        // Contatos permanecem disponíveis mesmo depois do fim da sessão.
        db.prepare('INSERT INTO ad_view_sessions(token_hash,event_id,router_id,campaign_id,mac,created_at,expires_at) VALUES (?,?,?,?,?,?,?)').run(hash,event.id,router.id,playlist[0]?.id||null,mac,now,new Date(Date.now()+60*60000).toISOString());
        db.prepare('INSERT INTO ad_story_runs(token_hash,playlist,started_at,settings_json) VALUES (?,?,?,?)').run(hash,JSON.stringify(playlist),Date.now(),JSON.stringify(config));
        if(config.mode==='lead')db.prepare('UPDATE ad_story_runs SET completed=1 WHERE token_hash=?').run(hash);
        else db.prepare('UPDATE ad_campaigns SET impressions=impressions+1 WHERE id=?').run(playlist[0].id);
      })();
      res.json({ok:true,token,playlist,settings:config,view_seconds:playlist[0]?.duration||0});
    }),
    validateAccess(session) {
      const run=db.prepare('SELECT completed FROM ad_story_runs WHERE token_hash=?').get(session.token_hash);
      if(!run?.completed)return 'Conclua os Stories antes de liberar o acesso. Atualize o portal se necessário.';
      if(!db.prepare('SELECT id FROM ad_contacts WHERE token_hash=?').get(session.token_hash))return 'Preencha o cadastro antes de liberar o acesso.';
      return null;
    }
  };
};
