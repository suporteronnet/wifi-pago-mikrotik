const crypto = require('crypto');

module.exports = function registerAdStories({app, db, adminAuth, requireRole, normalizeMac, adRouterHasClient}) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS ad_portal_settings (event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE, settings_json TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ad_story_settings (campaign_id INTEGER PRIMARY KEY REFERENCES ad_campaigns(id) ON DELETE CASCADE, duration INTEGER NOT NULL DEFAULT 8, position INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS ad_story_runs (token_hash TEXT PRIMARY KEY REFERENCES ad_view_sessions(token_hash) ON DELETE CASCADE, playlist TEXT NOT NULL, current_index INTEGER NOT NULL DEFAULT 0, started_at INTEGER NOT NULL, completed INTEGER NOT NULL DEFAULT 0, settings_json TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ad_contacts (id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, router_id INTEGER NOT NULL, mac TEXT NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT, city TEXT, survey_answer TEXT, marketing_consent INTEGER NOT NULL DEFAULT 0, terms_text TEXT NOT NULL, created_at TEXT NOT NULL, command_ref TEXT);
    CREATE INDEX IF NOT EXISTS ad_contacts_event ON ad_contacts(event_id, id);
  `);
  const defaults = {title:'Internet grátis', color:'#f97316', email:'hidden', city:'hidden', survey:'hidden', survey_question:'Como foi sua experiência?', terms:'Aceito os termos de uso desta rede Wi-Fi.', marketing_label:'Quero receber novidades e ofertas deste estabelecimento.'};
  function settings(eventId) {
    const row=db.prepare('SELECT settings_json FROM ad_portal_settings WHERE event_id=?').get(eventId);
    return {...defaults,...(row ? JSON.parse(row.settings_json) : {})};
  }
  function campaigns(eventId, active=true) {
    return db.prepare(`SELECT a.id,a.name,a.image_path,a.target_url,a.active,COALESCE(s.duration,8) AS duration,COALESCE(s.position,0) AS position
      FROM ad_campaigns a LEFT JOIN ad_story_settings s ON s.campaign_id=a.id
      WHERE (a.event_id=? OR EXISTS(SELECT 1 FROM ad_campaign_events x WHERE x.campaign_id=a.id AND x.event_id=?))
      ${active ? "AND a.active=1 AND (a.starts_at IS NULL OR a.starts_at='' OR a.starts_at<=?) AND (a.ends_at IS NULL OR a.ends_at='' OR a.ends_at>=?)" : ''}
      ORDER BY position,a.id LIMIT 20`).all(eventId,eventId,...(active ? [new Date().toISOString(),new Date().toISOString()] : []));
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
  app.get('/admin/api/ad-portals/:id',...admin,wrap((req,res)=>{
    const event=db.prepare("SELECT id,name FROM events WHERE id=? AND portal_mode='ads'").get(Number(req.params.id));
    if(!event)return fail(res,404,'Evento de anúncios não encontrado.');
    res.json({ok:true,event,settings:settings(event.id),campaigns:campaigns(event.id,false)});
  }));
  app.put('/admin/api/ad-portals/:id',...admin,wrap((req,res)=>{
    const id=Number(req.params.id);
    if(!db.prepare("SELECT id FROM events WHERE id=? AND portal_mode='ads'").get(id))return fail(res,404,'Evento de anúncios não encontrado.');
    const body=req.body||{}, result={...defaults};
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
    const config=JSON.parse(row.settings_json),body=req.body||{},name=String(body.name||'').trim(),phone=String(body.phone||'').replace(/\D/g,'');
    if(name.length<2||name.length>100||phone.length<10||phone.length>15)return fail(res,400,'Informe seu nome e telefone com DDD.');
    if(body.terms_accepted!==true)return fail(res,400,'Aceite os termos de uso para continuar.');
    const data={};
    for(const [key,max] of [['email',254],['city',100],['survey',1000]]) {
      data[key]=config[key]==='hidden' ? '' : String(body[key]||'').trim();
      if(data[key].length>max||(config[key]==='required'&&!data[key]))return fail(res,400,'Preencha os campos obrigatórios.');
    }
    if(data.email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email))return fail(res,400,'Informe um e-mail válido.');
    db.prepare(`INSERT INTO ad_contacts(token_hash,event_id,router_id,mac,name,phone,email,city,survey_answer,marketing_consent,terms_text,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(token_hash) DO UPDATE SET name=excluded.name,phone=excluded.phone,email=excluded.email,city=excluded.city,survey_answer=excluded.survey_answer,marketing_consent=excluded.marketing_consent`)
      .run(row.token_hash,row.event_id,row.router_id,row.mac,name,phone,data.email,data.city,data.survey,Number(body.marketing_consent===true),config.terms,new Date().toISOString());
    res.json({ok:true});
  }));
  return {
    start:wrap((req,res)=>{
      const body=req.body||{},mac=normalizeMac(body.mac);
      const event=db.prepare("SELECT id FROM events WHERE event_key=? AND portal_mode='ads' AND status='active'").get(String(body.event_key||''));
      if(!event||!mac)return fail(res,400,'Conecte-se ao Wi-Fi de um evento de anúncios.');
      const router=db.prepare("SELECT id FROM routers WHERE event_id=? AND router_key=? AND status='active'").get(event.id,String(body.router_key||''));
      if(!router)return fail(res,404,'MikroTik não encontrada.');
      if(!adRouterHasClient(router.id,mac))return fail(res,409,'Aguardando a MikroTik identificar este aparelho.');
      const playlist=campaigns(event.id);if(!playlist.length)return fail(res,404,'Nenhum anúncio ativo neste evento.');
      const token=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(token).digest('hex'),config=settings(event.id),now=new Date().toISOString();
      db.transaction(()=>{
        db.prepare('DELETE FROM ad_story_runs WHERE token_hash IN (SELECT token_hash FROM ad_view_sessions WHERE expires_at<?)').run(now);
        // Contatos permanecem disponíveis mesmo depois do fim da sessão.
        db.prepare('INSERT INTO ad_view_sessions(token_hash,event_id,router_id,campaign_id,mac,created_at,expires_at) VALUES (?,?,?,?,?,?,?)').run(hash,event.id,router.id,playlist[0].id,mac,now,new Date(Date.now()+60*60000).toISOString());
        db.prepare('INSERT INTO ad_story_runs(token_hash,playlist,started_at,settings_json) VALUES (?,?,?,?)').run(hash,JSON.stringify(playlist),Date.now(),JSON.stringify(config));
        db.prepare('UPDATE ad_campaigns SET impressions=impressions+1 WHERE id=?').run(playlist[0].id);
      })();
      res.json({ok:true,token,playlist,settings:config,view_seconds:playlist[0].duration});
    }),
    validateAccess(session) {
      const run=db.prepare('SELECT completed FROM ad_story_runs WHERE token_hash=?').get(session.token_hash);
      if(!run?.completed)return 'Conclua os Stories antes de liberar o acesso. Atualize o portal se necessário.';
      if(!db.prepare('SELECT id FROM ad_contacts WHERE token_hash=?').get(session.token_hash))return 'Preencha o cadastro antes de liberar o acesso.';
      return null;
    }
  };
};
