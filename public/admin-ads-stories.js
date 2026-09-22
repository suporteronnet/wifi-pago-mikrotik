(() => {
  'use strict';
  const host=document.getElementById('banners');if(!host)return;
  const stylesheet=document.createElement('link');stylesheet.rel='stylesheet';stylesheet.href='/admin-ads-stories.css?v=20260922-contacts';document.head.append(stylesheet);
  const section=document.createElement('section');section.className='portal-config-console';
  section.innerHTML=`<header class="portal-config-heading"><div><span>HOTSPOT ANÚNCIOS</span><h2>Seu portal, do seu jeito</h2><p>Configure o cadastro, monte os Stories e acompanhe os visitantes.</p></div></header>
    <div class="portal-config-event"><label>Evento de anúncios<select id="adPortalEvent"><option value="">Selecione um evento</option></select></label><button type="button" id="adRefreshEvents">Atualizar eventos</button></div>
    <div id="adPortalMessage" role="status" aria-live="polite"></div>
    <div id="adPortalContent" hidden>
      <nav class="portal-config-tabs" aria-label="Configurações de anúncios"><button type="button" data-tab="appearance" class="selected">1. Portal e cadastro</button><button type="button" data-tab="campaigns">2. Campanhas e imagens</button><button type="button" data-tab="contacts">3. Cadastros recebidos</button></nav>
      <section data-pane="appearance" class="portal-config-box"><h3>Portal e cadastro</h3><form id="adPortalForm"><div class="portal-config-grid">
        <label>Título do portal<input name="title" maxlength="80" required></label><label>Cor principal<input name="color" type="color" required></label>
        <label>E-mail<select name="email"><option value="hidden">Não solicitar</option><option value="optional">Opcional</option><option value="required">Obrigatório</option></select></label>
        <label>Cidade<select name="city"><option value="hidden">Não solicitar</option><option value="optional">Opcional</option><option value="required">Obrigatório</option></select></label>
        <label>Pesquisa<select name="survey"><option value="hidden">Não solicitar</option><option value="optional">Opcional</option><option value="required">Obrigatória</option></select></label>
        <label>Pergunta da pesquisa<input name="survey_question" maxlength="180" required></label></div>
        <p>Nome e telefone são obrigatórios. Receber ofertas é uma escolha do visitante.</p>
        <label>Termos de uso apresentados ao visitante<textarea name="terms" maxlength="2000" rows="4" required></textarea></label>
        <label>Texto da autorização para receber ofertas<input name="marketing_label" maxlength="250" required></label>
        <div class="portal-config-actions"><button class="primary" type="submit">Salvar portal e cadastro</button><span id="adSettingsFeedback" role="status"></span></div>
      </form></section>
      <section data-pane="campaigns" hidden><div class="portal-config-box"><div class="portal-config-row"><div><h3>Campanhas e imagens</h3><p>Cada campanha pode ter até 20 imagens. A ordem das campanhas e das imagens define a sequência dos Stories.</p></div><button id="adNewCampaign" type="button" class="primary">+ Nova campanha</button></div><div id="adCampaignList"></div></div>
        <section id="adCampaignEditor" class="portal-config-box" hidden><h3 id="adCampaignEditorTitle">Nova campanha</h3><form id="adCampaignForm"><div class="portal-config-grid">
          <label>Nome da campanha<input name="name" maxlength="100" required></label><label>Link do anunciante (opcional)<input name="target_url" type="url" placeholder="https://..."></label>
          <label>Texto do botão do anunciante<input name="button_label" maxlength="32" value="Me interessa" required></label>
          <label>Botão flutuante do WhatsApp<select name="whatsapp_enabled"><option value="false">Desativado</option><option value="true">Ativado</option></select></label>
          <label>Número do WhatsApp (país + DDD)<input name="whatsapp_phone" type="tel" maxlength="25" placeholder="55 69 99999-9999"></label>
          <label>Mensagem ao abrir o WhatsApp<textarea name="whatsapp_message" maxlength="1000" rows="2" placeholder="Olá! Vi seu anúncio no WI-FI TOTAL."></textarea></label>
          <label>Ordem da campanha<input name="position" type="number" min="0" max="999" value="0" required></label><label>Situação<select name="active"><option value="true">Ativa</option><option value="false">Inativa</option></select></label>
          <label>Início (opcional)<input name="starts_at" type="datetime-local"></label><label>Fim (opcional)<input name="ends_at" type="datetime-local"></label>
        </div><div class="portal-config-upload"><label>Selecionar imagens — pode escolher várias de uma vez<input id="adCampaignFiles" type="file" accept="image/jpeg,image/png,image/webp" multiple></label><p>JPG, PNG ou WebP, até 900 KB por imagem. Para Stories, prefira imagens verticais. As imagens existentes continuam disponíveis para edição.</p></div>
        <div id="adSlideList" class="portal-config-slide-grid"></div><p id="adSlideCount"></p><div id="adCampaignFeedback" role="status"></div>
        <div class="portal-config-actions"><button type="submit" class="primary" id="adSaveCampaign">Salvar campanha e imagens</button><button type="button" id="adCancelCampaign">Cancelar</button></div></form></section>
      </section>
      <section data-pane="contacts" class="portal-config-box" hidden><div class="portal-config-row"><h3>Cadastros deste evento</h3><button id="adRefreshContacts" type="button">Atualizar cadastros</button></div><div class="portal-config-table" id="adContacts"></div><div class="portal-config-actions"><button id="adContactsPrev" type="button">Anterior</button><span id="adContactsPage"></span><button id="adContactsNext" type="button">Próxima</button></div></section>
    </div>`;
  host.replaceChildren(section);
  const $=id=>document.getElementById(id),escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let eventId=0,page=1,campaigns=[],editingId=null,slides=[],saving=false,dirty=false;
  let contactRows=[];
  const contactDialog=document.createElement('dialog');
  contactDialog.className='portal-contact-dialog';contactDialog.setAttribute('aria-labelledby','portalContactTitle');
  document.body.append(contactDialog);
  contactDialog.addEventListener('click',event=>{if(event.target===contactDialog||event.target.closest('[data-close-contact]'))contactDialog.close();});
  function whatsappLink(phone){
    let digits=String(phone||'').replace(/\D/g,'');
    if(digits.length===10||digits.length===11)digits='55'+digits;
    return /^[1-9][0-9]{11,14}$/.test(digits)?'https://wa.me/'+digits:null;
  }
  function accessLabel(status){return ({applied:'Liberação confirmada',pending:'Aguardando MikroTik',expired:'Acesso encerrado',failed:'Falha na liberação',cancelled:'Cancelado'})[status]||'Cadastro recebido';}
  function showContact(id){
    const c=contactRows.find(row=>Number(row.id)===id);if(!c)return;
    const link=whatsappLink(c.phone);
    const field=(label,value)=>`<div class="portal-contact-field"><span>${label}</span><strong>${escape(value||'Não informado')}</strong></div>`;
    contactDialog.innerHTML=`<header><h2 id="portalContactTitle">Dados do visitante</h2><button type="button" data-close-contact aria-label="Fechar dados do visitante">×</button></header><div class="portal-contact-body"><div class="portal-contact-grid">${field('Nome',c.name)}<div class="portal-contact-field"><span>Telefone / WhatsApp</span><strong>${escape(c.phone)}</strong>${link?`<a class="portal-contact-whatsapp" href="${link}" target="_blank" rel="noopener noreferrer">Abrir WhatsApp ↗</a>`:'<small>Número incompleto. Não foi possível montar o link do WhatsApp.</small>'}</div>${field('E-mail',c.email)}${field('Cidade',c.city)}${field('Cadastro recebido',new Date(c.created_at).toLocaleString('pt-BR'))}${field('Situação da liberação',accessLabel(c.access_status))}</div><h3>Cadastro no Hotspot Anúncios</h3><div class="portal-contact-field">${field('Evento',$('adPortalEvent').selectedOptions[0]?.textContent)}${field('Resposta à pesquisa',c.survey_answer)}${field('Autorização para receber ofertas',c.marketing_consent?'Autorizou':'Não autorizou')}</div></div>`;
    contactDialog.showModal();
  }
  const report=(text,error=false,id='adPortalMessage')=>{$(id).textContent=text;$(id).classList.toggle('error',error);};
  async function request(path,options={}){const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),20000);try{const response=await fetch(path,{cache:'no-store',...options,signal:controller.signal});const data=await response.json();if(!response.ok||data.ok===false)throw new Error(data.error||'Não foi possível concluir a operação.');return data;}finally{clearTimeout(timeout);}}
  const json=(method,body)=>({method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  function tab(name){
    const panes=Array.from(section.querySelectorAll('[data-pane]'));
    if(!panes.some(p=>p.dataset.pane===name))return;
    section.querySelectorAll('[data-tab]').forEach(b=>{
      const selected=b.dataset.tab===name;
      b.classList.toggle('selected',selected);
      b.setAttribute('aria-selected',String(selected));
    });
    panes.forEach(p=>{
      const selected=p.dataset.pane===name;
      p.hidden=!selected;
      p.style.display=selected?'block':'none';
    });
    if(name==='contacts')contacts();
  }
  function localDate(value){if(!value)return '';const d=new Date(value);if(!Number.isFinite(d.getTime()))return '';const pad=n=>String(n).padStart(2,'0');return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;}
  function discard(){slides.forEach(s=>{if(s.preview)URL.revokeObjectURL(s.preview);});slides=[];editingId=null;dirty=false;$('adCampaignEditor').hidden=true;}
  function renderCampaigns(){
    $('adCampaignList').innerHTML=campaigns.length?campaigns.map(c=>`<article class="portal-config-campaign"><div class="portal-config-thumbs">${c.slides.slice(0,4).map(s=>`<img src="${escape(s.image_path)}" alt="">`).join('')}</div><div class="portal-config-campaign-info"><h4>${escape(c.name)}</h4><p>${c.slides.length} imagem(ns) • ${c.slides.reduce((sum,s)=>sum+s.duration,0)} segundos • Ordem ${c.position}</p><span class="portal-config-badge">${c.active?'Ativa':'Inativa'}${c.starts_at?' • Início '+escape(new Date(c.starts_at).toLocaleString('pt-BR')):''}${c.ends_at?' • Fim '+escape(new Date(c.ends_at).toLocaleString('pt-BR')):''}</span></div><div class="portal-config-actions"><button type="button" data-edit="${c.id}">Editar imagens e dados</button><button type="button" data-delete="${c.id}" class="danger">Excluir campanha</button></div></article>`).join(''):'<p class="portal-config-empty">Nenhuma campanha neste evento. Clique em Nova campanha e selecione as imagens.</p>';
  }
  function renderSlides(){
    $('adSlideList').innerHTML=slides.map((s,i)=>`<article class="portal-config-slide"><img src="${escape(s.preview||s.image_path)}" alt="Story ${i+1}"><div><strong>Story ${i+1}</strong><label>Duração em segundos<input type="number" min="3" max="30" value="${s.duration}" data-duration="${i}" required></label><div class="portal-config-actions"><button type="button" data-up="${i}" ${i===0?'disabled':''} aria-label="Mover Story ${i+1} para antes">↑</button><button type="button" data-down="${i}" ${i===slides.length-1?'disabled':''} aria-label="Mover Story ${i+1} para depois">↓</button><button type="button" data-remove="${i}" class="danger">Remover</button></div></div></article>`).join('');
    $('adSlideCount').textContent=`${slides.length} de 20 imagens selecionadas`;
  }
  function edit(campaign){
    if(saving)return;if(dirty&&!confirm('Descartar as alterações desta campanha?'))return;discard();
    const form=$('adCampaignForm');form.reset();editingId=campaign?.id||null;
    for(const key of ['name','target_url','position'])form.elements[key].value=campaign?.[key]??(key==='position'?campaigns.length:'');
    form.elements.button_label.value=campaign?.button_label||'Me interessa';
    form.elements.whatsapp_enabled.value=String(!!campaign?.whatsapp_enabled);
    for(const key of ['whatsapp_phone','whatsapp_message'])form.elements[key].value=campaign?.[key]||'';
    form.elements.active.value=String(campaign?!!campaign.active:true);form.elements.starts_at.value=localDate(campaign?.starts_at);form.elements.ends_at.value=localDate(campaign?.ends_at);
    slides=(campaign?.slides||[]).map(s=>({...s}));renderSlides();report('',false,'adCampaignFeedback');$('adCampaignEditorTitle').textContent=campaign?'Editar campanha':'Nova campanha';$('adCampaignEditor').hidden=false;$('adCampaignEditor').scrollIntoView({behavior:'smooth',block:'start'});form.elements.name.focus();
  }
  async function refreshCampaigns(){const requested=eventId;const data=await request(`/admin/api/ad-portals/${requested}`);if(requested!==eventId)return;campaigns=data.campaigns;renderCampaigns();}
  async function events(){try{const data=await request('/admin/api/events');$('adPortalEvent').innerHTML='<option value="">Selecione um evento</option>'+(Array.isArray(data)?data:data.events||[]).filter(e=>e.portal_mode==='ads').map(e=>`<option value="${Number(e.id)}">${escape(e.name)}</option>`).join('');$('adPortalEvent').value=eventId||'';}catch(error){report(error.message,true);}}
  async function load(){
    const requested=Number($('adPortalEvent').value);if(saving||(dirty&&!confirm('Descartar as alterações desta campanha?'))){$('adPortalEvent').value=eventId;return;}
    discard();eventId=requested;page=1;$('adPortalContent').hidden=true;if(!requested)return;
    try{const data=await request(`/admin/api/ad-portals/${requested}`);if(requested!==eventId)return;
      for(const [key,value] of Object.entries(data.settings))if($('adPortalForm').elements[key])$('adPortalForm').elements[key].value=value;
      campaigns=data.campaigns;renderCampaigns();$('adPortalContent').hidden=false;tab('appearance');report('Evento selecionado: '+data.event.name);report('',false,'adSettingsFeedback');await contacts();
    }catch(error){report(error.message,true);}
  }
  async function contacts(){const requested=eventId,requestedPage=page;if(!requested)return;try{const data=await request(`/admin/api/ad-contacts?event_id=${requested}&page=${requestedPage}`);if(requested!==eventId||requestedPage!==page)return;
    contactRows=data.contacts;
    const rows=data.contacts.map(c=>`<tr><td><strong>${escape(c.name)}</strong><br><small>${escape(c.email||'')}</small></td><td>${escape(c.phone)}</td><td>${escape(accessLabel(c.access_status))}</td><td>${escape(new Date(c.created_at).toLocaleString('pt-BR'))}</td><td><button type="button" data-contact-id="${Number(c.id)}">Ver dados</button></td></tr>`).join('');
    $('adContacts').innerHTML=rows?`<table><thead><tr><th>Visitante</th><th>Telefone</th><th>Liberação</th><th>Cadastro</th><th>Ações</th></tr></thead><tbody>${rows}</tbody></table>`:'<p class="portal-config-empty">Nenhum cadastro recebido neste evento.</p>';
    $('adContactsPage').textContent=`Página ${page} • ${data.total} cadastros`;$('adContactsPrev').disabled=page<=1;$('adContactsNext').disabled=page*50>=data.total;
  }catch(error){report(error.message,true);}}
  $('adCampaignFiles').onchange=event=>{
    const files=Array.from(event.target.files);if(slides.length+files.length>20){report('Uma campanha pode ter até 20 imagens.',true,'adCampaignFeedback');event.target.value='';return;}
    const invalid=files.find(f=>!['image/jpeg','image/png','image/webp'].includes(f.type)||f.size>900*1024||f.size===0);
    if(invalid){report(`O arquivo ${invalid.name} precisa ser JPG, PNG ou WebP de até 900 KB.`,true,'adCampaignFeedback');event.target.value='';return;}
    slides.push(...files.map(file=>({file,preview:URL.createObjectURL(file),duration:8})));dirty=true;renderSlides();event.target.value='';report('Imagens selecionadas. Ajuste a ordem e salve a campanha.',false,'adCampaignFeedback');
  };
  $('adSlideList').oninput=event=>{if(event.target.dataset.duration!==undefined){slides[Number(event.target.dataset.duration)].duration=Number(event.target.value);dirty=true;}};
  $('adSlideList').onclick=event=>{const b=event.target.closest('button');if(!b||saving)return;for(const action of ['up','down','remove'])if(b.dataset[action]!==undefined){const i=Number(b.dataset[action]);if(action==='remove'){if(slides[i].preview)URL.revokeObjectURL(slides[i].preview);slides.splice(i,1);}else{const next=i+(action==='up'?-1:1);[slides[i],slides[next]]=[slides[next],slides[i]];}dirty=true;renderSlides();break;}};
  $('adCampaignForm').oninput=()=>{dirty=true;};
  $('adCampaignForm').onsubmit=async event=>{
    event.preventDefault();if(saving)return;if(!slides.length){report('Selecione pelo menos uma imagem.',true,'adCampaignFeedback');return;}
    const form=event.currentTarget,body=Object.fromEntries(new FormData(form)),selectedEvent=eventId;
    if(slides.some(s=>!Number.isInteger(s.duration)||s.duration<3||s.duration>30)){report('Use durações de 3 a 30 segundos.',true,'adCampaignFeedback');return;}
    saving=true;form.querySelectorAll('input,select,textarea,button').forEach(x=>x.disabled=true);$('adPortalEvent').disabled=true;$('adNewCampaign').disabled=true;
    try{
      for(let i=0;i<slides.length;i++){const s=slides[i];if(s.file&&!s.image_path){report(`Enviando imagem ${i+1} de ${slides.length}…`,false,'adCampaignFeedback');const data=await request('/admin/api/ad-images',{method:'POST',headers:{'Content-Type':s.file.type},body:s.file});s.image_path=data.image_path;}}
      body.event_id=selectedEvent;body.active=body.active==='true';body.starts_at=body.starts_at?new Date(body.starts_at).toISOString():null;body.ends_at=body.ends_at?new Date(body.ends_at).toISOString():null;body.slides=slides.map(s=>({image_path:s.image_path,duration:s.duration}));
      body.whatsapp_enabled=body.whatsapp_enabled==='true';
      const saved=await request('/admin/api/ad-story-campaigns'+(editingId?'/'+editingId:''),json(editingId?'PUT':'POST',body));editingId=saved.id||editingId;dirty=false;await refreshCampaigns();discard();report('Campanha e imagens salvas. A nova sequência será usada nas próximas visitas.');
    }catch(error){report(error.message||'Falha ao salvar. Suas imagens continuam selecionadas para tentar novamente.',true,'adCampaignFeedback');}
    finally{saving=false;form.querySelectorAll('input,select,textarea,button').forEach(x=>x.disabled=false);$('adPortalEvent').disabled=false;$('adNewCampaign').disabled=false;renderSlides();}
  };
  $('adPortalForm').onsubmit=async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button'),body=Object.fromEntries(new FormData(event.currentTarget)),requested=eventId;button.disabled=true;try{await request(`/admin/api/ad-portals/${requested}`,json('PUT',body));if(requested===eventId)report('Configuração salva para as próximas visitas.',false,'adSettingsFeedback');}catch(error){report(error.message,true,'adSettingsFeedback');}finally{button.disabled=false;}};
  $('adCampaignList').onclick=async event=>{const b=event.target.closest('button');if(!b||saving)return;if(b.dataset.edit){edit(campaigns.find(c=>c.id===Number(b.dataset.edit)));return;}if(b.dataset.delete&&confirm('Excluir esta campanha e suas imagens da sequência?')){b.disabled=true;try{await request(`/admin/api/ad-story-campaigns/${b.dataset.delete}`,{method:'DELETE'});if(editingId===Number(b.dataset.delete))discard();await refreshCampaigns();report('Campanha excluída.');}catch(error){report(error.message,true);b.disabled=false;}}};
  section.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>tab(b.dataset.tab));$('adPortalEvent').onchange=load;$('adRefreshEvents').onclick=events;$('adNewCampaign').onclick=()=>edit(null);$('adCancelCampaign').onclick=()=>{if(!dirty||confirm('Descartar alterações da campanha?'))discard();};$('adRefreshContacts').onclick=contacts;$('adContactsPrev').onclick=()=>{page=Math.max(1,page-1);contacts();};$('adContactsNext').onclick=()=>{page++;contacts();};
  $('adContacts').addEventListener('click',event=>{const button=event.target.closest('[data-contact-id]');if(button)showContact(Number(button.dataset.contactId));});
  events();
})();
