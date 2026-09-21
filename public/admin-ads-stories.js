(() => {
  const host=document.getElementById('banners');if(!host)return;
  const section=document.createElement('section');section.className='section ads-management';
  section.innerHTML=`<div class="section-header"><h2>Portal de Stories e cadastro</h2></div><div class="section-body">
    <p>Selecione um evento de anúncios para configurar o portal e consultar os cadastros.</p>
    <div class="ads-toolbar"><select id="adPortalEvent" aria-label="Evento do portal"><option value="">Selecione um evento</option></select><button id="adRefreshEvents" type="button">Atualizar eventos</button></div>
    <div id="adPortalMessage" role="status"></div>
    <div id="adPortalContent" hidden>
      <form id="adPortalForm"><div class="ads-grid">
        <label>Título do portal<input name="title" maxlength="80" required></label><label>Cor dos botões<input name="color" type="color" required></label>
        <label>E-mail<select name="email"><option value="hidden">Não solicitar</option><option value="optional">Opcional</option><option value="required">Obrigatório</option></select></label>
        <label>Cidade<select name="city"><option value="hidden">Não solicitar</option><option value="optional">Opcional</option><option value="required">Obrigatório</option></select></label>
        <label>Pesquisa<select name="survey"><option value="hidden">Não solicitar</option><option value="optional">Opcional</option><option value="required">Obrigatória</option></select></label>
        <label>Pergunta da pesquisa<input name="survey_question" maxlength="180" required></label>
      </div><p>Nome e telefone são obrigatórios. O aceite para receber ofertas é sempre opcional.</p>
      <label>Termos de uso apresentados ao visitante<textarea name="terms" maxlength="2000" rows="3" required></textarea></label>
      <label>Texto da autorização para receber ofertas<input name="marketing_label" maxlength="250" required></label>
      <button type="submit">Salvar cadastro e aparência</button></form>
      <h3>Sequência dos Stories</h3><p>Cadastre ou troque as imagens em Campanhas abaixo. A ordem menor aparece primeiro. Duração e ordem acompanham a campanha em todos os eventos vinculados. Até 20 anúncios ativos por sequência.</p><div id="adStoryEditors"></div>
      <h3>Cadastros deste evento</h3><button id="adRefreshContacts" type="button">Atualizar cadastros</button><div class="ads-table" id="adContacts"></div><div class="ads-toolbar"><button id="adContactsPrev" type="button">Anterior</button><span id="adContactsPage"></span><button id="adContactsNext" type="button">Próxima</button></div>
    </div></div>`;
  host.prepend(section);
  const style=document.createElement('style');style.textContent='.ads-management [hidden]{display:none!important}.ads-management label{display:block;margin:12px 0;font-size:13px;color:#cbd5e1}.ads-management input,.ads-management select,.ads-management textarea{display:block;width:100%;margin-top:6px;padding:10px;border:1px solid #334155;border-radius:8px;background:#0b1728;color:#f8fafc;font:14px Arial}.ads-management input[type=color]{height:42px}.ads-management button{padding:10px 16px;border:1px solid #475569;border-radius:8px;background:#253652;color:#f8fafc;cursor:pointer}.ads-management button:disabled{opacity:.5;cursor:wait}.ads-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:0 16px}.ads-toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:12px 0}.ads-toolbar select{width:auto;min-width:220px}.ads-management p{color:#94a3b8;font-size:13px;line-height:1.5}.ads-management h3{margin-top:28px}.ads-story-editor{display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding:12px;border:1px solid #334155;border-radius:10px;margin:10px 0}.ads-story-editor img{width:60px;height:90px;object-fit:contain}.ads-story-editor label{width:120px}.ads-table{overflow:auto;margin:16px 0}.ads-table table{width:100%;border-collapse:collapse;min-width:700px}.ads-table th,.ads-table td{text-align:left;padding:10px;border-bottom:1px solid #334155;font-size:13px;max-width:250px;overflow-wrap:anywhere}#adPortalMessage{padding:10px 0;color:#a7f3d0}';document.head.append(style);
  const $=id=>document.getElementById(id),escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let page=1,eventId=0;
  async function request(path,options={}){const response=await fetch(path,{cache:'no-store',...options});const data=await response.json();if(!response.ok||data.ok===false)throw new Error(data.error||'Não foi possível carregar os dados.');return data;}
  function report(error){$('adPortalMessage').textContent=error.message||error;}
  async function events(){try{const data=await request('/admin/api/events');const selected=$('adPortalEvent').value;$('adPortalEvent').innerHTML='<option value="">Selecione um evento</option>'+(Array.isArray(data)?data:data.events||[]).filter(e=>e.portal_mode==='ads').map(e=>`<option value="${Number(e.id)}">${escape(e.name)}</option>`).join('');$('adPortalEvent').value=selected;}catch(error){report(error);}}
  async function contacts(){
    const requested=eventId;if(!requested)return;
    try{const data=await request(`/admin/api/ad-contacts?event_id=${requested}&page=${page}`);if(requested!==eventId)return;
      const rows=data.contacts.map(c=>`<tr><td>${escape(c.name)}</td><td>${escape(c.phone)}</td><td>${escape(c.email||'—')}</td><td>${escape(c.city||'—')}</td><td>${escape(c.survey_answer||'—')}</td><td>${c.marketing_consent?'Autorizou':'Não autorizou'}</td><td>${c.access_status==='applied'?'Confirmado':c.access_status==='pending'?'Aguardando MikroTik':'Cadastro recebido'}</td><td>${escape(new Date(c.created_at).toLocaleString('pt-BR'))}</td></tr>`).join('');
      $('adContacts').innerHTML=rows?`<table><thead><tr><th>Nome</th><th>Telefone</th><th>E-mail</th><th>Cidade</th><th>Pesquisa</th><th>Ofertas</th><th>Liberação</th><th>Cadastro</th></tr></thead><tbody>${rows}</tbody></table>`:'Nenhum cadastro recebido.';
      $('adContactsPage').textContent=`Página ${page} • ${data.total} cadastros`;$('adContactsPrev').disabled=page<=1;$('adContactsNext').disabled=page*50>=data.total;
    }catch(error){report(error);}
  }
  async function load(){
    eventId=Number($('adPortalEvent').value);page=1;$('adPortalContent').hidden=true;if(!eventId)return;const requested=eventId;
    try{const data=await request(`/admin/api/ad-portals/${requested}`);if(eventId!==requested)return;
      for(const [key,value] of Object.entries(data.settings))if($('adPortalForm').elements[key])$('adPortalForm').elements[key].value=value;
      $('adStoryEditors').innerHTML=data.campaigns.map(c=>`<form class="ads-story-editor" data-campaign="${Number(c.id)}"><img src="${escape(c.image_path)}" alt=""><strong>${escape(c.name)} ${c.active?'':'(inativa)'}</strong><label>Duração (segundos)<input name="duration" type="number" min="3" max="30" value="${Number(c.duration)}" required></label><label>Ordem<input name="position" type="number" min="0" max="999" value="${Number(c.position)}" required></label><button type="submit">Salvar Story</button></form>`).join('')||'Vincule uma campanha a este evento para montar os Stories.';
      $('adPortalContent').hidden=false;report('Configuração carregada.');await contacts();
    }catch(error){report(error);}
  }
  $('adPortalForm').onsubmit=async event=>{event.preventDefault();const body=Object.fromEntries(new FormData(event.currentTarget));try{await request(`/admin/api/ad-portals/${eventId}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});report('Configuração salva. Será usada nas próximas visitas.');}catch(error){report(error);}};
  $('adStoryEditors').onsubmit=async event=>{event.preventDefault();const form=event.target,body=Object.fromEntries(new FormData(form));try{await request(`/admin/api/ad-story-campaigns/${form.dataset.campaign}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});report('Story salvo. A sequência será usada nas próximas visitas.');}catch(error){report(error);}};
  $('adPortalEvent').onchange=load;$('adRefreshEvents').onclick=async()=>{await events();await load();};$('adRefreshContacts').onclick=contacts;
  $('adContactsPrev').onclick=()=>{page=Math.max(1,page-1);contacts();};$('adContactsNext').onclick=()=>{page++;contacts();};
  events();
})();
