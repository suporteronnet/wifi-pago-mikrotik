(() => {
  'use strict';
  const $=id=>document.getElementById(id),params=new URLSearchParams(location.search);
  const context={event_key:params.get('event_key')||'',router_key:params.get('router_key')||'',mac:params.get('mac')||''};
  const resumeKey='wifi-ads:'+JSON.stringify(context);
  function savedSession(){try{return JSON.parse(sessionStorage.getItem(resumeKey)||'{}');}catch{return {};}}
  function saveSession(values){try{sessionStorage.setItem(resumeKey,JSON.stringify({...savedSession(),...values}));}catch{}}
  let token='',playlist=[],index=0,elapsed=0,paused=false,ready=false,timer=null,advancing=false,connecting=false;
  let portalConfig={},profileSaved=false;
  function step(name){document.body.dataset.step=name;if(name!=='story')window.scrollTo({top:0,behavior:'instant'});}
  function updatePhoneButton(){
    if(portalConfig.mode!=='ads_phone'||connecting)return;
    const form=$('profileForm'),phone=form.elements.phone,value=phone.value.replace(/\D/g,'');
    phone.setCustomValidity(value&& !/^\d{10,15}$/.test(value)?'Informe o telefone com DDD.':'');
    $('connect').disabled=!form.checkValidity();
    phone.parentElement.classList.toggle('phone-valid',/^\d{10,15}$/.test(value));
  }
  function renderPause(){
    $('pause').innerHTML=paused?'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 5 11 7-11 7Z" fill="currentColor"/></svg>':'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14M16 5v14" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></svg>';
    $('pause').setAttribute('aria-pressed',String(paused));
    $('pause').setAttribute('aria-label',paused?'Continuar Story':'Pausar Story');
  }
  const interests=new Set(),sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  $('continueBrowser').onclick=()=>{
    // A real link preserves the user gesture. Do not grant access or invoke
    // custom app schemes: the device decides where this HTTP link opens.
    if(document.body.dataset.step==='story'){paused=true;renderPause();}
  };
  const message=(text,error=false)=>{$('message').textContent=text;$('message').classList.toggle('error',error);};
  const url=value=>{if(!value)return '';try{const u=new URL(value,location.origin);return ['http:','https:'].includes(u.protocol)?u.href:'';}catch{return '';}};
  async function post(path,body,timeout=8000){
    const controller=new AbortController(),handle=setTimeout(()=>controller.abort(),timeout);
    try{const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:controller.signal,cache:'no-store'});const data=await response.json();if(!response.ok||!data.ok){const error=new Error(data.error||'Não foi possível continuar.');error.status=response.status;error.code=data.code;throw error;}return data;}finally{clearTimeout(handle);}
  }
  function configure(config){
    portalConfig=config;
    document.body.dataset.mode=config.mode;
    document.body.dataset.experience='light';
    const brand=document.querySelector('.portal-brand img');brand.src=config.logo_path||'/wifi-total-mark.svg';brand.onerror=()=>{brand.onerror=null;brand.src='/wifi-total-mark.svg';};brand.width=144;brand.height=144;
    document.documentElement.style.setProperty('--accent',config.color);
    $('portalTitle').textContent=config.title;$('termsText').textContent=config.terms;$('marketingText').textContent=config.marketing_label;$('surveyQuestion').textContent=config.survey_question;
    const fields=config.mode==='ads_phone'?[{id:'phone',label:'WhatsApp com DDD',type:'tel',enabled:true,required:true}]:config.fields;
    const container=document.querySelector('.signup-fields');container.replaceChildren();
    for(const field of fields||[]){
      if(!field.enabled)continue;
      const label=document.createElement('label'),input=document.createElement(field.type==='satisfaction'?'select':field.type==='textarea'?'textarea':'input');
      label.textContent=field.label;input.name=field.id;input.dataset.profileField='true';input.required=field.required;
      if(field.type==='satisfaction'){
        for(const value of ['', 'Muito insatisfeito','Insatisfeito','Neutro','Satisfeito','Muito satisfeito']){
          const option=document.createElement('option');option.value=value;option.textContent=value||'Selecione sua satisfação';input.append(option);
        }
      }else{
        if(field.type==='textarea')input.rows=2;else input.type=field.type;
        input.maxLength=field.type==='textarea'?1000:254;
      }
      label.append(input);container.append(label);
    }
    document.querySelector('.signup-steps').hidden=true;
    document.querySelector('.signup-intro .eyebrow').textContent=config.mode==='ads_phone'?'SEU WHATSAPP':'SUA OPINIÃO';
    document.querySelector('.signup-intro h2').textContent=config.mode==='ads_phone'?'Informe seu WhatsApp para continuar':'Responda para conectar';
    document.querySelector('.signup-intro p').textContent=config.mode==='ads_phone'?'Na próxima tela, escolha uma oferta ou continue para navegar.':'Preencha os campos abaixo para liberar seu acesso.';
    $('connect').textContent=config.mode==='lead'?'CONECTAR E NAVEGAR':'VER OFERTAS';
    if(config.mode==='ads_phone'){
      const intro=document.querySelector('.signup-intro');intro.querySelector('h2').textContent='Olá, seja bem-vindo!';intro.querySelector('p').textContent='Por favor, insira seu número de WhatsApp para prosseguir.';
      const input=$('profileForm').elements.phone;input.autocomplete='tel';input.inputMode='tel';input.placeholder='(00) 00000-0000';input.maxLength=25;input.setAttribute('aria-label','WhatsApp com DDD');input.parentElement.classList.add('phone-entry');
      $('connect').textContent='Prosseguir →';$('skipOffers').textContent='Prosseguir →';
      $('profileForm').addEventListener('input',updatePhoneButton);updatePhoneButton();
    }
  }
  async function showStory(){
    step('story');
    $('pause').setAttribute('aria-pressed','false');
    clearInterval(timer);ready=false;elapsed=0;paused=false;renderPause();
    $('storyImage').hidden=true;$('storyLoading').hidden=false;
    $('storyOverlay').hidden=true;
    const story=playlist[index];$('storyCount').textContent=`${index+1} DE ${playlist.length}`;
    $('nextStory').disabled=true;$('nextStory').textContent='Carregando imagem…';$('interest').hidden=true;
    $('interest').textContent=story.button_label||'Me interessa';
    const target=url(story.target_url);if(target)$('interest').href=target;else $('interest').removeAttribute('href');
    const whatsapp=url(story.whatsapp_url);
    $('whatsapp').hidden=true;
    if(whatsapp)$('whatsapp').href=whatsapp;else $('whatsapp').removeAttribute('href');
    $('progress').replaceChildren(...playlist.map((_,i)=>{const bar=document.createElement('span'),fill=document.createElement('i');fill.style.width=i<index?'100%':'0';bar.append(fill);return bar;}));
    await new Promise((resolve,reject)=>{const img=$('storyImage'),handle=setTimeout(()=>reject(new Error('A imagem não carregou. Tente reabrir o portal.')),12000);img.onload=()=>{clearTimeout(handle);resolve();};img.onerror=()=>{clearTimeout(handle);reject(new Error('Imagem indisponível. Avise o responsável pelo Wi-Fi.'));};img.src=url(story.image_path);});
    $('storyImage').hidden=false;$('storyLoading').hidden=true;
    $('storyOverlay').textContent=story.overlay_text||'';
    $('storyOverlay').hidden=!story.overlay_text;
    $('storyScreen').classList.toggle('has-overlay',Boolean(story.overlay_text));
    // Antecipar somente a próxima imagem evita baixar a campanha inteira no celular.
    if(playlist[index+1]){const preload=new Image();preload.src=url(playlist[index+1].image_path);}
    ready=true;message('');let last=performance.now();
    timer=setInterval(()=>{const now=performance.now(),delta=Math.min(250,now-last);last=now;if(paused||document.hidden||!ready)return;elapsed+=delta;$('progress').children[index].firstChild.style.width=Math.min(100,elapsed/(story.duration*10))+'%';const remaining=Math.max(0,Math.ceil(story.duration-elapsed/1000));$('nextStory').textContent=remaining?`${remaining}s`:(index===playlist.length-1?'Continuar para cadastro':'Próximo anúncio');if(!remaining){$('nextStory').disabled=false;clearInterval(timer);advance();}},100);
  }
  async function advance(){
    if(advancing||!ready||elapsed<playlist[index].duration*1000)return;
    advancing=true;$('nextStory').disabled=true;
    try{const result=await post('/api/ads/story-next',{token,index});if(result.completed){$('storyScreen').hidden=true;$('profileScreen').hidden=false;step('profile');message(portalConfig.mode==='ads_phone'?'':'Preencha seus dados para liberar o acesso.');}else{index=result.index;await showStory();}}
    catch(error){message(error.status?error.message:'A conexão oscilou. Toque para continuar.',true);$('nextStory').disabled=false;$('nextStory').textContent='Tentar continuar';if(!ready)$('restart').hidden=false;}
    finally{advancing=false;}
  }
  $('pause').onclick=()=>{paused=!paused;renderPause();$('pause').setAttribute('aria-pressed',String(paused));$('pause').setAttribute('aria-label',paused?'Continuar Story':'Pausar Story');};$('nextStory').onclick=advance;
  function openAdvertiser(event){
    event.preventDefault();
    if(!event.currentTarget.getAttribute('href'))return;
    interests.add(playlist[index].id);
    message('Conclua os anúncios e o cadastro. Você poderá abrir esta oferta após conectar.');
  }
  $('interest').onclick=openAdvertiser;
  $('whatsapp').onclick=openAdvertiser;
  $('restart').onclick=()=>location.reload();
  function showOffers(){
    step('offers');
    $('profileScreen').hidden=true;$('offerScreen').hidden=false;$('offerList').replaceChildren();
    for(const story of new Map(playlist.map(s=>[s.id,s])).values()){
      const card=document.createElement('article'),img=document.createElement('img');img.src=url(story.image_path);img.alt=story.name;card.append(img);
      for(const [destination,label] of [[story.target_url,story.button_label||'Me interessa'],[story.whatsapp_url,story.target_url?'Conversar no WhatsApp':story.button_label||'Me interessa']]){
        if(!url(destination))continue;const button=document.createElement('button');button.type='button';button.textContent=label;button.onclick=()=>connectAccess(url(destination),story.id);card.append(button);
      }
      $('offerList').append(card);
    }
    message(portalConfig.mode==='ads_phone'?'':'Escolha uma oferta. Primeiro conectaremos seu aparelho, depois abriremos o destino.');
  }
  $('skipOffers').onclick=()=>connectAccess();
  async function connectAccess(destination='',campaignId=null){
    if(connecting||!profileSaved)return;connecting=true;$('connect').disabled=true;$('connect').textContent='Solicitando acesso…';
    saveSession({destination,campaignId});
    $('offerScreen').querySelectorAll('button').forEach(b=>b.disabled=true);
    const previousScreen=$('offerScreen').hidden?'profile':'offers';
    $('profileScreen').hidden=true;$('offerScreen').hidden=true;$('connectingScreen').hidden=false;step('connecting');
    try{
      for(let attempt=0;attempt<8;attempt++){
        try{await post('/api/ads/access',{token});break;}
        catch(error){if(error.code!=='DEVICE_NOT_SEEN'||attempt===7)throw error;message('Identificando seu aparelho para conectar…');await sleep(3000);}
      }
      message('Conectando seu aparelho…');
      const confirmationDeadline=Date.now()+90000;
      while(Date.now()<confirmationDeadline){
        let state;try{state=await post('/api/ads/status',{token},3000);}catch(error){if(error.status&&error.status<500&&error.status!==429)throw error;message('Concluindo a conexão. A confirmação será consultada novamente…');await sleep(1000);continue;}
        if(state.status==='applied'){
          $('profileScreen').hidden=true;$('offerScreen').hidden=true;$('connectingScreen').hidden=true;$('successScreen').hidden=false;step('success');message('Internet liberada.');
          // link-orig can be the captive login URL itself, causing a new portal run.
          const dest=destination;$('continue').href=dest&&url(dest)?url(dest):'http://neverssl.com/';
          $('continue').textContent=destination?(/^(wa\.me|api\.whatsapp\.com)$/i.test(new URL(destination).hostname)?'Abrir conversa no WhatsApp':'Abrir site do anunciante'):'Continuar navegando';
          if(campaignId)fetch(`/api/ad-campaigns/${campaignId}/click`,{method:'POST',keepalive:true}).catch(()=>{});
          for(const story of [...new Map(playlist.filter(s=>interests.has(s.id)&&url(s.target_url)).map(s=>[s.id,s])).values()]){const a=document.createElement('a');a.textContent='Conhecer '+story.name;a.href=url(story.target_url);a.target='_blank';a.rel='noopener noreferrer';a.onclick=()=>fetch(`/api/ad-campaigns/${story.id}/click`,{method:'POST',keepalive:true}).catch(()=>{});$('offers').append(a);}
          message('Internet liberada. Abrindo a navegação…');
          location.replace($('continue').href);
          return;
        }
        if(state.status==='expired')throw new Error('O tempo de acesso terminou. Reabra o portal para ver novos anúncios.');
        if(state.status==='cancelled')throw new Error('Esta solicitação ficou sem confirmação. Reabra o portal para tentar novamente.');
        if(state.status==='revoked')throw new Error('Este acesso foi encerrado na MikroTik. Solicite uma nova liberação.');
        await sleep(1000);
      }
      throw new Error('A confirmação ainda não chegou. Tente liberar novamente.');
    }catch(error){$('connectingScreen').hidden=true;$(previousScreen==='offers'?'offerScreen':'profileScreen').hidden=false;step(previousScreen);message(error.name==='AbortError'?'A conexão demorou. Tente novamente.':error.message,true);$('connect').disabled=false;$('connect').textContent='Tentar liberar novamente';}
    finally{connecting=false;$('offerScreen').querySelectorAll('button').forEach(b=>b.disabled=false);}
  }
  $('profileForm').addEventListener('submit',async event=>{
    event.preventDefault();if(connecting)return;$('connect').disabled=true;
    try{const form=event.currentTarget,answers={};form.querySelectorAll('[data-profile-field]').forEach(input=>answers[input.name]=input.value);
      await post('/api/ads/profile',{token,answers,terms_accepted:form.elements.terms_accepted.checked,marketing_consent:form.elements.marketing_consent.checked});profileSaved=true;
      if(portalConfig.mode==='lead')await connectAccess();else showOffers();
    }catch(error){message(error.message,true);}finally{if(!connecting)$('connect').disabled=false;}
  });
  async function begin(){
    try{
      if(!context.event_key||!context.router_key||!/^([a-f0-9]{2}:){5}[a-f0-9]{2}$/i.test(context.mac))throw new Error('Abra este portal conectando-se ao Wi-Fi do evento.');
      for(let attempt=0;attempt<20;attempt++){
        try{
          const saved=savedSession(),result=await post('/api/ads/session',{...context,resume_token:saved.token});
          token=result.token;playlist=result.playlist;configure(result.settings);index=result.index||0;profileSaved=result.profile_saved===true;
          saveSession({token,destination:result.token===saved.token?saved.destination:'',campaignId:result.token===saved.token?saved.campaignId:null});
          if(result.completed||result.settings.mode==='lead'){
            $('storyScreen').hidden=true;
            if(profileSaved){
              if(result.access_requested){$('profileScreen').hidden=false;await connectAccess(url(saved.destination),saved.campaignId);}
              else if(result.settings.mode==='lead')await connectAccess();else showOffers();
            }else{$('profileScreen').hidden=false;step('profile');}
          }else await showStory();
          return;
        }catch(error){if(error.status!==409||attempt===19)throw error;message(error.message);await sleep(3000);}
      }
    }catch(error){message(error.name==='AbortError'?'Não foi possível carregar. Reabra o portal.':error.message,true);$('restart').hidden=false;}
  }
  begin();
})();
