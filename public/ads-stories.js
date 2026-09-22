(() => {
  'use strict';
  const $=id=>document.getElementById(id),params=new URLSearchParams(location.search);
  const context={event_key:params.get('event_key')||'',router_key:params.get('router_key')||'',mac:params.get('mac')||''};
  let token='',playlist=[],index=0,elapsed=0,paused=false,ready=false,timer=null,advancing=false,connecting=false;
  const interests=new Set(),sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  const message=(text,error=false)=>{$('message').textContent=text;$('message').classList.toggle('error',error);};
  const url=value=>{if(!value)return '';try{const u=new URL(value,location.origin);return ['http:','https:'].includes(u.protocol)?u.href:'';}catch{return '';}};
  async function post(path,body,timeout=8000){
    const controller=new AbortController(),handle=setTimeout(()=>controller.abort(),timeout);
    try{const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:controller.signal,cache:'no-store'});const data=await response.json();if(!response.ok||!data.ok){const error=new Error(data.error||'Não foi possível continuar.');error.status=response.status;throw error;}return data;}finally{clearTimeout(handle);}
  }
  function configure(config){
    document.documentElement.style.setProperty('--accent',config.color);
    $('portalTitle').textContent=config.title;$('termsText').textContent=config.terms;$('marketingText').textContent=config.marketing_label;$('surveyQuestion').textContent=config.survey_question;
    for(const key of ['email','city','survey']){const control=$('profileForm').elements[key];$(key+'Field').hidden=config[key]==='hidden';control.disabled=config[key]==='hidden';control.required=config[key]==='required';}
  }
  async function showStory(){
    clearInterval(timer);ready=false;elapsed=0;paused=false;$('pause').textContent='Pausar';
    const story=playlist[index];$('storyCount').textContent=`${index+1} DE ${playlist.length}`;$('storyTitle').textContent=story.name;
    $('storyHelp').textContent='Veja os anúncios para continuar até o cadastro.';$('nextStory').disabled=true;$('nextStory').textContent='Carregando imagem…';$('interest').hidden=!url(story.target_url);
    $('interest').textContent=interests.has(story.id)?'Interesse salvo ✓':'Me interessa';
    $('progress').replaceChildren(...playlist.map((_,i)=>{const bar=document.createElement('span'),fill=document.createElement('i');fill.style.width=i<index?'100%':'0';bar.append(fill);return bar;}));
    await new Promise((resolve,reject)=>{const img=$('storyImage'),handle=setTimeout(()=>reject(new Error('A imagem não carregou. Tente reabrir o portal.')),12000);img.onload=()=>{clearTimeout(handle);resolve();};img.onerror=()=>{clearTimeout(handle);reject(new Error('Imagem indisponível. Avise o responsável pelo Wi-Fi.'));};img.src=url(story.image_path);});
    ready=true;message('Anúncio em exibição.');let last=performance.now();
    timer=setInterval(()=>{const now=performance.now(),delta=Math.min(250,now-last);last=now;if(paused||document.hidden||!ready)return;elapsed+=delta;$('progress').children[index].firstChild.style.width=Math.min(100,elapsed/(story.duration*10))+'%';const remaining=Math.max(0,Math.ceil(story.duration-elapsed/1000));$('nextStory').textContent=remaining?`Aguarde ${remaining}s…`:(index===playlist.length-1?'Continuar para cadastro':'Próximo anúncio');if(!remaining){$('nextStory').disabled=false;clearInterval(timer);advance();}},100);
  }
  async function advance(){
    if(advancing||!ready||elapsed<playlist[index].duration*1000)return;
    advancing=true;$('nextStory').disabled=true;
    try{const result=await post('/api/ads/story-next',{token,index});if(result.completed){$('storyScreen').hidden=true;$('profileScreen').hidden=false;message('Preencha seus dados para liberar o acesso.');$('profileForm').elements.name.focus();}else{index=result.index;await showStory();}}
    catch(error){message(error.status?error.message:'A conexão oscilou. Toque para continuar.',true);$('nextStory').disabled=false;$('nextStory').textContent='Tentar continuar';if(!ready)$('restart').hidden=false;}
    finally{advancing=false;}
  }
  $('pause').onclick=()=>{paused=!paused;$('pause').textContent=paused?'Continuar':'Pausar';};$('nextStory').onclick=advance;
  $('interest').onclick=()=>{interests.add(playlist[index].id);$('interest').textContent='Interesse salvo ✓';message('O link estará disponível depois que seu acesso for liberado.');};
  $('restart').onclick=()=>location.reload();
  $('profileForm').addEventListener('submit',async event=>{
    event.preventDefault();if(connecting)return;connecting=true;$('connect').disabled=true;$('connect').textContent='Solicitando acesso…';
    try{
      const form=event.currentTarget,body={token};for(const key of ['name','phone','email','city','survey'])body[key]=form.elements[key].value;
      body.terms_accepted=form.elements.terms_accepted.checked;body.marketing_consent=form.elements.marketing_consent.checked;
      await post('/api/ads/profile',body);await post('/api/ads/access',{token});message('Aguardando a MikroTik confirmar seu acesso…');
      for(let attempt=0;attempt<45;attempt++){
        let state;try{state=await post('/api/ads/status',{token},6000);}catch(error){if(error.status&&error.status<500&&error.status!==429)throw error;message('A conexão mudou. Verificando novamente…');await sleep(2000);continue;}
        if(state.status==='applied'){
          $('profileScreen').hidden=true;$('successScreen').hidden=false;message('Internet liberada.');
          const dest=params.get('linkOrig');$('continue').href=dest&&url(dest)?url(dest):'http://neverssl.com/';
          for(const story of [...new Map(playlist.filter(s=>interests.has(s.id)&&url(s.target_url)).map(s=>[s.id,s])).values()]){const a=document.createElement('a');a.textContent='Conhecer '+story.name;a.href=url(story.target_url);a.target='_blank';a.rel='noopener noreferrer';a.onclick=()=>fetch(`/api/ad-campaigns/${story.id}/click`,{method:'POST',keepalive:true}).catch(()=>{});$('offers').append(a);}
          return;
        }
        if(state.status==='expired')throw new Error('O tempo de acesso terminou. Reabra o portal para ver novos anúncios.');
        await sleep(2000);
      }
      throw new Error('A confirmação ainda não chegou. Tente liberar novamente.');
    }catch(error){message(error.name==='AbortError'?'A conexão demorou. Tente novamente.':error.message,true);$('connect').disabled=false;$('connect').textContent='Tentar liberar novamente';}
    finally{connecting=false;}
  });
  async function begin(){
    try{
      if(!context.event_key||!context.router_key||!/^([a-f0-9]{2}:){5}[a-f0-9]{2}$/i.test(context.mac))throw new Error('Abra este portal conectando-se ao Wi-Fi do evento.');
      for(let attempt=0;attempt<20;attempt++){
        try{const result=await post('/api/ads/session',context);token=result.token;playlist=result.playlist;configure(result.settings);await showStory();return;}catch(error){if(error.status!==409||attempt===19)throw error;message(error.message);await sleep(3000);}
      }
    }catch(error){message(error.name==='AbortError'?'Não foi possível carregar. Reabra o portal.':error.message,true);$('restart').hidden=false;}
  }
  begin();
})();
