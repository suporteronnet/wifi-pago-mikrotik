(() => {
  'use strict';
  const params=new URLSearchParams(location.hash.slice(1)),token=params.get('token');
  const status=document.getElementById('status'),link=document.getElementById('destination'),retry=document.getElementById('retry');
  let destination;
  try{
    destination=new URL(params.get('destination'));
    if(!['https:','http:'].includes(destination.protocol)||!token)throw new Error();
  }catch{status.textContent='Oferta inválida. Volte ao portal e escolha novamente.';return;}
  // The bearer token remains in the fragment, never in HTTP query logs or referrers.
  let checking=false;
  const authorize=params.get('authorize')==='1';
  const captive=/Android.*; wv\)|Android.*Version\/4\.0|(?:iPhone|iPad|iPod)(?![\s\S]*Safari\/)/i.test(navigator.userAgent);
  async function check(){
    if(checking)return;checking=true;retry.hidden=true;
    const deadline=Date.now()+120000;
    try{
      if(authorize){
        const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),10000);
        try{
          const response=await fetch('/api/ads/access',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token}),signal:controller.signal,cache:'no-store'});
          const data=await response.json();
          if(!response.ok||!data.ok)throw new Error(data.error||'Não foi possível solicitar o acesso. Tente novamente.');
        }finally{clearTimeout(timeout);}
      }
      while(Date.now()<deadline){
        const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),4000);
        let data;
        try{
          const response=await fetch('/api/ads/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token}),signal:controller.signal,cache:'no-store'});
          data=await response.json();
          if(!response.ok&&response.status<500&&response.status!==429)throw Object.assign(new Error(data.error||'Não foi possível confirmar o acesso.'),{terminal:true});
        }catch(error){if(error.terminal)throw error;}
        finally{clearTimeout(timeout);}
        if(data?.ok&&data.status==='applied'){
          document.getElementById('title').textContent='Internet liberada!';
          status.textContent='Abrindo sua oferta. Se não abrir automaticamente, toque no botão abaixo.';
          link.href=destination.href;
          link.textContent=/^(wa\.me|api\.whatsapp\.com)$/i.test(destination.hostname)?'Abrir conversa no WhatsApp':'Abrir site do anunciante';
          link.hidden=false;
          history.replaceState(null,'',location.pathname);
          location.replace(destination.href);
          return;
        }
        if(['expired','cancelled'].includes(data?.status))throw new Error('Esta solicitação terminou. Volte ao portal para tentar novamente.');
        await new Promise(resolve=>setTimeout(resolve,1000));
      }
      throw new Error('A confirmação ainda não chegou. Toque para verificar novamente.');
    }catch(error){status.textContent=error.message;retry.hidden=false;}
    finally{checking=false;}
  }
  retry.onclick=check;
  if(authorize&&captive){
    document.getElementById('title').textContent='Continue no navegador';
    status.textContent='A oferta está selecionada. Seu acesso será solicitado no navegador, para esta janela não interromper a abertura.';
    document.getElementById('browserHelp').hidden=false;
    const field=document.getElementById('browserUrl');field.value=location.href;
    document.getElementById('copyUrl').onclick=async()=>{
      try{await navigator.clipboard.writeText(location.href);status.textContent='Endereço copiado. Cole no Safari ou Chrome.';}
      catch{field.focus();field.select();status.textContent='Copie o endereço selecionado e cole no navegador.';}
    };
    document.getElementById('browserReady').onclick=()=>{document.getElementById('browserHelp').hidden=true;check();};
  }else check();
})();
