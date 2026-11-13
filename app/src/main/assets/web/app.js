'use strict';
const $=id=>document.getElementById(id);
const app={token:null,selected:0,active:false,mode:'off',error:'',services:[],check:null,probeBusy:false,systemBusy:false,root:false,rootChecked:false,dnsRequests:0,dnsReplies:0,dnsFailures:0,privateDnsMode:'неизвестно',smartChecked:0,smartSelected:0,smartFallbacks:0,smartLast:'Проверка маршрутов ещё не проводилась'};
const android=typeof window.HBAndroid!=='undefined';
window.HBTransport={
  pending:new Map(), serial:0,
  send(endpoint,data){
    const id='req_'+(++this.serial);
    return new Promise((resolve,reject)=>{
      this.pending.set(id,{resolve,reject});
      window.HBAndroid.post(id,endpoint,JSON.stringify(data||{}));
    });
  },
  complete(id,json,error){
    const req=this.pending.get(id);if(!req)return;this.pending.delete(id);
    if(error!==null&&error!==undefined)req.reject(Error(error));
    else try{req.resolve(JSON.parse(json));}catch(e){req.reject(e);}
  },
  push(json){try{updateStatus(JSON.parse(json));}catch(e){console.warn(e);}}
};
let toastTimer;
const notify=message=>{const el=$('toast');el.textContent=message;el.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.remove('show'),4200);};
async function request(endpoint,data){
  if(android)return window.HBTransport.send(endpoint,data);
  const opts=data===undefined?{}:{method:'POST',headers:{'content-type':'application/json','x-hb-token':app.token},body:JSON.stringify(data)};
  const resp=await fetch('/api/'+endpoint,{...opts,cache:'no-store'});
  let result;try{result=await resp.json();}catch{throw Error('Локальный сервер не ответил корректно');}
  if(!resp.ok)throw Error(result.error||'Ошибка: '+resp.status);
  return result;
}
function updateStatus(s){
  app.token=s.token;app.selected=s.selected;app.active=s.active;app.services=s.services;app.probeBusy=s.probeBusy;app.systemBusy=s.systemBusy;app.mode=s.mode||'off';app.error=s.error||'';app.root=!!s.root;app.rootChecked=!!s.rootChecked;
  app.dnsRequests=s.dnsRequests||0;app.dnsReplies=s.dnsReplies||0;app.dnsFailures=s.dnsFailures||0;
  app.privateDnsMode=s.privateDnsMode||'неизвестно';
  app.smartChecked=s.smartChecked||0;app.smartSelected=s.smartSelected||0;
  app.smartFallbacks=s.smartFallbacks||0;app.smartLast=s.smartLast||'Проверка маршрутов ещё не проводилась';
  render();
}
function render(){
  const provider=app.services[app.selected];if(!provider)return;
  $('badge').textContent='Smart DNS 1.26 · '+provider.site;
  $('addresses').textContent=provider.v4.join('  /  ');
  $('provider-note').textContent=provider.opens;
  document.querySelectorAll('.service').forEach(el=>{el.classList.toggle('selected',Number(el.dataset.set)===app.selected);el.disabled=app.systemBusy||app.probeBusy;});
  const busy=app.systemBusy||app.probeBusy;
  const power=$('toggle');power.classList.toggle('on',app.active);power.classList.toggle('loading',app.systemBusy);power.disabled=busy;
  $('toggle-text').textContent=app.systemBusy?'ПРИМЕНЯЕМ':app.active?'ВЫКЛЮЧИТЬ':'ВКЛЮЧИТЬ';
  $('status-title').textContent=app.systemBusy?'Применяем настройки…':app.active?(app.dnsReplies?'DNS работает · запросы видны':'DNS-сервис включён · нет подтверждения'):'DNS выключен';
  $('status-desc').textContent=app.error&&!app.active?app.error:app.active?
    (app.mode==='root'?`${provider.name}: системный DNS перенаправляется через root. Приложение работает самостоятельно.`:
    `${provider.name}: DNS применяется через локальный Android VPN, без root и Termux.`):
    (android?'Доступны два режима: root-перехват или DNS-VPN без root. Для VPN потребуется системное разрешение Android.':'Для системного переключения требуются root-права и запущенный локальный сервис.');
  const counter=$('dns-counter'), risk=$('dns-risk');
  if(counter)counter.textContent=`Перехвачено запросов: ${app.dnsRequests} · ответов: ${app.dnsReplies} · ошибок: ${app.dnsFailures}`;
  if(risk){
    const strict=app.privateDnsMode==='hostname';
    risk.textContent='Private DNS: '+app.privateDnsMode+(strict?' · строгий DoT может обходить обычный DNS-VPN. Откройте настройки Android и выберите Автоматически, если хотите проверить работу Smart DNS.':'');
    risk.classList.toggle('warning',strict);
  }
  const smart=$('smart-route-status');
  if(smart)smart.textContent=`Проверено HTTPS-путей: ${app.smartChecked} · выбрано: ${app.smartSelected} · резервных переключений: ${app.smartFallbacks}. ${app.smartLast}`;
  $('check').textContent=app.probeBusy?'Проверяем…':'Проверить '+provider.short;
  $('best').textContent=app.probeBusy?'Ищем…':'Найти лучший';
  $('check').disabled=busy;$('best').disabled=busy;
  $('mode-label').textContent=app.active?(app.mode==='root'?'ROOT DNS':'DNS-VPN'):(app.root?'ROOT ДОСТУПЕН':'БЕЗ ROOT · VPN');
  if(app.rootChecked){$('root-indicator').className='state-dot '+(app.root?'ok':'');
    $('root-detail').textContent=app.root?'Root доступен. Приложение автоматически использует его при включении.':'Root недоступен; используется DNS-VPN с разрешения Android.';}
  renderResults();
}
function renderResults(){
  const root=$('results');root.replaceChildren();
  for(const entry of [{label:'ChatGPT'},{label:'Claude'},{label:'Gemini'},{label:'ElevenLabs'},{label:'Grok'},{label:'Perplexity'}]){
    const row=app.check?.set===app.selected?app.check.rows.find(x=>x.label===entry.label):null;
    const tone=row?(row.result?.startsWith('HTTP 2')?'ok':row.result?.startsWith('HTTP 3')||row.result?.includes('CAPTCHA')?'captcha':'bad'):'';
    const box=document.createElement('div');box.className='result';
    const dot=document.createElement('span');dot.className='dot '+tone;
    const body=document.createElement('div');body.className='result-body';
    const name=document.createElement('span');name.className='result-name';name.textContent=entry.label;
    const status=document.createElement('span');status.className='result-state '+tone;status.textContent=row?.result||'—';
    if(row?.ip)status.title='DNS-ответ: '+row.ip;
    body.append(name,status);box.append(dot,body);root.append(box);
  }
}
async function perform(task){try{return await task();}catch(e){notify(e.message||String(e));throw e;}}
async function refresh(){try{updateStatus(await request('status'));}catch(e){$('status-desc').textContent=android?'Не отвечает Android-модуль. Перезапустите приложение.':'Локальный сервер не отвечает. Запустите node server.js';}}
function withBusy(fn){return async()=>{try{await fn();}catch{}};}
async function select(set){
  if(set===app.selected)return;
  await perform(async()=>{const data=await request('select',{set});app.check=null;updateStatus(data);$('best-note').textContent='';});
}
async function check(){
  app.probeBusy=true;render();$('best-note').textContent='';
  try{const selected=app.selected;const result=await perform(()=>request('probe',{set:selected}));app.check=result;}
  finally{app.probeBusy=false;render();}
}
async function findBest(){
  app.probeBusy=true;render();$('best-note').textContent='';
  try{
    const result=await perform(()=>request('best',{}));app.selected=result.selected;app.check=result.chosen;$('best-note').textContent=result.note;render();
  }finally{app.probeBusy=false;render();}
}
async function toggle(){
  if(!app.active&&!confirm(android?'Приложение запросит root у менеджера su, если он доступен. Иначе Android предложит создать локальный DNS-VPN. Продолжить?':'Для применения DNS нужны root-права. Продолжить?'))return;
  const target=!app.active;app.systemBusy=true;render();
  try{
    const s=await perform(()=>request('toggle',{on:target}));updateStatus(s);
    if(target)await check();
  }finally{app.systemBusy=false;render();}
}
async function rootCheck(){
  $('root-detail').textContent='Проверяем доступность su…';
  const result=await perform(()=>request('root-check',{}));
  app.rootChecked=true;app.root=result.available;
  $('root-indicator').className='state-dot '+(result.available?'ok':'bad');
  $('root-detail').textContent=result.details;
}
async function copyDns(){
  const text=app.services[app.selected].v4.join('\n');
  try{await navigator.clipboard.writeText(text);notify('Оба DNS-адреса скопированы');}
  catch{notify('Адреса: '+text.replace('\n',', '));}
}
async function checkUpdate(){try{const r=await request('update');if(r.newer){const link=$('update-link');link.href=r.url;link.textContent='Новая версия Android: '+r.latest+' ↗';link.classList.add('update');link.title='Релиз Android APK';}}catch{}}
document.addEventListener('DOMContentLoaded',async()=>{
  document.querySelectorAll('.service').forEach(b=>b.addEventListener('click',withBusy(()=>select(Number(b.dataset.set)))));
  $('check').addEventListener('click',withBusy(check));
  $('best').addEventListener('click',withBusy(findBest));
  $('toggle').addEventListener('click',withBusy(toggle));
  $('root-check').addEventListener('click',withBusy(rootCheck));
  $('verify').addEventListener('click',withBusy(async()=>{
    $('verify-result').textContent='Проверяем через системный резолвер Android…';
    const result=await perform(()=>request('verify',{}));
    $('verify-result').textContent=result.note;await refresh();
  }));
  $('copy-dns').addEventListener('click',withBusy(copyDns));
  $('settings').addEventListener('click',withBusy(async()=>{await perform(()=>request('open-settings',{}));notify('Открыты сетевые настройки Android');}));
  await refresh();void checkUpdate();
  setInterval(()=>{if(!app.systemBusy&&!app.probeBusy)void refresh();},7000);
  if(!android&&'serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});
  if(android)document.querySelectorAll('a[href^="http"]').forEach(a=>a.addEventListener('click',e=>{e.preventDefault();window.HBAndroid.open(a.href);}));
});
