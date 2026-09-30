const BASE_ALGORITHM_VERSION = "1.1";

const RISK_TERMS = [
  "chuva","alag","inund","enxurr","desliz","escorreg","tempestad","vendaval","vento","granizo","raio",
  "umidade","seca","estiagem","calor","frio","geada","incend","queimada","ressaca","mare","enchente",
  "transbord","rompimento","ciclone","tornado","nevoeiro","onda","avalanche","desastre","risco"
];
const ACTION_TERMS = [
  "evite","nao atravesse","procure","busque","saia","evacue","abrigue","afaste","mantenha-se","mantenha se",
  "retire","recolha","proteja-se","proteja se","desligue","permaneca","dirija-se","dirija se","hidrate",
  "feche","abandone","suba","desloque"
];
const GENERIC_ACTIONS = ["fique atento","mantenha os cuidados","redobre a atencao","acompanhe as orientacoes","atencao"];
const EXTREME_ACTIONS = ["evacue","evacuacao","saia imediatamente","busque abrigo","procure abrigo","local seguro","area segura","abrigue-se","abrigue se"];

function json(data,status=200){
  return new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8"}});
}
function normalize(s=""){
  return String(s).toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g,"");
}
function vigLimit(level){
  return {Extremo:120,Severo:240,Alto:4320,Moderado:4320,Baixo:4320}[level]??null;
}
function fmtDuration(minutes){
  if(minutes==null||Number.isNaN(Number(minutes)))return "-";
  let n=Math.round(Number(minutes));const sign=n<0?"-":"";n=Math.abs(n);
  const h=Math.floor(n/60),m=n%60;
  return h&&m?`${sign}${h}h${String(m).padStart(2,"0")}`:h?`${sign}${h}h`:`${sign}${m}min`;
}
function formatDate(s){
  if(!s)return "-";
  const d=new Date(s);if(Number.isNaN(d.getTime()))return s;
  return new Intl.DateTimeFormat("pt-BR",{timeZone:"America/Sao_Paulo",day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit",hour12:false}).format(d).replace(",","");
}
async function algorithmVersion(env){
  const r=await env.DB.prepare("SELECT value FROM settings WHERE key='ruleset_revision'").first();
  return `${BASE_ALGORITHM_VERSION}-r${Number(r?.value||0)}`;
}
async function termBank(env){
  const rows=await env.DB.prepare("SELECT category,normalized_term FROM custom_terms WHERE active=1 ORDER BY id").all();
  const bank={risk:[...RISK_TERMS],action:[...ACTION_TERMS],generic:[...GENERIC_ACTIONS],extreme:[...EXTREME_ACTIONS]};
  for(const r of rows.results||[])if(bank[r.category]&&!bank[r.category].includes(r.normalized_term))bank[r.category].push(r.normalized_term);
  return bank;
}
function evaluateText(level,headline,bank){
  const t=normalize(headline);
  if(!t.trim())return {status:"nao_conforme",note:"Mensagem principal vazia."};
  const hasRisk=bank.risk.some(x=>t.includes(normalize(x)));
  const hasAction=bank.action.some(x=>t.includes(normalize(x)));
  const hasGeneric=bank.generic.some(x=>t.includes(normalize(x)));
  const hasExtreme=bank.extreme.some(x=>t.includes(normalize(x)));
  if(!hasRisk)return {status:"revisao",note:"Não foi possível identificar com segurança o risco ou evento no texto."};
  if(level==="Extremo"){
    if(!hasExtreme)return {status:"nao_conforme",note:"O texto identifica o risco, mas não apresenta ação imediata de evacuação ou abrigamento compatível com alerta Extremo."};
    return {status:"conforme",note:"Risco identificado e orientação imediata de autoproteção encontrada."};
  }
  if(hasAction)return {status:"conforme",note:"Risco identificado e orientação concreta de autoproteção encontrada."};
  if(hasGeneric)return {status:"revisao",note:"Risco identificado, mas a orientação encontrada é genérica e deve ser confirmada por revisão humana."};
  return {status:"nao_conforme",note:"O texto identifica o risco, mas não foi encontrada recomendação de autoproteção."};
}
async function alerts(env,url){
  const q=url.searchParams;
  const from=q.get("from")||"",to=q.get("to")||"";
  if(!/^\d{4}-\d{2}-\d{2}$/.test(from)||!/^\d{4}-\d{2}-\d{2}$/.test(to))return json({error:"Período inválido."},400);
  let sql=`SELECT a.*,r.vig_choice,r.vig_correct_value,r.vig_reason,r.txt_choice,r.txt_correct_value,r.txt_reason,
    r.reviewer,r.algorithm_version_at_review,r.reviewed_at,r.vig_validated_value,r.txt_validated_value
    FROM alerts a LEFT JOIN reviews r ON r.file=a.file WHERE a.file_date>=? AND a.file_date<=?`;
  const binds=[from,to];
  if(q.get("uf")&&q.get("uf")!=="all"){sql+=" AND instr(','||replace(coalesce(a.uf,''),' ','')||',', ','||?||',')>0";binds.push(String(q.get("uf")).toUpperCase())}
  if(q.get("level")&&q.get("level")!=="all"){sql+=" AND a.level=?";binds.push(q.get("level"))}
  sql+=" ORDER BY COALESCE(NULLIF(a.sent,''),a.file_date) DESC,a.file DESC";
  const rs=await env.DB.prepare(sql).bind(...binds).all();
  const out=[];
  for(const row of rs.results||[]){
    const reviewed=!!row.reviewed_at;
    const vigFinal=reviewed&&row.vig_validated_value?row.vig_validated_value:row.vigencia_auto;
    const txtFinal=reviewed&&row.txt_validated_value?row.txt_validated_value:row.texto_auto;
    if(q.get("review")==="pending"&&reviewed)continue;
    if(q.get("review")==="reviewed"&&!reviewed)continue;
    if(q.get("vigencia")&&q.get("vigencia")!=="all"&&vigFinal!==q.get("vigencia"))continue;
    if(q.get("texto")&&q.get("texto")!=="all"&&txtFinal!==q.get("texto"))continue;
    const hasNon=vigFinal==="nao_conforme"||txtFinal==="nao_conforme";
    const ok=vigFinal==="conforme"&&txtFinal==="conforme";
    const rev=vigFinal==="revisao"||txtFinal==="revisao";
    if(q.get("result")==="nonconform"&&!hasNon)continue;
    if(q.get("result")==="ok"&&!ok)continue;
    if(q.get("result")==="review"&&!rev)continue;
    out.push({...row,reviewed,vigencia_final:vigFinal,texto_final:txtFinal,
      sent_display:formatDate(row.sent),effective_display:formatDate(row.effective),expires_display:formatDate(row.expires),
      duration_display:fmtDuration(row.duration_minutes),limit_display:fmtDuration(vigLimit(row.level))});
  }
  return json({alerts:out});
}
async function status(env){
  const rs=await env.DB.prepare("SELECT key,value FROM settings WHERE key LIKE 'last_sync_%'").all();
  const out={};for(const r of rs.results||[])out[r.key]=r.value;
  return json({
    last_sync_at:out.last_sync_at||"",
    last_sync_new:Number(out.last_sync_new||0),
    last_sync_errors:Number(out.last_sync_errors||0),
    last_sync_checked:Number(out.last_sync_checked||0),
    last_sync_lookback_days:Number(out.last_sync_lookback_days||0)
  });
}
async function review(env,body){
  if(!body?.file||!body?.vig_choice||!body?.txt_choice)return json({error:"Dados de revisão incompletos."},400);
  if(body.vig_choice==="no"&&!String(body.vig_reason||"").trim())return json({error:"Informe o motivo da correção da vigência."},400);
  if(body.txt_choice==="no"&&!String(body.txt_reason||"").trim())return json({error:"Informe o motivo da correção textual."},400);
  const a=await env.DB.prepare("SELECT vigencia_auto,texto_auto,algorithm_version FROM alerts WHERE file=?").bind(body.file).first();
  if(!a)return json({error:"Alerta não encontrado."},404);
  const vv=body.vig_choice==="yes"?a.vigencia_auto:String(body.vig_correct_value||"");
  const tv=body.txt_choice==="yes"?a.texto_auto:String(body.txt_correct_value||"");
  const now=new Date().toISOString();
  await env.DB.prepare(`INSERT INTO reviews(file,vig_choice,vig_correct_value,vig_reason,txt_choice,txt_correct_value,txt_reason,
    reviewer,algorithm_version_at_review,reviewed_at,vig_validated_value,txt_validated_value)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(file) DO UPDATE SET vig_choice=excluded.vig_choice,vig_correct_value=excluded.vig_correct_value,
    vig_reason=excluded.vig_reason,txt_choice=excluded.txt_choice,txt_correct_value=excluded.txt_correct_value,
    txt_reason=excluded.txt_reason,reviewer=excluded.reviewer,algorithm_version_at_review=excluded.algorithm_version_at_review,
    reviewed_at=excluded.reviewed_at,vig_validated_value=excluded.vig_validated_value,txt_validated_value=excluded.txt_validated_value`)
    .bind(body.file,body.vig_choice,body.vig_correct_value||"",String(body.vig_reason||"").trim(),body.txt_choice,
      body.txt_correct_value||"",String(body.txt_reason||"").trim(),String(body.reviewer||"").trim()||"Revisor",
      a.algorithm_version||BASE_ALGORITHM_VERSION,now,vv,tv).run();
  return json({ok:true});
}
function candidatePhrases(headline){
  return String(headline||"").split(/[.;!?]+/).map(s=>s.trim()).filter(Boolean)
    .filter(p=>{const n=p.split(/\s+/).length;return n>=2&&n<=14}).slice(0,4);
}
async function learning(env){
  const reviewed=await env.DB.prepare("SELECT COUNT(*) n FROM reviews WHERE reviewed_at IS NOT NULL").first();
  const rows=await env.DB.prepare(`SELECT a.file,a.headline,a.level,a.uf,a.texto_auto,a.algorithm_version,
    r.txt_validated_value,r.txt_reason,r.reviewed_at
    FROM alerts a JOIN reviews r ON r.file=a.file WHERE r.reviewed_at IS NOT NULL ORDER BY r.reviewed_at DESC`).all();
  let agree=0,corr=0;const divergences=[],counts=new Map();
  for(const r of rows.results||[]){
    if(r.texto_auto===r.txt_validated_value)agree++;else{
      corr++;divergences.push({file:r.file,headline:r.headline,level:r.level,uf:r.uf,auto_result:r.texto_auto,human_result:r.txt_validated_value,reason:r.txt_reason,algorithm_version:r.algorithm_version});
      if(r.txt_validated_value==="conforme")for(const p of candidatePhrases(r.headline)){
        const k=normalize(p),x=counts.get(k)||{phrase:p,count:0,examples:[]};x.count++;if(x.examples.length<3)x.examples.push({headline:r.headline,file:r.file});counts.set(k,x)
      }
    }
  }
  const custom=(await env.DB.prepare("SELECT * FROM custom_terms ORDER BY id DESC").all()).results||[];
  const activeNorm=new Set(custom.filter(x=>x.active).map(x=>x.normalized_term));
  const candidates=[...counts.values()].filter(x=>!activeNorm.has(normalize(x.phrase))).sort((a,b)=>b.count-a.count).slice(0,20);
  const version=await algorithmVersion(env),total=agree+corr;
  return json({metrics:{reviewed:Number(reviewed?.n||0),text_agreements:agree,text_corrections:corr,text_agreement_rate:total?Math.round(agree*1000/total)/10:0,algorithm_version:version},divergences,candidates,custom_terms:custom});
}
async function learningTerm(env,body){
  if(body?.action==="approve"){
    const term=String(body.term||"").trim(),category=String(body.category||"");
    if(!term||!["risk","action","generic","extreme"].includes(category))return json({error:"Expressão ou categoria inválida."},400);
    const norm=normalize(term),existing=await env.DB.prepare("SELECT id,active FROM custom_terms WHERE normalized_term=? AND category=?").bind(norm,category).first();
    if(existing?.active)return json({ok:true,already_active:true});
    if(existing)await env.DB.prepare("UPDATE custom_terms SET term=?,active=1,approved_by=?,approved_at=? WHERE id=?").bind(term,String(body.reviewer||"Revisor"),new Date().toISOString(),existing.id).run();
    else await env.DB.prepare("INSERT INTO custom_terms(term,normalized_term,category,source,approved_by,approved_at,active) VALUES(?,?,?,?,?,?,1)")
      .bind(term,norm,category,"human_learning",String(body.reviewer||"Revisor"),new Date().toISOString()).run();
  }else if(body?.action==="disable"){
    await env.DB.prepare("UPDATE custom_terms SET active=0 WHERE id=?").bind(Number(body.id)).run();
  }else return json({error:"Ação inválida."},400);
  const row=await env.DB.prepare("SELECT value FROM settings WHERE key='ruleset_revision'").first();
  const rev=Number(row?.value||0)+1;
  await env.DB.prepare("INSERT INTO settings(key,value) VALUES('ruleset_revision',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(String(rev)).run();
  return json({ok:true,revision:rev});
}
async function reprocess(env,body){
  const cursor=String(body?.cursor||""),limit=Math.min(Math.max(Number(body?.limit||20),1),25);
  const rs=await env.DB.prepare("SELECT file,level,headline FROM alerts WHERE file>? ORDER BY file LIMIT ?").bind(cursor,limit).all();
  const bank=await termBank(env),version=await algorithmVersion(env);let changed=0,processed=0,next="";
  for(const a of rs.results||[]){
    const txt=evaluateText(a.level,a.headline,bank);
    const old=await env.DB.prepare("SELECT texto_auto FROM alerts WHERE file=?").bind(a.file).first();
    if(old?.texto_auto!==txt.status)changed++;
    await env.DB.prepare("UPDATE alerts SET texto_auto=?,texto_note=?,algorithm_version=? WHERE file=?").bind(txt.status,txt.note,version,a.file).run();
    await env.DB.prepare("INSERT OR IGNORE INTO evaluation_history(file,dimension,algorithm_version,result,note,evaluated_at) VALUES(?,?,?,?,?,?)")
      .bind(a.file,"texto",version,txt.status,txt.note,new Date().toISOString()).run();
    processed++;next=a.file;
  }
  if((rs.results||[]).length<limit)next="";
  return json({processed,changed,next_cursor:next});
}

export default {
  async fetch(request,env){
    const url=new URL(request.url);
    try{
      if(url.pathname==="/healthz")return json({ok:true});
      if(url.pathname==="/api/alerts"&&request.method==="GET")return alerts(env,url);
      if(url.pathname==="/api/status"&&request.method==="GET")return status(env);
      if(url.pathname==="/api/review"&&request.method==="POST")return review(env,await request.json());
      if(url.pathname==="/api/learning"&&request.method==="GET")return learning(env);
      if(url.pathname==="/api/learning/term"&&request.method==="POST")return learningTerm(env,await request.json());
      if(url.pathname==="/api/reprocess"&&request.method==="POST")return reprocess(env,await request.json());
      return env.ASSETS.fetch(request);
    }catch(e){return json({error:String(e?.message||e)},500)}
  }
};