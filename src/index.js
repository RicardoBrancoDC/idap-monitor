import { XMLParser } from "fast-xml-parser";

const REPO = "https://idapcap.mdr.gov.br/";
const BASE_ALGORITHM_VERSION = "1.1";
const CAP_PARSER_VERSION = 5;

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

const parser = new XMLParser({
  ignoreAttributes: false,
  removeNSPrefix: true,
  trimValues: true,
  parseTagValue: false,
  isArray: (name) => ["info","parameter","area"].includes(name)
});

function json(data, status=200){
  return new Response(JSON.stringify(data), {status, headers:{"content-type":"application/json; charset=utf-8"}});
}
function normalize(s=""){
  return String(s).toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g,"");
}
function asArray(v){return v==null?[]:(Array.isArray(v)?v:[v])}
function firstText(v){
  if(v==null)return "";
  if(typeof v==="string"||typeof v==="number")return String(v).trim();
  if(Array.isArray(v))return firstText(v[0]);
  if(typeof v==="object"&&"#text" in v)return firstText(v["#text"]);
  return "";
}
function findAlertObject(obj){
  if(!obj||typeof obj!=="object")return null;
  if("identifier" in obj && "sender" in obj && "info" in obj)return obj;
  for(const v of Object.values(obj)){
    if(v&&typeof v==="object"){
      if(Array.isArray(v)){for(const x of v){const r=findAlertObject(x);if(r)return r}}
      else {const r=findAlertObject(v);if(r)return r}
    }
  }
  return null;
}
function collectKey(obj,key,out=[]){
  if(!obj||typeof obj!=="object")return out;
  if(Object.prototype.hasOwnProperty.call(obj,key))for(const x of asArray(obj[key]))out.push(firstText(x));
  for(const v of Object.values(obj)){
    if(v&&typeof v==="object"){
      if(Array.isArray(v))for(const x of v)collectKey(x,key,out);
      else collectKey(v,key,out);
    }
  }
  return out;
}
function extractAlertId(doc){
  const vals=collectKey(doc,"id").filter(Boolean);
  const exact=vals.find(v=>/^\s*\d+\s*\/\s*\d{4}\s*$/.test(v));
  if(exact){const m=exact.match(/(\d+)\s*\/\s*(\d{4})/);return `${m[1]}/${m[2]}`}
  return vals.find(v=>!/^https?:\/\//i.test(v))||"";
}
function chooseInfo(alert){
  const infos=asArray(alert?.info);
  if(!infos.length)return {};
  return infos.find(i=>normalize(firstText(i?.language)).startsWith("pt"))||infos[0];
}
function parameters(info){
  const out={};
  for(const p of asArray(info?.parameter)){
    const k=firstText(p?.valueName).toLowerCase();
    if(k)out[k]=firstText(p?.value);
  }
  return out;
}
function paramLike(params, needles){
  for(const [k,v] of Object.entries(params))if(needles.some(n=>k.includes(n)))return v;
  return "";
}
function inferLevel(severity,urgency,params){
  const explicit=paramLike(params,["nivel","nível","level"]);
  if(explicit){
    const n=normalize(explicit);
    for(const [k,l] of [["extremo","Extremo"],["severo","Severo"],["alto","Alto"],["moderado","Moderado"],["baixo","Baixo"]])if(n.includes(k))return l;
  }
  const sev=normalize(severity), urg=normalize(urgency);
  if(sev==="extreme")return urg==="immediate"?"Extremo":"Severo";
  if(sev==="severe")return "Alto";
  if(sev==="moderate")return "Moderado";
  if(sev==="minor")return "Baixo";
  return severity||"Não identificado";
}
function vigLimit(level){return {Extremo:120,Severo:240,Alto:4320,Moderado:4320,Baixo:4320}[level]??null}
function fmtDuration(minutes){
  if(minutes==null||Number.isNaN(minutes))return "-";
  const sign=minutes<0?"-":""; minutes=Math.abs(Math.round(minutes));
  const h=Math.floor(minutes/60),m=minutes%60;
  return h&&m?`${sign}${h}h${String(m).padStart(2,"0")}`:h?`${sign}${h}h`:`${sign}${m}min`;
}
function parseDate(s){if(!s)return null;const d=new Date(s);return Number.isNaN(d.getTime())?null:d}
function evaluateVigencia(level,sent,effective,expires){
  const start=parseDate(effective)||parseDate(sent), end=parseDate(expires), lim=vigLimit(level);
  if(!start||!end)return {minutes:null,status:"revisao",note:"Não foi possível calcular a vigência porque faltam data inicial ou expiração."};
  const minutes=Math.round((end-start)/60000);
  if(minutes<0)return {minutes,status:"nao_conforme",note:"A data de expiração é anterior ao início da vigência."};
  if(lim==null)return {minutes,status:"revisao",note:"Nível não reconhecido para aplicação automática do limite de vigência."};
  if(minutes<=lim)return {minutes,status:"conforme",note:`Vigência de ${fmtDuration(minutes)}, dentro do limite de ${fmtDuration(lim)} para o nível ${level}.`};
  return {minutes,status:"nao_conforme",note:`Vigência de ${fmtDuration(minutes)}, acima do limite de ${fmtDuration(lim)} para o nível ${level}.`};
}
async function termBank(env){
  const rows=await env.DB.prepare("SELECT category, normalized_term FROM custom_terms WHERE active=1 ORDER BY id").all();
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
async function algorithmVersion(env){
  const r=await env.DB.prepare("SELECT value FROM settings WHERE key='ruleset_revision'").first();
  return `${BASE_ALGORITHM_VERSION}-r${Number(r?.value||0)}`;
}
function formatDate(s){
  const d=parseDate(s); if(!d)return s||"-";
  return new Intl.DateTimeFormat("pt-BR",{timeZone:"America/Sao_Paulo",day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit",hour12:false}).format(d).replace(",","");
}
function getAreaDesc(info){
  for(const a of asArray(info?.area)){const x=firstText(a?.areaDesc);if(x)return x}
  return "";
}
async function parseCAP(env,name,fileDate,uf,xmlText){
  const doc=parser.parse(xmlText);
  const alert=findAlertObject(doc)||doc;
  const info=chooseInfo(alert);
  const params=parameters(info);
  const sender=firstText(alert?.sender);
  const senderName=firstText(info?.senderName);
  const sent=firstText(alert?.sent);
  const effective=firstText(info?.effective);
  const expires=firstText(info?.expires);
  const severity=firstText(info?.severity);
  const urgency=firstText(info?.urgency);
  const certainty=firstText(info?.certainty);
  const level=inferLevel(severity,urgency,params);
  const headline=firstText(info?.headline)||firstText(info?.description);
  const vig=evaluateVigencia(level,sent,effective,expires);
  const bank=await termBank(env);
  const txt=evaluateText(level,headline,bank);
  const version=await algorithmVersion(env);
  const sourceUrl=REPO+encodeURIComponent(name);
  return {
    file:name,file_date:fileDate,uf,source_url:sourceUrl,alert_id:extractAlertId(doc),
    identifier:firstText(alert?.identifier),sender,sender_name:senderName,
    institution:senderName||paramLike(params,["institu","orgao","órgão","emissor"])||sender||"Não identificado",
    sent,effective,expires,event:firstText(info?.event),severity,urgency,certainty,level,headline,
    area_desc:getAreaDesc(info),duration_minutes:vig.minutes,vigencia_auto:vig.status,vigencia_note:vig.note,
    texto_auto:txt.status,texto_note:txt.note,algorithm_version:version,parser_version:CAP_PARSER_VERSION,
    fetched_at:new Date().toISOString()
  };
}
async function saveAlert(env,a){
  await env.DB.prepare(`INSERT INTO alerts(
    file,file_date,uf,source_url,alert_id,identifier,sender,sender_name,institution,sent,effective,expires,
    event,severity,urgency,certainty,level,headline,area_desc,duration_minutes,vigencia_auto,vigencia_note,
    texto_auto,texto_note,algorithm_version,parser_version,fetched_at
  ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  ON CONFLICT(file) DO UPDATE SET
    file_date=excluded.file_date,uf=excluded.uf,source_url=excluded.source_url,alert_id=excluded.alert_id,
    identifier=excluded.identifier,sender=excluded.sender,sender_name=excluded.sender_name,institution=excluded.institution,
    sent=excluded.sent,effective=excluded.effective,expires=excluded.expires,event=excluded.event,severity=excluded.severity,
    urgency=excluded.urgency,certainty=excluded.certainty,level=excluded.level,headline=excluded.headline,area_desc=excluded.area_desc,
    duration_minutes=excluded.duration_minutes,vigencia_auto=excluded.vigencia_auto,vigencia_note=excluded.vigencia_note,
    texto_auto=excluded.texto_auto,texto_note=excluded.texto_note,algorithm_version=excluded.algorithm_version,
    parser_version=excluded.parser_version,fetched_at=excluded.fetched_at`).bind(
      a.file,a.file_date,a.uf,a.source_url,a.alert_id,a.identifier,a.sender,a.sender_name,a.institution,a.sent,a.effective,a.expires,
      a.event,a.severity,a.urgency,a.certainty,a.level,a.headline,a.area_desc,a.duration_minutes,a.vigencia_auto,a.vigencia_note,
      a.texto_auto,a.texto_note,a.algorithm_version,a.parser_version,a.fetched_at
    ).run();
  await env.DB.prepare(`INSERT OR IGNORE INTO evaluation_history(file,dimension,algorithm_version,result,note,evaluated_at) VALUES(?,?,?,?,?,?)`)
    .bind(a.file,"vigencia",a.algorithm_version,a.vigencia_auto,a.vigencia_note,a.fetched_at).run();
  await env.DB.prepare(`INSERT OR IGNORE INTO evaluation_history(file,dimension,algorithm_version,result,note,evaluated_at) VALUES(?,?,?,?,?,?)`)
    .bind(a.file,"texto",a.algorithm_version,a.texto_auto,a.texto_note,a.fetched_at).run();
}
async function ingest(env,body){
  const files=Array.isArray(body?.files)?body.files:[];
  if(files.length>5)return json({error:"Envie no máximo 5 XML por lote."},400);
  let downloaded=0,cached=0;const errors=[];
  for(const item of files){
    const name=String(item?.name||"");
    if(!/^\d+.*\d{8}-[A-Z]{2}\.xml$/i.test(name)){errors.push({file:name,error:"Nome de arquivo inválido."});continue}
    const current=await env.DB.prepare("SELECT parser_version FROM alerts WHERE file=?").bind(name).first();
    if(Number(current?.parser_version||0)>=CAP_PARSER_VERSION){cached++;continue}
    try{
      const res=await fetch(REPO+encodeURIComponent(name),{headers:{"user-agent":"IDAP-Monitor-Cloudflare/5"}});
      if(!res.ok)throw new Error(`HTTP ${res.status}`);
      const xml=await res.text();
      const a=await parseCAP(env,name,String(item.date||""),String(item.uf||"").toUpperCase(),xml);
      await saveAlert(env,a); downloaded++;
    }catch(e){errors.push({file:name,error:String(e?.message||e)})}
  }
  return json({downloaded,cached,errors});
}
async function alerts(env,url){
  const q=url.searchParams;
  const from=q.get("from")||"",to=q.get("to")||"";
  if(!/^\d{4}-\d{2}-\d{2}$/.test(from)||!/^\d{4}-\d{2}-\d{2}$/.test(to))return json({error:"Período inválido."},400);
  let sql=`SELECT a.*,r.vig_choice,r.vig_correct_value,r.vig_reason,r.txt_choice,r.txt_correct_value,r.txt_reason,
    r.reviewer,r.algorithm_version_at_review,r.reviewed_at,r.vig_validated_value,r.txt_validated_value
    FROM alerts a LEFT JOIN reviews r ON r.file=a.file WHERE a.file_date>=? AND a.file_date<=?`;
  const binds=[from,to];
  if(q.get("uf")&&q.get("uf")!=="all"){sql+=" AND a.uf=?";binds.push(q.get("uf"))}
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
  const pieces=String(headline||"").split(/[.;!?]+/).map(s=>s.trim()).filter(Boolean);
  return pieces.filter(p=>{const n=p.split(/\s+/).length;return n>=2&&n<=14}).slice(0,4);
}
async function learning(env){
  const reviewed=await env.DB.prepare("SELECT COUNT(*) n FROM reviews WHERE reviewed_at IS NOT NULL").first();
  const rows=await env.DB.prepare(`SELECT a.file,a.headline,a.level,a.uf,a.texto_auto,a.algorithm_version,
    r.txt_validated_value,r.txt_reason,r.reviewed_at
    FROM alerts a JOIN reviews r ON r.file=a.file WHERE r.reviewed_at IS NOT NULL ORDER BY r.reviewed_at DESC`).all();
  let agree=0,corr=0;const divergences=[],counts=new Map();
  for(const r of rows.results||[]){
    if(r.texto_auto===r.txt_validated_value)agree++; else{
      corr++;divergences.push({file:r.file,headline:r.headline,level:r.level,uf:r.uf,auto_result:r.texto_auto,human_result:r.txt_validated_value,reason:r.txt_reason,algorithm_version:r.algorithm_version});
      if(r.txt_validated_value==="conforme"){
        for(const p of candidatePhrases(r.headline)){const k=normalize(p);const x=counts.get(k)||{phrase:p,count:0,examples:[]};x.count++;if(x.examples.length<3)x.examples.push({headline:r.headline,file:r.file});counts.set(k,x)}
      }
    }
  }
  const custom=(await env.DB.prepare("SELECT * FROM custom_terms ORDER BY id DESC").all()).results||[];
  const activeNorm=new Set(custom.filter(x=>x.active).map(x=>x.normalized_term));
  const candidates=[...counts.values()].filter(x=>!activeNorm.has(normalize(x.phrase))).sort((a,b)=>b.count-a.count).slice(0,20);
  const version=await algorithmVersion(env);
  const total=agree+corr;
  return json({metrics:{reviewed:Number(reviewed?.n||0),text_agreements:agree,text_corrections:corr,text_agreement_rate:total?Math.round(agree*1000/total)/10:0,algorithm_version:version},divergences,candidates,custom_terms:custom});
}
async function learningTerm(env,body){
  const action=body?.action;
  if(action==="approve"){
    const term=String(body.term||"").trim(),category=String(body.category||"");
    if(!term||!["risk","action","generic","extreme"].includes(category))return json({error:"Expressão ou categoria inválida."},400);
    const norm=normalize(term), existing=await env.DB.prepare("SELECT id,active FROM custom_terms WHERE normalized_term=? AND category=?").bind(norm,category).first();
    if(existing?.active)return json({ok:true,already_active:true});
    if(existing)await env.DB.prepare("UPDATE custom_terms SET term=?,active=1,approved_by=?,approved_at=? WHERE id=?").bind(term,String(body.reviewer||"Revisor"),new Date().toISOString(),existing.id).run();
    else await env.DB.prepare("INSERT INTO custom_terms(term,normalized_term,category,source,approved_by,approved_at,active) VALUES(?,?,?,?,?,?,1)")
      .bind(term,norm,category,"human_learning",String(body.reviewer||"Revisor"),new Date().toISOString()).run();
  }else if(action==="disable"){
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
  async fetch(request, env){
    const url=new URL(request.url);
    try{
      if(url.pathname==="/healthz")return json({ok:true});
      if(url.pathname==="/api/index"){
        const r=await fetch(REPO,{headers:{"user-agent":"IDAP-Monitor-Cloudflare/5"}});
        return new Response(r.body,{status:r.status,headers:{"content-type":"text/html; charset=utf-8","cache-control":"public, max-age=300"}});
      }
      if(url.pathname==="/api/ingest"&&request.method==="POST")return ingest(env,await request.json());
      if(url.pathname==="/api/alerts"&&request.method==="GET")return alerts(env,url);
      if(url.pathname==="/api/review"&&request.method==="POST")return review(env,await request.json());
      if(url.pathname==="/api/learning"&&request.method==="GET")return learning(env);
      if(url.pathname==="/api/learning/term"&&request.method==="POST")return learningTerm(env,await request.json());
      if(url.pathname==="/api/reprocess"&&request.method==="POST")return reprocess(env,await request.json());
      return env.ASSETS.fetch(request);
    }catch(e){
      return json({error:String(e?.message||e)},500);
    }
  }
};