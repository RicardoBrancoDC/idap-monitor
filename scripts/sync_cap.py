#!/usr/bin/env python3
import argparse
import concurrent.futures
import datetime as dt
import json
import os
import re
import sys
import urllib.parse
import warnings
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from zoneinfo import ZoneInfo

import requests
from requests.exceptions import SSLError

REPO = "https://idapcap.mdr.gov.br/"
PARSER_VERSION = 6
BASE_ALGORITHM_VERSION = "1.1"
MAX_LOOKBACK = 90
FETCH_WORKERS = 6

RISK_TERMS = [
    "chuva","alag","inund","enxurr","desliz","escorreg","tempestad","vendaval","vento","granizo","raio",
    "umidade","seca","estiagem","calor","frio","geada","incend","queimada","ressaca","mare","enchente",
    "transbord","rompimento","ciclone","tornado","nevoeiro","onda","avalanche","desastre","risco"
]
ACTION_TERMS = [
    "evite","nao atravesse","procure","busque","saia","evacue","abrigue","afaste","mantenha-se","mantenha se",
    "retire","recolha","proteja-se","proteja se","desligue","permaneca","dirija-se","dirija se","hidrate",
    "feche","abandone","suba","desloque"
]
GENERIC_ACTIONS = ["fique atento","mantenha os cuidados","redobre a atencao","acompanhe as orientacoes","atencao"]
EXTREME_ACTIONS = ["evacue","evacuacao","saia imediatamente","busque abrigo","procure abrigo","local seguro","area segura","abrigue-se","abrigue se"]

FILE_RE = re.compile(r"(?P<date>\d{8})-(?P<uf>[A-Z]{2})\.xml$", re.I)
ALERT_ID_RE = re.compile(r"^\s*(\d+)\s*/\s*(\d{4})\s*$")


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


def need_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Variável obrigatória ausente: {name}")
    return value


ACCOUNT_ID = need_env("CLOUDFLARE_ACCOUNT_ID")
API_TOKEN = need_env("CLOUDFLARE_API_TOKEN")
DATABASE_ID = os.environ.get("D1_DATABASE_ID", "410a7557-5a1d-442a-a0ac-7e9743622231").strip()
D1_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/d1/database/{DATABASE_ID}/query"
D1_HEADERS = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}


def normalize(s):
    import unicodedata
    s = (s or "").lower()
    s = unicodedata.normalize("NFD", s)
    return "".join(c for c in s if unicodedata.category(c) != "Mn")


def d1_call(payload):
    r = requests.post(D1_URL, headers=D1_HEADERS, json=payload, timeout=90)
    try:
        data = r.json()
    except Exception:
        raise RuntimeError(f"D1 retornou HTTP {r.status_code}: {r.text[:500]}")
    if not r.ok or not data.get("success"):
        raise RuntimeError(f"Erro D1: {json.dumps(data.get('errors') or data, ensure_ascii=False)[:1000]}")
    return data.get("result") or []


def d1_select(sql, params=None):
    result = d1_call({"sql": sql, "params": params or []})
    if not result:
        return []
    return result[0].get("results") or []


def d1_batch(statements):
    if not statements:
        return []
    return d1_call({"batch": statements})


def safe_get(url, timeout=40):
    headers = {"User-Agent": "IDAP-Monitor-GitHubSync/5.1"}
    try:
        return requests.get(url, headers=headers, timeout=timeout, verify=True)
    except SSLError:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        return requests.get(url, headers=headers, timeout=timeout, verify=False)


def list_candidates(start_date, end_date):
    r = safe_get(REPO, timeout=60)
    r.raise_for_status()
    p = LinkParser()
    p.feed(r.text)
    out, seen = [], set()
    for href in p.links:
        decoded = urllib.parse.unquote(href)
        name = decoded.rstrip("/").split("/")[-1]
        if name in seen or not name.lower().endswith(".xml"):
            continue
        seen.add(name)
        m = FILE_RE.search(name)
        if not m:
            continue
        try:
            file_date = dt.datetime.strptime(m.group("date"), "%d%m%Y").date()
        except ValueError:
            continue
        if not (start_date <= file_date <= end_date):
            continue
        out.append({
            "name": name,
            "url": urllib.parse.urljoin(REPO, href),
            "date": file_date.isoformat(),
            "uf": m.group("uf").upper()
        })
    out.sort(key=lambda x: (x["date"], x["name"]))
    return out, len(seen)


def lname(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def direct_text(parent, name):
    if parent is None:
        return ""
    for el in list(parent):
        if lname(el.tag) == name and el.text:
            return el.text.strip()
    return ""


def first_text(parent, name):
    if parent is None:
        return ""
    for el in parent.iter():
        if lname(el.tag) == name and el.text:
            return el.text.strip()
    return ""


def find_alert_root(root):
    if lname(root.tag) == "alert" and direct_text(root, "identifier"):
        return root
    for el in root.iter():
        if lname(el.tag) == "alert" and direct_text(el, "identifier"):
            return el
    return root


def choose_info(alert):
    infos = [el for el in list(alert) if lname(el.tag) == "info"]
    if not infos:
        infos = [el for el in alert.iter() if lname(el.tag) == "info"]
    if not infos:
        return alert
    for info in infos:
        if normalize(direct_text(info, "language")).startswith("pt"):
            return info
    return infos[0]


def parse_parameters(info):
    out = {}
    for par in info.iter():
        if lname(par.tag) != "parameter":
            continue
        k = direct_text(par, "valueName")
        v = direct_text(par, "value")
        if k:
            out[k.lower()] = v
    return out


def param_like(params, needles):
    for k, v in params.items():
        if any(n in k for n in needles):
            return v
    return ""


def extract_alert_id(root):
    for el in root.iter():
        if lname(el.tag) == "id" and el.text:
            m = ALERT_ID_RE.match(el.text.strip())
            if m:
                return f"{m.group(1)}/{m.group(2)}"
    for el in root.iter():
        if lname(el.tag) == "id" and el.text:
            value = el.text.strip()
            if value and not value.lower().startswith(("http://", "https://")):
                return value
    return ""


def infer_level(severity, urgency, params):
    explicit = param_like(params, ["nivel", "nível", "level"])
    if explicit:
        n = normalize(explicit)
        for key, label in [("extremo","Extremo"),("severo","Severo"),("alto","Alto"),("moderado","Moderado"),("baixo","Baixo")]:
            if key in n:
                return label
    sev, urg = normalize(severity), normalize(urgency)
    if sev == "extreme":
        return "Extremo" if urg == "immediate" else "Severo"
    if sev == "severe":
        return "Alto"
    if sev == "moderate":
        return "Moderado"
    if sev == "minor":
        return "Baixo"
    return severity or "Não identificado"


def parse_iso(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def fmt_duration(minutes):
    if minutes is None:
        return "-"
    sign = "-" if minutes < 0 else ""
    minutes = abs(int(minutes))
    h, m = divmod(minutes, 60)
    return f"{sign}{h}h{m:02d}" if h and m else (f"{sign}{h}h" if h else f"{sign}{m}min")


def vig_limit(level):
    return {"Extremo":120,"Severo":240,"Alto":4320,"Moderado":4320,"Baixo":4320}.get(level)


def evaluate_vigencia(level, sent, effective, expires):
    start = parse_iso(effective) or parse_iso(sent)
    end = parse_iso(expires)
    limit = vig_limit(level)
    if not start or not end:
        return None, "revisao", "Não foi possível calcular a vigência porque faltam data inicial ou expiração."
    minutes = int(round((end - start).total_seconds() / 60))
    if minutes < 0:
        return minutes, "nao_conforme", "A data de expiração é anterior ao início da vigência."
    if limit is None:
        return minutes, "revisao", "Nível não reconhecido para aplicação automática do limite de vigência."
    if minutes <= limit:
        return minutes, "conforme", f"Vigência de {fmt_duration(minutes)}, dentro do limite de {fmt_duration(limit)} para o nível {level}."
    return minutes, "nao_conforme", f"Vigência de {fmt_duration(minutes)}, acima do limite de {fmt_duration(limit)} para o nível {level}."


def load_rule_bank():
    rows = d1_select("SELECT category, normalized_term FROM custom_terms WHERE active=1 ORDER BY id")
    bank = {
        "risk": list(RISK_TERMS), "action": list(ACTION_TERMS),
        "generic": list(GENERIC_ACTIONS), "extreme": list(EXTREME_ACTIONS)
    }
    for r in rows:
        category, term = r.get("category"), r.get("normalized_term")
        if category in bank and term and term not in bank[category]:
            bank[category].append(term)
    revision = d1_select("SELECT value FROM settings WHERE key='ruleset_revision'")
    rev = int((revision[0].get("value") if revision else "0") or 0)
    return bank, f"{BASE_ALGORITHM_VERSION}-r{rev}"


def evaluate_text(level, headline, bank):
    t = normalize(headline)
    if not t.strip():
        return "nao_conforme", "Mensagem principal vazia."
    has_risk = any(normalize(x) in t for x in bank["risk"])
    has_action = any(normalize(x) in t for x in bank["action"])
    has_generic = any(normalize(x) in t for x in bank["generic"])
    has_extreme = any(normalize(x) in t for x in bank["extreme"])
    if not has_risk:
        return "revisao", "Não foi possível identificar com segurança o risco ou evento no texto."
    if level == "Extremo":
        if not has_extreme:
            return "nao_conforme", "O texto identifica o risco, mas não apresenta ação imediata de evacuação ou abrigamento compatível com alerta Extremo."
        return "conforme", "Risco identificado e orientação imediata de autoproteção encontrada."
    if has_action:
        return "conforme", "Risco identificado e orientação concreta de autoproteção encontrada."
    if has_generic:
        return "revisao", "Risco identificado, mas a orientação encontrada é genérica e deve ser confirmada por revisão humana."
    return "nao_conforme", "O texto identifica o risco, mas não foi encontrada recomendação de autoproteção."


def area_desc(info):
    for a in info.iter():
        if lname(a.tag) == "area":
            value = direct_text(a, "areaDesc") or first_text(a, "areaDesc")
            if value:
                return value
    return ""


def parse_cap(item, bank, algorithm_version):
    r = safe_get(item["url"], timeout=40)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    alert = find_alert_root(root)
    info = choose_info(alert)
    params = parse_parameters(info)
    sender = direct_text(alert, "sender") or first_text(alert, "sender")
    sender_name = direct_text(info, "senderName") or first_text(info, "senderName")
    sent = direct_text(alert, "sent") or first_text(alert, "sent")
    effective = direct_text(info, "effective") or first_text(info, "effective")
    expires = direct_text(info, "expires") or first_text(info, "expires")
    severity = direct_text(info, "severity") or first_text(info, "severity")
    urgency = direct_text(info, "urgency") or first_text(info, "urgency")
    certainty = direct_text(info, "certainty") or first_text(info, "certainty")
    level = infer_level(severity, urgency, params)
    headline = direct_text(info, "headline") or first_text(info, "headline")
    if not headline:
        headline = direct_text(info, "description") or first_text(info, "description")
    duration, vig_status, vig_note = evaluate_vigencia(level, sent, effective, expires)
    txt_status, txt_note = evaluate_text(level, headline, bank)
    institution = sender_name or param_like(params, ["institu","orgao","órgão","emissor"]) or sender or "Não identificado"
    return {
        "file": item["name"], "file_date": item["date"], "uf": item["uf"], "source_url": item["url"],
        "alert_id": extract_alert_id(root), "identifier": direct_text(alert, "identifier") or first_text(alert, "identifier"),
        "sender": sender, "sender_name": sender_name, "institution": institution,
        "sent": sent, "effective": effective, "expires": expires,
        "event": direct_text(info, "event") or first_text(info, "event"),
        "severity": severity, "urgency": urgency, "certainty": certainty, "level": level,
        "headline": headline, "area_desc": area_desc(info), "duration_minutes": duration,
        "vigencia_auto": vig_status, "vigencia_note": vig_note,
        "texto_auto": txt_status, "texto_note": txt_note,
        "algorithm_version": algorithm_version, "parser_version": PARSER_VERSION,
        "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    }


UPSERT_ALERT = """INSERT INTO alerts(
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
parser_version=excluded.parser_version,fetched_at=excluded.fetched_at"""

ALERT_COLUMNS = [
    "file","file_date","uf","source_url","alert_id","identifier","sender","sender_name","institution",
    "sent","effective","expires","event","severity","urgency","certainty","level","headline","area_desc",
    "duration_minutes","vigencia_auto","vigencia_note","texto_auto","texto_note","algorithm_version",
    "parser_version","fetched_at"
]


def save_alert(a):
    params = [a.get(c) for c in ALERT_COLUMNS]
    stmts = [
        {"sql": UPSERT_ALERT, "params": params},
        {"sql": "INSERT OR IGNORE INTO evaluation_history(file,dimension,algorithm_version,result,note,evaluated_at) VALUES(?,?,?,?,?,?)",
         "params": [a["file"],"vigencia",a["algorithm_version"],a["vigencia_auto"],a["vigencia_note"],a["fetched_at"]]},
        {"sql": "INSERT OR IGNORE INTO evaluation_history(file,dimension,algorithm_version,result,note,evaluated_at) VALUES(?,?,?,?,?,?)",
         "params": [a["file"],"texto",a["algorithm_version"],a["texto_auto"],a["texto_note"],a["fetched_at"]]}
    ]
    d1_batch(stmts)


def update_sync_status(new_count, error_count, checked, lookback):
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    values = {
        "last_sync_at": now,
        "last_sync_new": str(new_count),
        "last_sync_errors": str(error_count),
        "last_sync_checked": str(checked),
        "last_sync_lookback_days": str(lookback)
    }
    d1_batch([{
        "sql": "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        "params": [k,v]
    } for k,v in values.items()])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lookback-days", type=int, default=3)
    args = ap.parse_args()
    lookback = max(1, min(args.lookback_days, MAX_LOOKBACK))
    today = dt.datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    start = today - dt.timedelta(days=lookback-1)

    print(f"Sincronizando CAP de {start} a {today}...")
    candidates, index_count = list_candidates(start, today)
    print(f"Índice: {index_count} XML; candidatos no período: {len(candidates)}")

    existing_rows = d1_select(
        "SELECT file, parser_version FROM alerts WHERE file_date>=? AND file_date<=?",
        [start.isoformat(), today.isoformat()]
    )
    existing = {r["file"]: int(r.get("parser_version") or 0) for r in existing_rows}
    todo = [x for x in candidates if existing.get(x["name"], 0) < PARSER_VERSION]
    print(f"Já atuais no D1: {len(candidates)-len(todo)}; para baixar/reprocessar: {len(todo)}")

    bank, version = load_rule_bank()
    parsed, errors = [], []

    def worker(item):
        try:
            return parse_cap(item, bank, version), None
        except Exception as e:
            return None, {"file": item["name"], "error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        for alert, err in ex.map(worker, todo):
            if alert:
                parsed.append(alert)
            elif err:
                errors.append(err)

    saved = 0
    for a in parsed:
        try:
            save_alert(a)
            saved += 1
        except Exception as e:
            errors.append({"file": a["file"], "error": f"D1: {e}"})

    update_sync_status(saved, len(errors), len(candidates), lookback)
    print(f"Concluído. Gravados/reprocessados: {saved}; erros: {len(errors)}")
    for e in errors[:20]:
        print(f"ERRO {e['file']}: {e['error']}")

    if errors and saved == 0 and todo:
        sys.exit(1)


if __name__ == "__main__":
    main()
