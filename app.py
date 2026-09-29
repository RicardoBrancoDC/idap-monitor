#!/usr/bin/env python3
import argparse
import base64
import hmac
import concurrent.futures
import datetime as dt
import json
import os
import re
import sqlite3
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_VERSION = "4.0.0"
DEFAULT_REPO = os.environ.get("IDAP_REPO_URL", "https://idapcap.mdr.gov.br/")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("IDAP_DATA_DIR", BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.environ.get("IDAP_DB_PATH", os.path.join(DATA_DIR, "idap_monitor.db"))
HTML_PATH = os.path.join(BASE_DIR, "index.html")
AUTH_USER = os.environ.get("IDAP_BASIC_USER", "").strip()
AUTH_PASSWORD = os.environ.get("IDAP_BASIC_PASSWORD", "")
INDEX_TTL_SECONDS = 300
MAX_RANGE_DAYS = 31
MAX_FILES_PER_QUERY = 500
FETCH_WORKERS = 12
USER_AGENT = f"IDAP-Monitor/{APP_VERSION}"
BASE_ALGORITHM_VERSION = "1.1"
CAP_PARSER_VERSION = 4

REPO_URL = DEFAULT_REPO
RULESET_REVISION = 0
INDEX_CACHE = {"at": None, "links": [], "tls_relaxed": False}
INDEX_LOCK = threading.Lock()
TERM_CACHE = None
TERM_CACHE_LOCK = threading.Lock()

RISK_TERMS = [
    "chuva", "alag", "inund", "enxurr", "desliz", "escorreg", "tempestad",
    "vendaval", "vento", "granizo", "raio", "umidade", "seca", "estiagem",
    "calor", "frio", "geada", "incend", "queimada", "ressaca", "mare",
    "enchente", "transbord", "rompimento", "ciclone", "tornado", "nevoeiro",
    "onda", "avalanche", "desastre", "risco"
]
ACTION_TERMS = [
    "evite", "nao atravesse", "procure", "busque", "saia", "evacue", "abrigue",
    "afaste", "mantenha-se", "mantenha se", "retire", "recolha", "proteja-se",
    "proteja se", "desligue", "permaneca", "dirija-se", "dirija se", "hidrate",
    "feche", "abandone", "suba", "desloque"
]
GENERIC_ACTIONS = [
    "fique atento", "mantenha os cuidados", "redobre a atencao",
    "acompanhe as orientacoes", "atencao"
]
EXTREME_ACTIONS = [
    "evacue", "evacuacao", "saia imediatamente", "busque abrigo", "procure abrigo",
    "local seguro", "area segura", "abrigue-se", "abrigue se"
]


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


def db_connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def now_iso():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def normalize(s):
    import unicodedata
    s = (s or "").lower()
    s = unicodedata.normalize("NFD", s)
    return "".join(c for c in s if unicodedata.category(c) != "Mn")


def algorithm_version():
    return f"{BASE_ALGORITHM_VERSION}-r{RULESET_REVISION}"


def init_db():
    global RULESET_REVISION
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            file TEXT PRIMARY KEY,
            file_date TEXT, uf TEXT, source_url TEXT,
            alert_id TEXT, identifier TEXT, sender TEXT, sender_name TEXT, institution TEXT,
            sent TEXT, effective TEXT, expires TEXT,
            event TEXT, severity TEXT, urgency TEXT, certainty TEXT,
            level TEXT, headline TEXT, area_desc TEXT,
            duration_minutes INTEGER,
            vigencia_auto TEXT, vigencia_note TEXT,
            texto_auto TEXT, texto_note TEXT,
            algorithm_version TEXT, parser_version INTEGER, fetched_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            file TEXT PRIMARY KEY,
            vig_choice TEXT, vig_correct_value TEXT, vig_reason TEXT,
            txt_choice TEXT, txt_correct_value TEXT, txt_reason TEXT,
            reviewer TEXT, algorithm_version_at_review TEXT, reviewed_at TEXT,
            vig_validated_value TEXT, txt_validated_value TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS custom_terms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            term TEXT NOT NULL,
            normalized_term TEXT NOT NULL,
            category TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'human_learning',
            approved_by TEXT,
            approved_at TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(normalized_term, category)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS evaluation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT NOT NULL,
            dimension TEXT NOT NULL,
            algorithm_version TEXT NOT NULL,
            result TEXT NOT NULL,
            note TEXT,
            evaluated_at TEXT NOT NULL,
            UNIQUE(file, dimension, algorithm_version)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('ruleset_revision','0')")

    alert_cols = {r[1] for r in con.execute("PRAGMA table_info(alerts)").fetchall()}
    if "algorithm_version" not in alert_cols:
        con.execute("ALTER TABLE alerts ADD COLUMN algorithm_version TEXT")
    if "sender_name" not in alert_cols:
        con.execute("ALTER TABLE alerts ADD COLUMN sender_name TEXT")
    if "alert_id" not in alert_cols:
        con.execute("ALTER TABLE alerts ADD COLUMN alert_id TEXT")
    if "parser_version" not in alert_cols:
        con.execute("ALTER TABLE alerts ADD COLUMN parser_version INTEGER")

    review_cols = {r[1] for r in con.execute("PRAGMA table_info(reviews)").fetchall()}
    if "algorithm_version_at_review" not in review_cols:
        con.execute("ALTER TABLE reviews ADD COLUMN algorithm_version_at_review TEXT")
    if "vig_validated_value" not in review_cols:
        con.execute("ALTER TABLE reviews ADD COLUMN vig_validated_value TEXT")
    if "txt_validated_value" not in review_cols:
        con.execute("ALTER TABLE reviews ADD COLUMN txt_validated_value TEXT")

    con.execute("UPDATE alerts SET algorithm_version='1.0' WHERE algorithm_version IS NULL OR algorithm_version=''")
    con.execute("""
        UPDATE reviews SET vig_validated_value = CASE
            WHEN vig_choice='no' THEN vig_correct_value
            ELSE (SELECT vigencia_auto FROM alerts WHERE alerts.file=reviews.file)
        END
        WHERE vig_validated_value IS NULL OR vig_validated_value=''
    """)
    con.execute("""
        UPDATE reviews SET txt_validated_value = CASE
            WHEN txt_choice='no' THEN txt_correct_value
            ELSE (SELECT texto_auto FROM alerts WHERE alerts.file=reviews.file)
        END
        WHERE txt_validated_value IS NULL OR txt_validated_value=''
    """)

    rows = con.execute("""
        SELECT file, algorithm_version, vigencia_auto, vigencia_note,
               texto_auto, texto_note, fetched_at
        FROM alerts
    """).fetchall()
    for row in rows:
        version = row[1] or "1.0"
        when = row[6] or now_iso()
        if row[2]:
            con.execute("""
                INSERT OR IGNORE INTO evaluation_history
                (file,dimension,algorithm_version,result,note,evaluated_at)
                VALUES(?,?,?,?,?,?)
            """, (row[0], "vigencia", version, row[2], row[3], when))
        if row[4]:
            con.execute("""
                INSERT OR IGNORE INTO evaluation_history
                (file,dimension,algorithm_version,result,note,evaluated_at)
                VALUES(?,?,?,?,?,?)
            """, (row[0], "texto", version, row[4], row[5], when))

    row = con.execute("SELECT value FROM settings WHERE key='ruleset_revision'").fetchone()
    try:
        RULESET_REVISION = int(row[0]) if row else 0
    except Exception:
        RULESET_REVISION = 0

    con.commit()
    con.close()


def invalidate_term_cache():
    global TERM_CACHE
    with TERM_CACHE_LOCK:
        TERM_CACHE = None


def get_term_bank():
    global TERM_CACHE
    with TERM_CACHE_LOCK:
        if TERM_CACHE is not None:
            return TERM_CACHE
        bank = {
            "risk": list(RISK_TERMS),
            "action": list(ACTION_TERMS),
            "generic": list(GENERIC_ACTIONS),
            "extreme": list(EXTREME_ACTIONS),
        }
        try:
            con = db_connect()
            rows = con.execute("""
                SELECT category, normalized_term
                FROM custom_terms
                WHERE active=1 ORDER BY id
            """).fetchall()
            con.close()
            for row in rows:
                cat = row["category"]
                if cat in bank and row["normalized_term"] not in bank[cat]:
                    bank[cat].append(row["normalized_term"])
        except Exception:
            pass
        TERM_CACHE = bank
        return TERM_CACHE


def add_history(con, file_name, dimension, version, result, note, when=None):
    if not result:
        return
    con.execute("""
        INSERT OR IGNORE INTO evaluation_history
        (file,dimension,algorithm_version,result,note,evaluated_at)
        VALUES(?,?,?,?,?,?)
    """, (file_name, dimension, version, result, note, when or now_iso()))


def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(), False
    except (urllib.error.URLError, ssl.SSLCertVerificationError) as e:
        msg = str(e).lower()
        if isinstance(e, urllib.error.URLError) and "certificate" not in msg and "ssl" not in msg:
            raise
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(), True


def get_index_links(force=False):
    with INDEX_LOCK:
        now = dt.datetime.now().timestamp()
        cached_at = INDEX_CACHE["at"]
        if not force and cached_at and now - cached_at < INDEX_TTL_SECONDS:
            return INDEX_CACHE["links"], INDEX_CACHE["tls_relaxed"]
        raw, relaxed = http_get(REPO_URL, timeout=30)
        parser = LinkParser()
        parser.feed(raw.decode("utf-8", errors="replace"))
        links, seen = [], set()
        for href in parser.links:
            decoded = urllib.parse.unquote(href)
            name = decoded.rstrip("/").split("/")[-1]
            if name.lower().endswith(".xml") and name not in seen:
                seen.add(name)
                links.append((name, urllib.parse.urljoin(REPO_URL, href)))
        INDEX_CACHE.update({"at": now, "links": links, "tls_relaxed": relaxed})
        return links, relaxed


FILE_RE = re.compile(r"(?P<date>\d{8})-(?P<uf>[A-Z]{2})\.xml$", re.I)


def file_meta(name):
    m = FILE_RE.search(name)
    if not m:
        return None
    try:
        d = dt.datetime.strptime(m.group("date"), "%d%m%Y").date()
    except ValueError:
        return None
    return d, m.group("uf").upper()


def strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def first_text(parent, name):
    for el in parent.iter():
        if strip_ns(el.tag) == name and el.text:
            return el.text.strip()
    return ""


def direct_child_text(parent, name):
    for el in list(parent):
        if strip_ns(el.tag) == name and el.text:
            return el.text.strip()
    return ""


ALERT_ID_RE = re.compile(r"^\\s*(\\d+)\\s*/\\s*(\\d{4})\\s*$")


def extract_alert_id(root):
    """
    Procura o ID operacional do alerta, por exemplo 100008/2022.

    Alguns XML possuem outros elementos <id>, inclusive URLs de feed/RSS.
    Por isso, não usamos simplesmente o primeiro <id> encontrado.
    """
    candidates = []
    for el in root.iter():
        if strip_ns(el.tag) == "id" and el.text:
            value = el.text.strip()
            m = ALERT_ID_RE.match(value)
            if m:
                # normaliza espaços, mantendo exatamente o formato numero/ano
                candidates.append(f"{m.group(1)}/{m.group(2)}")

    if candidates:
        return candidates[0]

    # Fallback conservador: aceita um id não-URL apenas se não houver padrão numero/ano.
    for el in root.iter():
        if strip_ns(el.tag) == "id" and el.text:
            value = el.text.strip()
            lower = value.lower()
            if value and not lower.startswith(("http://", "https://")):
                return value

    return ""


def choose_info(root):
    infos = [el for el in list(root) if strip_ns(el.tag) == "info"]
    if not infos:
        infos = [el for el in root.iter() if strip_ns(el.tag) == "info"]
    if not infos:
        return root
    for info in infos:
        if direct_child_text(info, "language").lower().startswith("pt"):
            return info
    return infos[0]


def parse_parameters(info):
    out = {}
    for par in info.iter():
        if strip_ns(par.tag) != "parameter":
            continue
        key = val = ""
        for ch in list(par):
            n = strip_ns(ch.tag)
            if n == "valueName" and ch.text:
                key = ch.text.strip()
            elif n == "value" and ch.text:
                val = ch.text.strip()
        if key:
            out[key.lower()] = val
    return out


def param_like(params, needles):
    for k, v in params.items():
        if any(n in k for n in needles):
            return v
    return ""


def parse_dt(s):
    if not s:
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return dt.datetime.fromisoformat(s)
    except ValueError:
        return None


def fmt_dt(s):
    d = parse_dt(s)
    return d.strftime("%d/%m/%Y %H:%M") if d else (s or "-")


def infer_level(severity, urgency, params):
    explicit = param_like(params, ["nivel", "nível", "level"])
    if explicit:
        n = normalize(explicit)
        for key, label in [
            ("extremo", "Extremo"), ("severo", "Severo"), ("alto", "Alto"),
            ("moderado", "Moderado"), ("baixo", "Baixo")
        ]:
            if key in n:
                return label
    sev, urg = normalize(severity), normalize(urgency)
    if sev == "extreme":
        return "Extremo" if urg == "immediate" else "Severo"
    return {"severe": "Alto", "moderate": "Moderado", "minor": "Baixo"}.get(
        sev, severity or "Não identificado"
    )


def vigencia_limit_minutes(level):
    return {"Extremo": 120, "Severo": 240, "Alto": 4320, "Moderado": 4320, "Baixo": 4320}.get(level)


def format_duration(minutes):
    if minutes is None:
        return "-"
    sign = "-" if minutes < 0 else ""
    minutes = abs(int(minutes))
    h, m = divmod(minutes, 60)
    if h and m:
        return f"{sign}{h}h{m:02d}"
    if h:
        return f"{sign}{h}h"
    return f"{sign}{m}min"


def evaluate_vigencia(level, sent, effective, expires):
    start = parse_dt(effective) or parse_dt(sent)
    end = parse_dt(expires)
    limit = vigencia_limit_minutes(level)
    if not start or not end:
        return None, "revisao", "Não foi possível calcular a vigência porque faltam data inicial ou expiração."
    minutes = int(round((end - start).total_seconds() / 60))
    if minutes < 0:
        return minutes, "nao_conforme", "A data de expiração é anterior ao início da vigência."
    if limit is None:
        return minutes, "revisao", "Nível não reconhecido para aplicação automática do limite de vigência."
    if minutes <= limit:
        return minutes, "conforme", f"Vigência de {format_duration(minutes)}, dentro do limite de {format_duration(limit)} para o nível {level}."
    return minutes, "nao_conforme", f"Vigência de {format_duration(minutes)}, acima do limite de {format_duration(limit)} para o nível {level}."


def evaluate_text(level, headline, term_bank=None):
    t = normalize(headline)
    if not t.strip():
        return "nao_conforme", "Mensagem principal vazia."
    bank = term_bank or get_term_bank()
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


def parse_cap(file_name, source_url, file_date, uf, xml_bytes):
    root = ET.fromstring(xml_bytes)
    info = choose_info(root)
    params = parse_parameters(info)
    alert_id = extract_alert_id(root)
    identifier = direct_child_text(root, "identifier") or first_text(root, "identifier")
    sender = direct_child_text(root, "sender") or first_text(root, "sender")
    sender_name = direct_child_text(info, "senderName") or first_text(info, "senderName")
    sent = direct_child_text(root, "sent") or first_text(root, "sent")
    event = direct_child_text(info, "event") or first_text(info, "event")
    severity = direct_child_text(info, "severity") or first_text(info, "severity")
    urgency = direct_child_text(info, "urgency") or first_text(info, "urgency")
    certainty = direct_child_text(info, "certainty") or first_text(info, "certainty")
    effective = direct_child_text(info, "effective") or first_text(info, "effective")
    expires = direct_child_text(info, "expires") or first_text(info, "expires")
    headline = (
        direct_child_text(info, "headline") or first_text(info, "headline") or
        direct_child_text(info, "description") or first_text(info, "description")
    )
    area_desc = ""
    for area in info.iter():
        if strip_ns(area.tag) == "area":
            area_desc = direct_child_text(area, "areaDesc") or first_text(area, "areaDesc")
            if area_desc:
                break
    institution = sender_name or param_like(params, ["institu", "orgao", "órgão", "emissor"]) or sender or "Não identificado"
    level = infer_level(severity, urgency, params)
    duration, vig_status, vig_note = evaluate_vigencia(level, sent, effective, expires)
    txt_status, txt_note = evaluate_text(level, headline)
    return {
        "file": file_name, "file_date": file_date.isoformat(), "uf": uf,
        "source_url": source_url, "alert_id": alert_id,
        "identifier": identifier, "sender": sender,
        "sender_name": sender_name, "institution": institution,
        "sent": sent, "effective": effective,
        "expires": expires, "event": event, "severity": severity, "urgency": urgency,
        "certainty": certainty, "level": level, "headline": headline,
        "area_desc": area_desc, "duration_minutes": duration,
        "vigencia_auto": vig_status, "vigencia_note": vig_note,
        "texto_auto": txt_status, "texto_note": txt_note,
        "algorithm_version": algorithm_version(),
        "parser_version": CAP_PARSER_VERSION,
        "fetched_at": now_iso(),
    }


def save_alert(a):
    con = db_connect()
    cols = list(a)
    vals = [a[c] for c in cols]
    placeholders = ",".join(["?"] * len(cols))
    updates = ",".join([f"{c}=excluded.{c}" for c in cols if c != "file"])
    con.execute(
        f"INSERT INTO alerts ({','.join(cols)}) VALUES ({placeholders}) "
        f"ON CONFLICT(file) DO UPDATE SET {updates}", vals
    )
    add_history(con, a["file"], "vigencia", a["algorithm_version"], a["vigencia_auto"], a["vigencia_note"], a["fetched_at"])
    add_history(con, a["file"], "texto", a["algorithm_version"], a["texto_auto"], a["texto_note"], a["fetched_at"])
    con.commit()
    con.close()


def cached_files(names):
    """Retorna somente arquivos já processados pela versão atual do parser CAP."""
    if not names:
        return set()
    con = db_connect()
    out = set()
    for i in range(0, len(names), 400):
        chunk = names[i:i+400]
        q = ",".join(["?"] * len(chunk))
        rows = con.execute(
            f"SELECT file FROM alerts WHERE file IN ({q}) "
            f"AND COALESCE(parser_version, 0) >= ?",
            [*chunk, CAP_PARSER_VERSION]
        ).fetchall()
        out.update(r["file"] for r in rows)
    con.close()
    return out

def fetch_one(item):
    name, url, d, uf = item
    raw, _ = http_get(url, timeout=25)
    save_alert(parse_cap(name, url, d, uf, raw))
    return name


def sync_range(date_from, date_to, uf="all"):
    links, tls_relaxed = get_index_links()
    candidates = []
    for name, url in links:
        meta = file_meta(name)
        if not meta:
            continue
        d, file_uf = meta
        if date_from <= d <= date_to and (uf == "all" or file_uf == uf):
            candidates.append((name, url, d, file_uf))
    candidates.sort(key=lambda x: (x[2], x[0]), reverse=True)
    if len(candidates) > MAX_FILES_PER_QUERY:
        raise ValueError(
            f"O período encontrou {len(candidates)} XML. Reduza a consulta para no máximo "
            f"{MAX_FILES_PER_QUERY} arquivos nesta versão de teste."
        )
    names = [x[0] for x in candidates]
    have = cached_files(names)
    missing = [x for x in candidates if x[0] not in have]
    errors = []
    if missing:
        with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
            futs = {ex.submit(fetch_one, item): item for item in missing}
            for fut in concurrent.futures.as_completed(futs):
                item = futs[fut]
                try:
                    fut.result()
                except Exception as e:
                    errors.append({"file": item[0], "error": str(e)})
    return {
        "index_files": len(links), "matched_files": len(candidates),
        "downloaded": len(missing) - len(errors), "cached": len(candidates) - len(missing),
        "errors": errors[:10], "tls_relaxed": tls_relaxed,
    }


def load_results(date_from, date_to, uf, level, review, result, vigencia_filter='all', texto_filter='all'):
    con = db_connect()
    params = [date_from.isoformat(), date_to.isoformat()]
    where = ["a.file_date >= ?", "a.file_date <= ?"]
    if uf != "all":
        where.append("a.uf = ?")
        params.append(uf)
    if level != "all":
        where.append("a.level = ?")
        params.append(level)
    sql = """
        SELECT a.*,
               r.vig_choice, r.vig_correct_value, r.vig_reason,
               r.txt_choice, r.txt_correct_value, r.txt_reason,
               r.reviewer, r.algorithm_version_at_review, r.reviewed_at,
               r.vig_validated_value, r.txt_validated_value
        FROM alerts a LEFT JOIN reviews r ON r.file=a.file
        WHERE """ + " AND ".join(where) + """
        ORDER BY COALESCE(NULLIF(a.sent,''), a.file_date) DESC, a.file DESC
    """
    rows = con.execute(sql, params).fetchall()
    con.close()
    out = []
    for row in rows:
        d = dict(row)
        d["reviewed"] = bool(d.get("reviewed_at"))
        d["vigencia_final"] = d["vigencia_auto"]
        d["texto_final"] = d["texto_auto"]
        if d["reviewed"]:
            if d.get("vig_validated_value"):
                d["vigencia_final"] = d["vig_validated_value"]
            if d.get("txt_validated_value"):
                d["texto_final"] = d["txt_validated_value"]
        if review == "pending" and d["reviewed"]:
            continue
        if review == "reviewed" and not d["reviewed"]:
            continue
        if vigencia_filter != "all" and d["vigencia_final"] != vigencia_filter:
            continue
        if texto_filter != "all" and d["texto_final"] != texto_filter:
            continue
        has_non = d["vigencia_final"] == "nao_conforme" or d["texto_final"] == "nao_conforme"
        is_ok = d["vigencia_final"] == "conforme" and d["texto_final"] == "conforme"
        needs_rev = d["vigencia_final"] == "revisao" or d["texto_final"] == "revisao"
        if result == "nonconform" and not has_non:
            continue
        if result == "ok" and not is_ok:
            continue
        if result == "review" and not needs_rev:
            continue
        d["sent_display"] = fmt_dt(d["sent"])
        d["effective_display"] = fmt_dt(d["effective"])
        d["expires_display"] = fmt_dt(d["expires"])
        d["duration_display"] = format_duration(d["duration_minutes"])
        lim = vigencia_limit_minutes(d["level"])
        d["limit_display"] = format_duration(lim) if lim else "-"
        out.append(d)
    return out


def auto_result_at_review(con, file_name, dimension, version, fallback):
    if version:
        row = con.execute("""
            SELECT result FROM evaluation_history
            WHERE file=? AND dimension=? AND algorithm_version=?
            ORDER BY id DESC LIMIT 1
        """, (file_name, dimension, version)).fetchone()
        if row:
            return row["result"]
    return fallback


def save_review(payload):
    if not payload.get("file") or not payload.get("vig_choice") or not payload.get("txt_choice"):
        raise ValueError("Dados de revisão incompletos.")
    if payload["vig_choice"] == "no" and not (payload.get("vig_reason") or "").strip():
        raise ValueError("Informe o motivo da correção da vigência.")
    if payload["txt_choice"] == "no" and not (payload.get("txt_reason") or "").strip():
        raise ValueError("Informe o motivo da correção textual.")

    con = db_connect()
    alert = con.execute("""
        SELECT vigencia_auto, texto_auto, algorithm_version
        FROM alerts WHERE file=?
    """, (payload["file"],)).fetchone()
    if not alert:
        con.close()
        raise ValueError("Alerta não encontrado no banco local.")

    version_at_review = alert["algorithm_version"] or algorithm_version()
    vig_validated = alert["vigencia_auto"] if payload["vig_choice"] == "yes" else payload.get("vig_correct_value", "")
    txt_validated = alert["texto_auto"] if payload["txt_choice"] == "yes" else payload.get("txt_correct_value", "")

    con.execute("""
        INSERT INTO reviews(
            file,vig_choice,vig_correct_value,vig_reason,
            txt_choice,txt_correct_value,txt_reason,
            reviewer,algorithm_version_at_review,reviewed_at,
            vig_validated_value,txt_validated_value
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(file) DO UPDATE SET
            vig_choice=excluded.vig_choice,
            vig_correct_value=excluded.vig_correct_value,
            vig_reason=excluded.vig_reason,
            txt_choice=excluded.txt_choice,
            txt_correct_value=excluded.txt_correct_value,
            txt_reason=excluded.txt_reason,
            reviewer=excluded.reviewer,
            algorithm_version_at_review=excluded.algorithm_version_at_review,
            reviewed_at=excluded.reviewed_at,
            vig_validated_value=excluded.vig_validated_value,
            txt_validated_value=excluded.txt_validated_value
    """, (
        payload["file"], payload["vig_choice"], payload.get("vig_correct_value", ""),
        (payload.get("vig_reason") or "").strip(), payload["txt_choice"],
        payload.get("txt_correct_value", ""), (payload.get("txt_reason") or "").strip(),
        (payload.get("reviewer") or "").strip() or "Revisor local",
        version_at_review, now_iso(), vig_validated, txt_validated
    ))
    con.commit()
    con.close()


def extract_candidate_phrases(headline, reason, known_bank):
    candidates = []
    for pat in [r'"([^"]{3,120})"', r'“([^”]{3,120})”', r"'([^']{3,120})'"]:
        for match in re.findall(pat, reason or ""):
            phrase = match.strip(" .,:;-")
            if phrase:
                candidates.append(phrase)

    sentences = [s.strip(" .,:;-") for s in re.split(r"[.!?;]+", headline or "") if s.strip()]
    known_action = [normalize(x) for x in known_bank["action"] + known_bank["generic"] + known_bank["extreme"]]
    risk = [normalize(x) for x in known_bank["risk"]]
    for sentence in sentences:
        ns = normalize(sentence)
        words = sentence.split()
        if len(words) < 2 or len(words) > 18:
            continue
        if any(k in ns for k in known_action):
            continue
        risk_hits = sum(1 for k in risk if k in ns)
        if risk_hits and len(sentences) > 1:
            continue
        candidates.append(sentence)

    out, seen = [], set()
    for phrase in candidates:
        nphrase = normalize(phrase)
        if nphrase and nphrase not in seen:
            seen.add(nphrase)
            out.append(phrase)
    return out[:4]


def get_learning_data():
    con = db_connect()
    reviews = con.execute("""
        SELECT r.*, a.headline, a.level, a.uf, a.institution,
               a.texto_auto AS current_text_auto,
               a.vigencia_auto AS current_vig_auto,
               a.algorithm_version AS current_algorithm_version
        FROM reviews r JOIN alerts a ON a.file=r.file
        ORDER BY r.reviewed_at DESC
    """).fetchall()

    total = len(reviews)
    text_agreements = text_corrections = 0
    vig_agreements = vig_corrections = 0
    divergences = []
    candidate_map = {}
    bank = get_term_bank()

    for row in reviews:
        d = dict(row)
        version = d.get("algorithm_version_at_review") or d.get("current_algorithm_version")
        auto_text = auto_result_at_review(con, d["file"], "texto", version, d.get("current_text_auto"))
        auto_vig = auto_result_at_review(con, d["file"], "vigencia", version, d.get("current_vig_auto"))
        human_text = d.get("txt_validated_value") or (d.get("txt_correct_value") if d.get("txt_choice") == "no" else auto_text)
        human_vig = d.get("vig_validated_value") or (d.get("vig_correct_value") if d.get("vig_choice") == "no" else auto_vig)

        if auto_text == human_text:
            text_agreements += 1
        else:
            text_corrections += 1
            divergences.append({
                "file": d["file"], "headline": d.get("headline") or "",
                "level": d.get("level") or "", "uf": d.get("uf") or "",
                "institution": d.get("institution") or "", "auto_result": auto_text or "",
                "human_result": human_text or "", "reason": d.get("txt_reason") or "",
                "reviewer": d.get("reviewer") or "", "reviewed_at": d.get("reviewed_at") or "",
                "algorithm_version": version or "",
            })
            if human_text == "conforme":
                for phrase in extract_candidate_phrases(d.get("headline") or "", d.get("txt_reason") or "", bank):
                    key = normalize(phrase)
                    item = candidate_map.setdefault(key, {"phrase": phrase, "count": 0, "examples": []})
                    item["count"] += 1
                    if len(item["examples"]) < 3:
                        item["examples"].append({
                            "file": d["file"], "headline": d.get("headline") or "",
                            "reason": d.get("txt_reason") or "",
                        })

        if auto_vig == human_vig:
            vig_agreements += 1
        else:
            vig_corrections += 1

    custom_terms = [dict(r) for r in con.execute("""
        SELECT id,term,normalized_term,category,approved_by,approved_at,active
        FROM custom_terms ORDER BY active DESC, approved_at DESC, id DESC
    """).fetchall()]
    con.close()

    candidates = sorted(candidate_map.values(), key=lambda x: (-x["count"], normalize(x["phrase"])))[:30]
    return {
        "metrics": {
            "reviewed": total,
            "text_agreements": text_agreements,
            "text_corrections": text_corrections,
            "text_agreement_rate": round((text_agreements / total * 100), 1) if total else 0,
            "vig_agreements": vig_agreements,
            "vig_corrections": vig_corrections,
            "vig_agreement_rate": round((vig_agreements / total * 100), 1) if total else 0,
            "algorithm_version": algorithm_version(),
        },
        "divergences": divergences[:100],
        "candidates": candidates,
        "custom_terms": custom_terms,
    }


def reprocess_cached_alerts():
    version = algorithm_version()
    bank = get_term_bank()
    con = db_connect()
    rows = con.execute("""
        SELECT file,level,headline,texto_auto,texto_note,algorithm_version
        FROM alerts
    """).fetchall()
    updated = changed = 0
    for row in rows:
        old_result = row["texto_auto"]
        old_note = row["texto_note"]
        old_version = row["algorithm_version"] or "1.0"
        add_history(con, row["file"], "texto", old_version, old_result, old_note)
        new_result, new_note = evaluate_text(row["level"], row["headline"], bank)
        add_history(con, row["file"], "texto", version, new_result, new_note)
        if new_result != old_result or new_note != old_note or old_version != version:
            con.execute("""
                UPDATE alerts SET texto_auto=?, texto_note=?, algorithm_version=?
                WHERE file=?
            """, (new_result, new_note, version, row["file"]))
            updated += 1
            if new_result != old_result:
                changed += 1
    con.commit()
    con.close()
    return {"processed": len(rows), "updated": updated, "changed_result": changed, "version": version}


def approve_custom_term(term, category, reviewer):
    global RULESET_REVISION
    category = (category or "").strip()
    if category not in {"risk", "action", "generic", "extreme"}:
        raise ValueError("Categoria de aprendizagem inválida.")
    term = (term or "").strip()
    nterm = normalize(term)
    if len(nterm) < 2:
        raise ValueError("Informe uma palavra ou frase válida.")

    con = db_connect()
    existing = con.execute("""
        SELECT id,active FROM custom_terms
        WHERE normalized_term=? AND category=?
    """, (nterm, category)).fetchone()
    if existing and existing["active"]:
        con.close()
        return {"already_active": True, "term": term, "category": category, "version": algorithm_version()}

    con.execute("""
        INSERT INTO custom_terms(term,normalized_term,category,source,approved_by,approved_at,active)
        VALUES(?,?,?,?,?,?,1)
        ON CONFLICT(normalized_term,category) DO UPDATE SET
            term=excluded.term, approved_by=excluded.approved_by,
            approved_at=excluded.approved_at, active=1
    """, (term, nterm, category, "human_learning", (reviewer or "").strip() or "Revisor local", now_iso()))
    RULESET_REVISION += 1
    con.execute("""
        INSERT INTO settings(key,value) VALUES('ruleset_revision',?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (str(RULESET_REVISION),))
    con.commit()
    con.close()
    invalidate_term_cache()
    result = reprocess_cached_alerts()
    result.update({"already_active": False, "term": term, "category": category})
    return result


def disable_custom_term(term_id):
    global RULESET_REVISION
    con = db_connect()
    row = con.execute("SELECT id,active FROM custom_terms WHERE id=?", (term_id,)).fetchone()
    if not row:
        con.close()
        raise ValueError("Termo não encontrado.")
    if not row["active"]:
        con.close()
        return {"already_inactive": True, "version": algorithm_version()}
    con.execute("UPDATE custom_terms SET active=0 WHERE id=?", (term_id,))
    RULESET_REVISION += 1
    con.execute("""
        INSERT INTO settings(key,value) VALUES('ruleset_revision',?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (str(RULESET_REVISION),))
    con.commit()
    con.close()
    invalidate_term_cache()
    result = reprocess_cached_alerts()
    result["already_inactive"] = False
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def auth_enabled(self):
        return bool(AUTH_USER and AUTH_PASSWORD)

    def is_authorized(self):
        if not self.auth_enabled():
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(header[6:]).decode("utf-8")
            user, password = raw.split(":", 1)
        except Exception:
            return False
        return hmac.compare_digest(user, AUTH_USER) and hmac.compare_digest(password, AUTH_PASSWORD)

    def require_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="IDAP Monitor", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("Autenticação necessária.".encode("utf-8"))

    def send_json(self, obj, status=200):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/healthz":
            self.send_json({"ok": True, "version": APP_VERSION})
            return

        if not self.is_authorized():
            self.require_auth()
            return

        if parsed.path == "/":
            with open(HTML_PATH, "rb") as f:
                raw = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if parsed.path == "/api/alerts":
            try:
                q = urllib.parse.parse_qs(parsed.query)
                date_from = dt.datetime.strptime(q.get("from", [""])[0], "%Y-%m-%d").date()
                date_to = dt.datetime.strptime(q.get("to", [""])[0], "%Y-%m-%d").date()
                if date_to < date_from:
                    raise ValueError("A data final não pode ser anterior à data inicial.")
                if (date_to - date_from).days > MAX_RANGE_DAYS:
                    raise ValueError(f"Selecione um período de até {MAX_RANGE_DAYS} dias nesta versão de teste.")
                uf = q.get("uf", ["all"])[0]
                level = q.get("level", ["all"])[0]
                review = q.get("review", ["all"])[0]
                vigencia_filter = q.get("vigencia", ["all"])[0]
                texto_filter = q.get("texto", ["all"])[0]
                result = q.get("result", ["all"])[0]
                sync = sync_range(date_from, date_to, uf)
                alerts = load_results(
                    date_from, date_to, uf, level, review, result,
                    vigencia_filter, texto_filter
                )
                self.send_json({"alerts": alerts, "sync": sync})
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
            return

        if parsed.path == "/api/learning":
            try:
                self.send_json(get_learning_data())
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
            return

        self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if not self.is_authorized():
            self.require_auth()
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}

            if parsed.path == "/api/review":
                save_review(payload)
                self.send_json({"ok": True})
                return

            if parsed.path == "/api/learning/term":
                action = payload.get("action")
                if action == "approve":
                    self.send_json(approve_custom_term(
                        payload.get("term"), payload.get("category"), payload.get("reviewer")
                    ))
                    return
                if action == "disable":
                    self.send_json(disable_custom_term(int(payload.get("id"))))
                    return
                raise ValueError("Ação de aprendizagem inválida.")

            self.send_error(404)
        except Exception as e:
            self.send_json({"error": str(e)}, 400)


def main():
    global REPO_URL
    parser = argparse.ArgumentParser(description="IDAP Monitor")
    default_port = int(os.environ.get("PORT", "8765"))
    default_host = os.environ.get("HOST") or ("0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--host", default=default_host)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    REPO_URL = args.repo if args.repo.endswith("/") else args.repo + "/"
    init_db()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    local_url = f"http://127.0.0.1:{args.port}/"

    print("\nIDAP Monitor iniciado.")
    print(f"Versão: {APP_VERSION}")
    print(f"Servidor: {args.host}:{args.port}")
    print(f"Banco: {DB_PATH}")
    print(f"Repositório CAP: {REPO_URL}")
    print(f"Versão do avaliador: {algorithm_version()}")
    print(f"Autenticação: {'ativada' if AUTH_USER and AUTH_PASSWORD else 'desativada'}")
    if args.host in {"127.0.0.1", "localhost", "0.0.0.0"}:
        print(f"Abra: {local_url}")
    print("Pressione Ctrl+C para encerrar.\n")

    hosted = bool(os.environ.get("PORT") or os.environ.get("RENDER"))
    if not args.no_browser and not hosted:
        threading.Timer(0.7, lambda: webbrowser.open(local_url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
