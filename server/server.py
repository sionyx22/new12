# -*- coding: utf-8 -*-
"""
PC Cleaner Dashboard - שרת לוגים ודוחות (ללא תלויות חיצוניות, רק ספריית הסטנדרט של Python).
משתני סביבה: INGEST_KEY (מפתח לתוכנה), DASH_PASSWORD (סיסמת הדשבורד), SECRET_KEY (חתימת עוגיות),
DB_PATH (ברירת מחדל: /var/data/pccleaner.db אם קיים דיסק, אחרת ./pccleaner.db), PORT.
"""
import hmac
import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

INGEST_KEY = os.environ.get("INGEST_KEY", "")
DASH_PASSWORD = os.environ.get("DASH_PASSWORD", "")
SECRET_KEY = (os.environ.get("SECRET_KEY") or secrets.token_hex(32)).encode()
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH") or ("/var/data/pccleaner.db" if os.path.isdir("/var/data") else "pccleaner.db")
UPDATE_REPO = os.environ.get("UPDATE_REPO", "").strip()          # למשל: sionyx22/pccleaner-updates
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()        # טוקן לקריאה בלבד של הריפו הפרטי
ASSET_NAME = os.environ.get("ASSET_NAME", "PCCleaner.exe")
GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com").rstrip("/")
MAX_BODY = 8 * 1024 * 1024
ONLINE_SECS = 180
SESSION_SECS = 12 * 3600
LOG_RETENTION_DAYS = 30
MAX_LOGS_PER_MACHINE = 100000
MAX_REPORTS_PER_MACHINE = 50

_db_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.row_factory = sqlite3.Row
_db.executescript("""
CREATE TABLE IF NOT EXISTS machines(id TEXT PRIMARY KEY, host TEXT, ver TEXT, first_seen TEXT, last_seen REAL, last_line TEXT);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT, machine TEXT, ts TEXT, level TEXT, line TEXT, recv REAL);
CREATE INDEX IF NOT EXISTS ix_logs_m ON logs(machine, id);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, machine TEXT, name TEXT, created TEXT, body TEXT);
CREATE INDEX IF NOT EXISTS ix_rep_m ON reports(machine, id);
""")
_ingests = [0]
_login_fails = {}


def classify(line):
    if "ERROR" in line or " FAIL" in line or "UNCAUGHT" in line or "FAILED" in line:
        return "error"
    if "guard:" in line:
        return "guard"
    if " DRY " in line or line.startswith("DRY "):
        return "dry"
    if " OK" in line:
        return "ok"
    return "info"


def q(sql, args=(), one=False, write=False):
    with _db_lock:
        cur = _db.execute(sql, args)
        if write:
            _db.commit()
            return cur
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def ingest(payload):
    mid = str(payload.get("machine", ""))[:64]
    if not mid:
        return 0
    host = str(payload.get("host", ""))[:80]
    ver = str(payload.get("ver", ""))[:20]
    now = time.time()
    n = 0
    last_line = None
    with _db_lock:
        _db.execute("INSERT OR IGNORE INTO machines(id, host, ver, first_seen, last_seen, last_line) VALUES(?,?,?,?,?,?)",
                    (mid, host, ver, time.strftime("%Y-%m-%d %H:%M:%S"), now, ""))
        for it in payload.get("items", [])[:2000]:
            kind = it.get("k")
            ts = str(it.get("ts", ""))[:19]
            text = str(it.get("t", ""))
            if kind in ("log", "event"):
                text = text[:4000]
                _db.execute("INSERT INTO logs(machine, ts, level, line, recv) VALUES(?,?,?,?,?)",
                            (mid, ts, classify(text), text, now))
                last_line = text
                n += 1
            elif kind == "report":
                _db.execute("INSERT INTO reports(machine, name, created, body) VALUES(?,?,?,?)",
                            (mid, str(it.get("n", "report"))[:120], ts, text[:3_000_000]))
                n += 1
        _db.execute("UPDATE machines SET host=?, ver=?, last_seen=?, last_line=COALESCE(?, last_line) WHERE id=?",
                    (host, ver, now, last_line, mid))
        _db.commit()
    _ingests[0] += 1
    if _ingests[0] % 100 == 0:
        retention()
    return n


def retention():
    cutoff = time.time() - LOG_RETENTION_DAYS * 86400
    with _db_lock:
        _db.execute("DELETE FROM logs WHERE recv < ?", (cutoff,))
        for m in _db.execute("SELECT id FROM machines").fetchall():
            _db.execute("DELETE FROM logs WHERE machine=? AND id NOT IN (SELECT id FROM logs WHERE machine=? ORDER BY id DESC LIMIT ?)",
                        (m["id"], m["id"], MAX_LOGS_PER_MACHINE))
            _db.execute("DELETE FROM reports WHERE machine=? AND id NOT IN (SELECT id FROM reports WHERE machine=? ORDER BY id DESC LIMIT ?)",
                        (m["id"], m["id"], MAX_REPORTS_PER_MACHINE))
        _db.commit()


# ---------- עדכונים: משיכת הגרסה האחרונה מריפו פרטי ב-GitHub ----------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_rel = {"t": 0.0, "data": None}
_exe_lock = threading.Lock()
_exe_cache = {}


def ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:4])


def _gh_headers(accept):
    h = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "pccleaner-dashboard"}
    if GITHUB_TOKEN:                       # לריפו ציבורי הטוקן אופציונלי (מונע מגבלת קצב); לריפו פרטי הוא חובה
        h["Authorization"] = "Bearer " + GITHUB_TOKEN
    return h


def gh_open_asset(asset_id):
    """פותח קובץ מהריפו הפרטי. את הכותרת Authorization שולחים רק ל-GitHub ולא לכתובת ההורדה המחותמת."""
    req = urllib.request.Request(f"{GITHUB_API}/repos/{UPDATE_REPO}/releases/assets/{asset_id}",
                                 headers=_gh_headers("application/octet-stream"))
    try:
        return urllib.request.build_opener(_NoRedirect).open(req, timeout=60)
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location") if e.code in (301, 302, 303, 307, 308) else None
        if not loc:
            raise
        return urllib.request.urlopen(urllib.request.Request(loc, headers={"User-Agent": "pccleaner-dashboard"}), timeout=120)


def latest_release(force=False):
    if not UPDATE_REPO:
        return {"error": "לא הוגדר UPDATE_REPO בשרת"}
    if not force and _rel["data"] and time.time() - _rel["t"] < 120:
        return _rel["data"]
    try:
        req = urllib.request.Request(f"{GITHUB_API}/repos/{UPDATE_REPO}/releases/latest",
                                     headers=_gh_headers("application/vnd.github+json"))
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read().decode("utf-8"))
        assets = {a["name"].lower(): a for a in d.get("assets", [])}
        exe = assets.get(ASSET_NAME.lower())
        if not exe:
            raise ValueError(f"אין קובץ {ASSET_NAME} בגרסה {d.get('tag_name')}")
        sha = assets.get(ASSET_NAME.lower() + ".sha256")
        data = {"tag": d.get("tag_name", ""), "version": re.sub(r"^[^\d]*", "", d.get("tag_name", "")),
                "notes": (d.get("body") or "")[:1000], "published": (d.get("published_at") or "")[:10],
                "size": exe.get("size", 0), "asset_id": exe["id"], "sha_id": sha["id"] if sha else None}
    except urllib.error.HTTPError as e:
        data = {"error": f"GitHub החזיר {e.code} (בדוק UPDATE_REPO והרשאות הטוקן)"}
    except Exception as e:
        data = {"error": f"{type(e).__name__}: {e}"}
    if "error" in data and _rel["data"] and "error" not in _rel["data"]:
        data = dict(_rel["data"], stale=data["error"])      # שומרים את הגרסה הידועה אם GitHub נפל זמנית
    _rel.update(t=time.time(), data=data)
    return data


def ensure_exe(meta):
    """מוריד את ה-EXE לתיקייה זמנית (פעם אחת לכל גרסה), מאמת SHA-256 מול הקובץ שנוצר ב-CI, ומחזיר (נתיב, sha, גודל)."""
    with _exe_lock:
        c = _exe_cache.get(meta["tag"])
        if c and os.path.exists(c[0]):
            return c
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", meta["tag"])
        path = os.path.join(tempfile.gettempdir(), f"pccleaner-{safe}.exe")
        h = hashlib.sha256()
        with gh_open_asset(meta["asset_id"]) as r, open(path + ".part", "wb") as f:
            while True:
                chunk = r.read(1024 * 256)
                if not chunk:
                    break
                h.update(chunk)
                f.write(chunk)
        sha = h.hexdigest()
        if meta.get("sha_id"):
            with gh_open_asset(meta["sha_id"]) as r:
                expected = r.read(500).decode("utf-8", "ignore").strip().split()[0].lower()
            if expected != sha:
                os.remove(path + ".part")
                raise ValueError("SHA-256 לא תואם לקובץ שנוצר ב-CI")
        os.replace(path + ".part", path)
        _exe_cache.clear()
        _exe_cache[meta["tag"]] = (path, sha, os.path.getsize(path))
        return _exe_cache[meta["tag"]]


def sign(value):
    return hmac.new(SECRET_KEY, value.encode(), hashlib.sha256).hexdigest()


def make_session():
    exp = str(int(time.time()) + SESSION_SECS)
    return exp + "." + sign(exp)


def valid_session(cookie_header):
    for part in (cookie_header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "sid" and "." in v:
            exp, sig = v.split(".", 1)
            if exp.isdigit() and int(exp) > time.time() and hmac.compare_digest(sig, sign(exp)):
                return True
    return False


CSS = """
:root{--bg:#0b1220;--card:#131c2e;--line:#22304a;--txt:#e5ecf7;--mut:#8da2c0;--ok:#22c55e;--err:#ef4444;--warn:#f59e0b;--acc:#3b82f6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 Segoe UI,Arial,sans-serif}
a{color:var(--acc);text-decoration:none}header{padding:14px 22px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center}
header h1{font-size:18px;margin:0;flex:1}main{padding:20px 22px;max-width:1300px;margin:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-left:8px;background:#64748b}.dot.on{background:var(--ok)}
.mut{color:var(--mut);font-size:13px}.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;background:#1e293b;margin-left:6px}
.badge.err{background:#7f1d1d}.btn{background:var(--acc);color:#fff;border:0;padding:7px 14px;border-radius:8px;cursor:pointer;font-size:14px}
.btn.gray{background:#334155}input,select{background:#0f172a;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font-size:14px}
#log{background:#060b16;border:1px solid var(--line);border-radius:10px;height:62vh;overflow:auto;padding:10px;font:13px/1.55 Consolas,monospace;direction:ltr;text-align:left}
#log div{white-space:pre-wrap;word-break:break-all}.error{color:#fca5a5}.ok{color:#86efac}.dry{color:#fcd34d}.guard{color:#93c5fd}.info{color:#cbd5e1}
.bar{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0;align-items:center}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid var(--line);text-align:right}
pre{background:#060b16;border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto;direction:ltr;text-align:left;white-space:pre-wrap;font-size:13px}
.login{max-width:340px;margin:18vh auto}.login input{width:100%;margin:8px 0}
"""


def page(title, body, script=""):
    return ("<!doctype html><html lang='he' dir='rtl'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body>{body}"
            f"<script>{script}</script></body></html>")


def login_page(msg=""):
    body = ("<div class='login card'><h2>PC Cleaner Dashboard</h2>"
            f"<div class='mut'>{html.escape(msg)}</div>"
            "<form method='post' action='/login'><input type='password' name='password' placeholder='סיסמה' autofocus>"
            "<button class='btn' style='width:100%'>כניסה</button></form></div>")
    return page("כניסה", body)


HOME_JS = """
const fmt=s=>{if(s<60)return 'לפני '+s+' שנ׳';if(s<3600)return 'לפני '+Math.floor(s/60)+' דק׳';if(s<86400)return 'לפני '+Math.floor(s/3600)+' שע׳';return 'לפני '+Math.floor(s/86400)+' ימים'};
const el=(t,txt,cls)=>{const e=document.createElement(t);if(txt!==undefined)e.textContent=txt;if(cls)e.className=cls;return e};
async function load(){
 const r=await fetch('/api/machines');if(r.status==401){location='/';return}
 const d=await r.json(),L=d.latest||{};
 const u=document.getElementById('upd');u.textContent='';
 if(L.version){
  u.append(el('b','גרסה אחרונה: v'+L.version),el('span',L.published?'  ·  פורסמה '+L.published:'','mut'));
  const a=el('a','⬇ הורד PCCleaner.exe','btn');a.href='/download/PCCleaner.exe';a.style.marginRight='14px';u.append(a);
  const ok=d.machines.filter(m=>m.ver&&m.ver==L.version).length;
  u.append(el('div',ok+' מתוך '+d.machines.length+' מחשבים מעודכנים לגרסה הזאת','mut'));
  if(L.notes)u.append(el('div',L.notes.slice(0,300),'mut'));
  if(L.stale)u.append(el('div','⚠ GitHub לא זמין כרגע, מוצגת הגרסה האחרונה הידועה','mut'));
 }else{u.append(el('b','עדכונים'),el('div',L.error||'אין עדכון זמין','mut'))}
 document.getElementById('count').textContent=d.machines.length+' מחשבים';
 const t=document.getElementById('tbody');t.textContent='';
 if(!d.machines.length){const tr=el('tr');tr.append(el('td','עדיין לא התחבר אף מחשב. הגדר בתוכנה: דשבורד ← כתובת ומפתח.'));t.append(tr)}
 for(const m of d.machines){
  const tr=el('tr');
  const n=el('td');const dot=el('span','','dot'+(m.online?' on':''));const a=el('a',m.host||m.id);a.href='/m/'+encodeURIComponent(m.id);n.append(dot,a);
  const v=el('td','v'+(m.ver||'?'));if(L.version&&m.ver&&m.ver!=L.version){v.append(el('span','ישן','badge err'))}
  tr.append(n,el('td',m.online?'מחובר':fmt(m.ago)),v,el('td',(m.first_seen||'').slice(0,16),'mut'),el('td',m.errors?String(m.errors):'0',m.errors?'badge err':'mut'),el('td',m.id,'mut'));
  t.append(tr)}
}
load();setInterval(load,5000);
"""


def home_page():
    body = ("<header><h1>🧹 PC Cleaner · דשבורד</h1><span id='count' class='mut'></span><a href='/logout'>יציאה</a></header>"
            "<main><div class='card' id='upd' style='margin-bottom:18px'></div>"
            "<h3>מחשבים שהתוכנה מותקנת בהם</h3><div class='card'><table><thead><tr><th>מחשב</th><th>סטטוס</th><th>גרסה</th>"
            "<th>נראה לראשונה</th><th>שגיאות (24ש׳)</th><th>מזהה</th></tr></thead><tbody id='tbody'></tbody></table></div></main>")
    return page("PC Cleaner", body, HOME_JS)


MACHINE_JS = """
const M=%s;let after=0,auto=true;const box=document.getElementById('log');
const lvl=()=>document.getElementById('lvl').value,flt=()=>document.getElementById('flt').value.toLowerCase();
function add(r){const d=document.createElement('div');d.className=r.level;d.dataset.l=r.level;d.textContent=r.ts.slice(11)+'  '+r.line;box.append(d)}
function apply(){for(const d of box.children){const okL=!lvl()||d.dataset.l==lvl();const okT=!flt()||d.textContent.toLowerCase().includes(flt());d.style.display=okL&&okT?'':'none'}}
async function poll(){
 const r=await fetch('/api/logs?m='+encodeURIComponent(M)+'&after='+after);if(r.status==401){location='/';return}
 const d=await r.json();for(const x of d.rows){add(x);after=x.id}
 if(d.rows.length){apply();if(auto)box.scrollTop=box.scrollHeight}
 document.getElementById('st').textContent=d.online?'🟢 מחובר':'⚪ לא מחובר';
}
box.addEventListener('scroll',()=>{auto=box.scrollTop+box.clientHeight>=box.scrollHeight-30});
document.getElementById('lvl').onchange=apply;document.getElementById('flt').oninput=apply;
poll();setInterval(poll,2500);
"""


def machine_page(mid):
    m = q("SELECT * FROM machines WHERE id=?", (mid,), one=True)
    if not m:
        return page("לא נמצא", "<main>מחשב לא נמצא. <a href='/'>חזרה</a></main>")
    reps = q("SELECT id, name, created, length(body) AS n FROM reports WHERE machine=? ORDER BY id DESC LIMIT 20", (mid,))
    rows = "".join(f"<tr><td><a href='/report/{r['id']}'>{html.escape(r['name'])}</a></td><td class='mut'>{html.escape(r['created'])}</td>"
                   f"<td class='mut'>{r['n'] // 1024} KB</td></tr>" for r in reps) or "<tr><td class='mut'>אין דוחות עדיין</td></tr>"
    body = (f"<header><a href='/'>← חזרה</a><h1>{html.escape(m['host'] or m['id'])} <span class='mut'>({html.escape(m['id'])} · v{html.escape(m['ver'] or '')})</span></h1>"
            "<span id='st' class='mut'></span></header><main>"
            "<div class='bar'><select id='lvl'><option value=''>כל הרמות</option><option value='error'>שגיאות</option><option value='guard'>הגנה</option>"
            "<option value='dry'>הדמיה</option><option value='ok'>הצלחות</option><option value='info'>מידע</option></select>"
            "<input id='flt' placeholder='חיפוש בלוג...' style='flex:1;min-width:180px'>"
            f"<a class='btn gray' href='/api/export?m={html.escape(mid)}'>⬇ הורד לוג</a></div>"
            "<div id='log'></div><h3>דוחות סריקה</h3><div class='card'><table>" + rows + "</table></div>"
            f"<form method='post' action='/m/{html.escape(mid)}/delete' onsubmit=\"return confirm('למחוק את כל הנתונים של המחשב הזה?')\" style='margin-top:18px'>"
            "<button class='btn gray'>🗑 מחק נתוני מחשב</button></form></main>")
    return page("מחשב " + (m["host"] or mid), body, MACHINE_JS % json.dumps(mid))


class Handler(BaseHTTPRequestHandler):
    server_version = "PCCleanerDash/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))

    def ip(self):
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path, name):
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 256)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def bearer_ok(self):
        auth = self.headers.get("Authorization", "")
        return auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].strip(), INGEST_KEY)

    def json(self, obj, code=200):
        self.send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def authed(self):
        return valid_session(self.headers.get("Cookie"))

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return None
        return self.rfile.read(n)

    def do_GET(self):
        u = urlparse(self.path)
        p, qs = u.path, parse_qs(u.query)
        if p == "/healthz":
            return self.send(200, "ok", "text/plain")
        if p == "/api/update/latest":
            if not self.bearer_ok():
                return self.json({"error": "unauthorized"}, 401)
            meta = latest_release()
            if "error" in meta and not meta.get("tag"):
                return self.json({"update": False, "error": meta["error"]}, 503)
            cur = (qs.get("cur") or [""])[0]
            if ver_tuple(meta["version"]) <= ver_tuple(cur):
                return self.json({"update": False, "version": meta["version"]})
            try:
                path, sha, size = ensure_exe(meta)
            except Exception as e:
                sys.stderr.write(f"update fetch error: {e!r}\n")
                return self.json({"update": False, "error": "fetch failed"}, 502)
            return self.json({"update": True, "version": meta["version"], "sha256": sha, "size": size, "notes": meta["notes"][:500]})
        if p == "/api/update/download":
            if not self.bearer_ok():
                return self.json({"error": "unauthorized"}, 401)
            meta = latest_release()
            if not meta.get("tag"):
                return self.json({"error": "no release"}, 503)
            try:
                path, sha, size = ensure_exe(meta)
            except Exception:
                return self.json({"error": "fetch failed"}, 502)
            return self.send_file(path, ASSET_NAME)
        if not self.authed():
            if p.startswith("/api/"):
                return self.json({"error": "auth"}, 401)
            return self.send(200, login_page())
        if p == "/":
            return self.send(200, home_page())
        if p == "/logout":
            return self.send(302, "", headers={"Location": "/", "Set-Cookie": "sid=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"})
        if p.startswith("/m/"):
            return self.send(200, machine_page(p[3:]))
        if p.startswith("/report/") and p[8:].isdigit():
            r = q("SELECT * FROM reports WHERE id=?", (int(p[8:]),), one=True)
            if not r:
                return self.send(404, page("לא נמצא", "<main>לא נמצא</main>"))
            body = (f"<header><a href='/m/{html.escape(r['machine'])}'>← חזרה</a><h1>{html.escape(r['name'])}</h1></header>"
                    f"<main><pre>{html.escape(r['body'])}</pre></main>")
            return self.send(200, page(r["name"], body))
        if p == "/api/machines":
            now = time.time()
            out = []
            for m in q("SELECT * FROM machines ORDER BY last_seen DESC"):
                e = q("SELECT COUNT(*) c FROM logs WHERE machine=? AND level='error' AND recv>?", (m["id"], now - 86400), one=True)["c"]
                ago = int(now - m["last_seen"])
                out.append({"id": m["id"], "host": m["host"], "ver": m["ver"], "online": ago < ONLINE_SECS,
                            "ago": ago, "errors": e, "last_line": m["last_line"], "first_seen": m["first_seen"]})
            return self.json({"machines": out, "latest": latest_release()})
        if p == "/download/" + ASSET_NAME:
            meta = latest_release()
            if "error" in meta and not meta.get("tag"):
                return self.send(503, meta["error"], "text/plain; charset=utf-8")
            try:
                path, sha, size = ensure_exe(meta)
            except Exception as e:
                return self.send(502, f"הורדה מ-GitHub נכשלה: {e}", "text/plain; charset=utf-8")
            return self.send_file(path, ASSET_NAME)
        if p == "/api/logs":
            mid = (qs.get("m") or [""])[0]
            after = int((qs.get("after") or ["0"])[0] or 0)
            if after == 0:      # טעינה ראשונה: 500 השורות האחרונות
                rows = list(reversed(q("SELECT id, ts, level, line FROM logs WHERE machine=? ORDER BY id DESC LIMIT 500", (mid,))))
            else:
                rows = q("SELECT id, ts, level, line FROM logs WHERE machine=? AND id>? ORDER BY id LIMIT 1000", (mid, after))
            m = q("SELECT last_seen FROM machines WHERE id=?", (mid,), one=True)
            return self.json({"rows": [dict(r) for r in rows], "online": bool(m and time.time() - m["last_seen"] < ONLINE_SECS)})
        if p == "/api/export":
            mid = (qs.get("m") or [""])[0]
            rows = q("SELECT ts, line FROM logs WHERE machine=? ORDER BY id", (mid,))
            text = "\n".join(f"{r['ts']}  {r['line']}" for r in rows)
            return self.send(200, text, "text/plain; charset=utf-8",
                             {"Content-Disposition": f"attachment; filename=pccleaner-{mid}.log"})
        return self.send(404, "not found", "text/plain")

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/api/ingest":
            if not self.bearer_ok():
                return self.json({"error": "unauthorized"}, 401)
            raw = self.read_body()
            if raw is None:
                return self.json({"error": "too large"}, 413)
            try:
                payload = json.loads(raw.decode("utf-8"))
                n = ingest(payload)
            except Exception as e:
                sys.stderr.write(f"ingest error: {e!r}\n")
                return self.json({"error": "bad request"}, 400)
            return self.json({"ok": True, "n": n})
        if p == "/login":
            ip = self.ip()
            tries = [t for t in _login_fails.get(ip, []) if t > time.time() - 300]
            if len(tries) >= 5:
                return self.send(429, login_page("יותר מדי ניסיונות. נסה שוב בעוד כמה דקות."))
            raw = self.read_body() or b""
            pw = parse_qs(raw.decode("utf-8", "ignore")).get("password", [""])[0]
            if hmac.compare_digest(pw.encode(), DASH_PASSWORD.encode()):
                _login_fails.pop(ip, None)
                secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
                return self.send(302, "", headers={"Location": "/", "Set-Cookie": f"sid={make_session()}; Max-Age={SESSION_SECS}; Path=/; HttpOnly; SameSite=Strict{secure}"})
            tries.append(time.time())
            _login_fails[ip] = tries
            time.sleep(1)
            return self.send(200, login_page("סיסמה שגויה"))
        if p.startswith("/m/") and p.endswith("/delete"):
            if not self.authed():
                return self.send(302, "", headers={"Location": "/"})
            mid = p[3:-7]
            for t in ("logs", "reports"):
                q(f"DELETE FROM {t} WHERE machine=?", (mid,), write=True)
            q("DELETE FROM machines WHERE id=?", (mid,), write=True)
            return self.send(302, "", headers={"Location": "/"})
        return self.send(404, "not found", "text/plain")


def main():
    if len(INGEST_KEY) < 16 or len(DASH_PASSWORD) < 6:
        sys.exit("חובה להגדיר INGEST_KEY (לפחות 16 תווים) ו-DASH_PASSWORD (לפחות 6 תווים) כמשתני סביבה.")
    print(f"Dashboard on :{PORT}, db={DB_PATH}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
