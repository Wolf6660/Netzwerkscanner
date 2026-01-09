import re
import json
import sqlite3
import subprocess
from pathlib import Path
from typing import List, Dict, Optional

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "netscan.sqlite3"

DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="NetScan Web")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

# ---------------------------
# Konfiguration
# ---------------------------

# Default Presets (nur Initialbefüllung, wenn DB noch leer ist)
DEFAULT_PRESETS = [
    {"name": "Standort A (10.10.0.0/24)", "range": "10.10.0.0/24"},
    {"name": "Standort B (10.20.0.0/24)", "range": "10.20.0.0/24"},
    {"name": "Mgmt (192.168.1.0/24)", "range": "192.168.1.0/24"},
]

DEFAULT_PORTS = "22,80,443,445,3389"

# ---------------------------
# DB
# ---------------------------

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,         -- 'ip' (später erweiterbar)
                key_value TEXT NOT NULL,        -- z.B. '10.10.0.15'
                alias_name TEXT NOT NULL,
                notes TEXT DEFAULT '',
                updated_at TEXT DEFAULT (datetime('now')),
                UNIQUE(key_type, key_value)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS seen (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                last_seen TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS presets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip_range TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0
            )
        """)

init_db()

# ---------------------------
# Input Validation
# ---------------------------

CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
RANGE_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}\s*-\s*\d{1,3}(\.\d{1,3}){3}$")

def validate_range(r: str) -> str:
    r = (r or "").strip()
    if not r:
        raise ValueError("Range ist leer.")
    if CIDR_RE.match(r) or RANGE_RE.match(r):
        return r
    raise ValueError(
        "Ungültiges Format. Erlaubt: CIDR (z.B. 10.10.0.0/24) "
        "oder Start-Ende (z.B. 10.10.0.10-10.10.0.50)."
    )

# ---------------------------
# Alias / Seen
# ---------------------------

def get_alias_for_ip(ip: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(
            "SELECT key_type, key_value, alias_name, notes, updated_at "
            "FROM aliases WHERE key_type='ip' AND key_value=?",
            (ip,)
        ).fetchone()
        return dict(row) if row else None

def upsert_alias_ip(ip: str, alias_name: str, notes: str = ""):
    alias_name = (alias_name or "").strip()
    notes = (notes or "").strip()
    if not alias_name:
        return
    with db() as conn:
        conn.execute("""
            INSERT INTO aliases (key_type, key_value, alias_name, notes)
            VALUES ('ip', ?, ?, ?)
            ON CONFLICT(key_type, key_value) DO UPDATE SET
                alias_name=excluded.alias_name,
                notes=excluded.notes,
                updated_at=datetime('now')
        """, (ip, alias_name, notes))

def delete_alias_ip(ip: str):
    with db() as conn:
        conn.execute("DELETE FROM aliases WHERE key_type='ip' AND key_value=?", (ip,))

def mark_seen(ip: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO seen (ip) VALUES (?)
            ON CONFLICT(ip) DO UPDATE SET last_seen=datetime('now')
        """, (ip,))

def get_last_seen(ip: str) -> Optional[str]:
    with db() as conn:
        row = conn.execute("SELECT last_seen FROM seen WHERE ip=?", (ip,)).fetchone()
        return row["last_seen"] if row else None

# ---------------------------
# Presets
# ---------------------------

def get_presets() -> List[Dict]:
    """
    Lädt Presets aus der DB. Wenn noch keine vorhanden sind,
    werden DEFAULT_PRESETS einmalig in die DB geschrieben.
    """
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, ip_range, sort_order "
            "FROM presets ORDER BY sort_order ASC, id ASC"
        ).fetchall()

    if not rows:
        with db() as conn:
            for i, p in enumerate(DEFAULT_PRESETS):
                conn.execute(
                    "INSERT INTO presets (name, ip_range, sort_order) VALUES (?, ?, ?)",
                    (p["name"], p["range"], i),
                )
        with db() as conn:
            rows = conn.execute(
                "SELECT id, name, ip_range, sort_order "
                "FROM presets ORDER BY sort_order ASC, id ASC"
            ).fetchall()

    return [
        {"id": r["id"], "name": r["name"], "range": r["ip_range"], "sort_order": r["sort_order"]}
        for r in rows
    ]

def save_presets(presets: List[Dict]):
    """
    presets = [{"name": "...", "range": "..."}...]
    Einfach & robust: alte löschen, neu schreiben.
    Validiert jeden Range.
    """
    cleaned: List[Dict] = []
    for p in presets:
        name = (p.get("name") or "").strip()
        ipr = (p.get("range") or "").strip()
        if not name and not ipr:
            continue

        ipr = validate_range(ipr)
        if not name:
            name = ipr

        cleaned.append({"name": name, "range": ipr})

    with db() as conn:
        conn.execute("DELETE FROM presets")
        for i, p in enumerate(cleaned):
            conn.execute(
                "INSERT INTO presets (name, ip_range, sort_order) VALUES (?, ?, ?)",
                (p["name"], p["range"], i),
            )

# ---------------------------
# Scanner
# ---------------------------

def run_nmap_scan(target_range: str, tcp_ping: bool, ports: str, reverse_dns: bool) -> List[Dict]:
    """
    Liefert Liste: [{ip, up, hostname, alias, notes, last_seen, rtt_ms}]
    """
    cmd = ["nmap", "-sn", "-oG", "-"]

    # -n deaktiviert DNS; nur aktivieren, wenn reverse_dns True
    if not reverse_dns:
        cmd += ["-n"]

    if tcp_ping:
        ports_clean = (ports or DEFAULT_PORTS).strip()
        cmd += [f"-PS{ports_clean}"]

    cmd += [target_range]

    proc = subprocess.run(cmd, capture_output=True, text=True)

    # nmap kann 1 liefern, wenn Hosts down sind -> kein fataler Fehler
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or "nmap Fehler")

    results: List[Dict] = []

    for line in proc.stdout.splitlines():
        if not line.startswith("Host:"):
            continue

        m = re.search(r"Host:\s+(\S+)\s+\((.*?)\)\s+Status:\s+(\w+)", line)
        if not m:
            continue

        ip, hostname, status = m.group(1), m.group(2), m.group(3)
        up = (status.lower() == "up")

        if up:
            mark_seen(ip)

        alias = get_alias_for_ip(ip)
        last_seen = get_last_seen(ip)

        results.append({
            "ip": ip,
            "up": up,
            "hostname": hostname if hostname else "",
            "alias": alias["alias_name"] if alias else "",
            "notes": alias["notes"] if alias else "",
            "last_seen": last_seen or "",
            "rtt_ms": None,
        })

    def ip_key(x):
        return tuple(int(p) for p in x["ip"].split("."))

    results.sort(key=lambda x: (not x["up"], ip_key(x)))
    return results

# ---------------------------
# Routes
# ---------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "presets": get_presets(),
        "default_ports": DEFAULT_PORTS
    })

@app.post("/scan")
def scan(
    target_range: str = Form(""),
    tcp_ping: Optional[str] = Form(None),
    ports: str = Form(DEFAULT_PORTS),
    reverse_dns: Optional[str] = Form(None),
):
    try:
        r = validate_range(target_range)
        results = run_nmap_scan(
            target_range=r,
            tcp_ping=bool(tcp_ping),
            ports=ports,
            reverse_dns=bool(reverse_dns),
        )
        return JSONResponse({"ok": True, "range": r, "results": results})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})

@app.post("/alias/set")
def alias_set(ip: str = Form(""), alias_name: str = Form(""), notes: str = Form("")):
    ip = (ip or "").strip()
    if not ip:
        return JSONResponse({"ok": False, "error": "IP fehlt"})
    upsert_alias_ip(ip, alias_name, notes)
    return JSONResponse({"ok": True})

@app.post("/alias/delete")
def alias_delete(ip: str = Form("")):
    ip = (ip or "").strip()
    if not ip:
        return JSONResponse({"ok": False, "error": "IP fehlt"})
    delete_alias_ip(ip)
    return JSONResponse({"ok": True})

# ---------------------------
# Einstellungen
# ---------------------------

@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request):
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "presets": get_presets(),
    })

@app.post("/settings/save")
def settings_save(payload: str = Form("")):
    """
    payload enthält JSON: [{"name":"..","range":".."}, ...]
    """
    try:
        presets = json.loads(payload or "[]")
        if not isinstance(presets, list):
            return JSONResponse({"ok": False, "error": "Ungültiges Format"})
        save_presets(presets)
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})
