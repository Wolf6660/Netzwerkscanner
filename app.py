import ipaddress
import json
import re
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

try:
    from fritzconnection.lib.fritzhosts import FritzHosts
except ImportError:  # Routerintegration bleibt optional
    FritzHosts = None

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "netscan.sqlite3"
DEFAULT_PORTS = "22,80,443,445,3389"
DEFAULT_NETWORKS = [
    {"name": "Standort A", "range": "10.10.0.0/24"},
    {"name": "Standort B", "range": "10.20.0.0/24"},
    {"name": "Management", "range": "192.168.1.0/24"},
]

DATA_DIR.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="NetScan")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def columns(conn: sqlite3.Connection, table: str) -> set:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def add_column(conn: sqlite3.Connection, table: str, definition: str) -> None:
    name = definition.split()[0]
    if name not in columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def init_db() -> None:
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT, key_type TEXT NOT NULL,
            key_value TEXT NOT NULL, alias_name TEXT NOT NULL, notes TEXT DEFAULT '',
            updated_at TEXT DEFAULT (datetime('now')), UNIQUE(key_type, key_value))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS seen (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE,
            last_seen TEXT DEFAULT (datetime('now')))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS presets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            ip_range TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0)""")
        for definition in (
            "tcp_ping INTEGER NOT NULL DEFAULT 1", "ports TEXT NOT NULL DEFAULT '22,80,443,445,3389'",
            "reverse_dns INTEGER NOT NULL DEFAULT 1", "router_type TEXT NOT NULL DEFAULT 'none'",
            "router_host TEXT NOT NULL DEFAULT ''", "router_user TEXT NOT NULL DEFAULT ''",
            "router_password TEXT NOT NULL DEFAULT ''",
        ):
            add_column(conn, "presets", definition)
        conn.execute("""CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT, network_id INTEGER NOT NULL,
            identity TEXT NOT NULL, mac TEXT DEFAULT '', ip TEXT NOT NULL,
            hostname TEXT DEFAULT '', vendor TEXT DEFAULT '', device_type TEXT DEFAULT '',
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            UNIQUE(network_id, identity), FOREIGN KEY(network_id) REFERENCES presets(id) ON DELETE CASCADE)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS device_aliases (
            network_id INTEGER NOT NULL, identity TEXT NOT NULL, alias_name TEXT NOT NULL,
            notes TEXT DEFAULT '', updated_at TEXT DEFAULT (datetime('now')),
            PRIMARY KEY(network_id, identity), FOREIGN KEY(network_id) REFERENCES presets(id) ON DELETE CASCADE)""")


init_db()


def validate_range(value: str) -> str:
    value = (value or "").strip()
    try:
        if "-" in value:
            start, end = (ipaddress.ip_address(x.strip()) for x in value.split("-", 1))
            if start.version != 4 or end.version != 4 or int(start) > int(end):
                raise ValueError
            return f"{start}-{end}"
        net = ipaddress.ip_network(value, strict=False)
        if net.version != 4 or net.prefixlen < 16:
            raise ValueError("Aus Sicherheitsgründen sind nur IPv4-Netze ab /16 erlaubt.")
        return str(net)
    except ValueError as exc:
        if str(exc).startswith("Aus Sicherheitsgründen"):
            raise
        raise ValueError("Ungültiger IPv4-Bereich (Beispiel: 192.168.1.0/24).") from exc


def normalize_mac(value: str) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2)) if len(raw) == 12 else ""


def target_contains(target_range: str, ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    if "-" in target_range:
        start, end = (ipaddress.ip_address(x.strip()) for x in target_range.split("-", 1))
        return int(start) <= int(address) <= int(end)
    return address in ipaddress.ip_network(target_range, strict=False)


def get_networks(include_password: bool = False) -> List[Dict]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM presets ORDER BY sort_order,id").fetchall()
        if not rows:
            for i, item in enumerate(DEFAULT_NETWORKS):
                conn.execute("INSERT INTO presets(name,ip_range,sort_order) VALUES(?,?,?)",
                             (item["name"], item["range"], i))
            rows = conn.execute("SELECT * FROM presets ORDER BY sort_order,id").fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["range"] = item.pop("ip_range")
        item["has_router_password"] = bool(item.get("router_password"))
        if not include_password:
            item.pop("router_password", None)
        result.append(item)
    return result


def get_network(network_id: int) -> Dict:
    with db() as conn:
        row = conn.execute("SELECT * FROM presets WHERE id=?", (network_id,)).fetchone()
    if not row:
        raise ValueError("Netzwerk wurde nicht gefunden.")
    return dict(row)


def save_networks(items: List[Dict]) -> None:
    cleaned = []
    for item in items:
        name = str(item.get("name") or "").strip()
        ip_range = str(item.get("range") or "").strip()
        if not name and not ip_range:
            continue
        ip_range = validate_range(ip_range)
        router_type = str(item.get("router_type") or "none")
        if router_type not in ("none", "fritzbox"):
            raise ValueError("Unbekannter Routertyp.")
        cleaned.append({
            "id": int(item["id"]) if item.get("id") else None,
            "name": name or ip_range, "range": ip_range,
            "tcp_ping": int(bool(item.get("tcp_ping", True))),
            "ports": str(item.get("ports") or DEFAULT_PORTS).strip(),
            "reverse_dns": int(bool(item.get("reverse_dns", True))),
            "router_type": router_type,
            "router_host": str(item.get("router_host") or "").strip(),
            "router_user": str(item.get("router_user") or "").strip(),
            "router_password": str(item.get("router_password") or ""),
        })
    with db() as conn:
        existing = {row["id"] for row in conn.execute("SELECT id FROM presets")}
        kept = set()
        for order, item in enumerate(cleaned):
            if item["id"] in existing:
                kept.add(item["id"])
                password_sql = "router_password=router_password" if not item["router_password"] else "router_password=?"
                params = [item[k] for k in ("name", "range", "tcp_ping", "ports", "reverse_dns", "router_type", "router_host", "router_user")]
                if item["router_password"]:
                    params.append(item["router_password"])
                params += [order, item["id"]]
                conn.execute(f"""UPDATE presets SET name=?,ip_range=?,tcp_ping=?,ports=?,reverse_dns=?,
                    router_type=?,router_host=?,router_user=?,{password_sql},sort_order=? WHERE id=?""", params)
            else:
                cur = conn.execute("""INSERT INTO presets(name,ip_range,tcp_ping,ports,reverse_dns,
                    router_type,router_host,router_user,router_password,sort_order) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (item["name"], item["range"], item["tcp_ping"], item["ports"], item["reverse_dns"],
                     item["router_type"], item["router_host"], item["router_user"], item["router_password"], order))
                kept.add(cur.lastrowid)
        for old_id in existing - kept:
            conn.execute("DELETE FROM presets WHERE id=?", (old_id,))


def fritz_hosts(network: Dict) -> Dict[str, Dict]:
    if network["router_type"] != "fritzbox":
        return {}
    if FritzHosts is None:
        raise RuntimeError("FRITZ!Box-Unterstützung ist nicht installiert.")
    if not network["router_host"] or not network["router_user"]:
        raise RuntimeError("FRITZ!Box-Adresse oder Benutzer fehlt.")
    try:
        hosts = FritzHosts(address=network["router_host"], user=network["router_user"],
                           password=network["router_password"]).get_hosts_info()
    except Exception as exc:
        raise RuntimeError(f"FRITZ!Box nicht erreichbar oder Anmeldung fehlgeschlagen: {exc}") from exc
    result = {}
    for host in hosts:
        ip = str(host.get("ip") or "").strip()
        if ip:
            result[ip] = {"mac": normalize_mac(host.get("mac") or ""),
                          "hostname": str(host.get("name") or "").strip(), "source": "FRITZ!Box"}
    return result


def guess_device_type(hostname: str, vendor: str, mac: str) -> str:
    text = f"{hostname} {vendor}".lower()
    rules = (("shelly", "Shelly/Smart Home"), ("iphone", "iPhone"), ("ipad", "iPad"),
             ("apple", "Apple-Gerät"), ("fritz", "FRITZ!Box/AVM"), ("asus", "ASUS-Gerät"),
             ("synology", "Synology NAS"), ("printer", "Drucker"), ("drucker", "Drucker"),
             ("camera", "Kamera"), ("raspberry", "Raspberry Pi"))
    for needle, label in rules:
        if needle in text:
            return label
    if mac and vendor:
        return "Netzwerkgerät"
    return "Unbekannt"


def scan_network(network: Dict) -> tuple[List[Dict], List[str]]:
    cmd = ["nmap", "-sn", "-oX", "-"]
    if not network["reverse_dns"]:
        cmd.append("-n")
    if network["tcp_ping"]:
        ports = re.sub(r"[^0-9,\-]", "", network["ports"] or DEFAULT_PORTS)
        cmd.append(f"-PS{ports or DEFAULT_PORTS}")
    cmd.append(network["ip_range"])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or "nmap-Fehler")
    warnings = []
    router = {}
    if network["router_type"] == "fritzbox":
        try:
            router = fritz_hosts(network)
        except RuntimeError as exc:
            warnings.append(str(exc))
    found = {}
    root = ET.fromstring(proc.stdout)
    for host in root.findall("host"):
        if host.find("status").get("state") != "up":
            continue
        addresses = {a.get("addrtype"): a for a in host.findall("address")}
        ipv4 = addresses.get("ipv4")
        if ipv4 is None:
            continue
        ip = ipv4.get("addr")
        mac_node = addresses.get("mac")
        mac = normalize_mac(mac_node.get("addr") if mac_node is not None else "")
        vendor = mac_node.get("vendor", "") if mac_node is not None else ""
        names = host.findall("hostnames/hostname")
        hostname = names[0].get("name", "") if names else ""
        extra = router.get(ip, {})
        found[ip] = {"ip": ip, "mac": mac or extra.get("mac", ""),
                     "hostname": hostname or extra.get("hostname", ""), "vendor": vendor,
                     "source": "nmap + FRITZ!Box" if extra else "nmap"}
    for ip, extra in router.items():
        try:
            if target_contains(network["ip_range"], ip):
                found.setdefault(ip, {"ip": ip, "mac": extra["mac"], "hostname": extra["hostname"],
                                      "vendor": "", "source": "FRITZ!Box"})
        except ValueError:
            pass
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    results = []
    with db() as conn:
        for item in found.values():
            identity = f"mac:{item['mac']}" if item["mac"] else f"ip:{item['ip']}"
            item["device_type"] = guess_device_type(item["hostname"], item["vendor"], item["mac"])
            conn.execute("""INSERT INTO devices(network_id,identity,mac,ip,hostname,vendor,device_type,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(network_id,identity) DO UPDATE SET ip=excluded.ip,
                mac=excluded.mac,hostname=excluded.hostname,vendor=excluded.vendor,
                device_type=excluded.device_type,last_seen=excluded.last_seen""",
                (network["id"], identity, item["mac"], item["ip"], item["hostname"], item["vendor"],
                 item["device_type"], now, now))
            alias = conn.execute("SELECT alias_name,notes FROM device_aliases WHERE network_id=? AND identity=?",
                                 (network["id"], identity)).fetchone()
            if not alias and item["mac"]:
                old = conn.execute("SELECT alias_name,notes FROM device_aliases WHERE network_id=? AND identity=?",
                                   (network["id"], f"ip:{item['ip']}")).fetchone()
                if old:
                    conn.execute("INSERT OR REPLACE INTO device_aliases VALUES(?,?,?,?,datetime('now'))",
                                 (network["id"], identity, old["alias_name"], old["notes"]))
                    alias = old
            if not alias:
                alias = conn.execute("SELECT alias_name,notes FROM aliases WHERE key_type='ip' AND key_value=?",
                                     (item["ip"],)).fetchone()
            item.update({"identity": identity, "alias": alias["alias_name"] if alias else "",
                         "notes": alias["notes"] if alias else "", "last_seen": now, "up": True})
            results.append(item)
    results.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return results, warnings


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "networks": get_networks()})


@app.post("/scan/{network_id}")
def scan(network_id: int):
    try:
        network = get_network(network_id)
        results, warnings = scan_network(network)
        return JSONResponse({"ok": True, "network": network["name"], "range": network["ip_range"],
                             "results": results, "warnings": warnings})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/alias/set")
def alias_set(network_id: int = Form(...), identity: str = Form(...), alias_name: str = Form(""), notes: str = Form("")):
    alias_name = alias_name.strip()
    with db() as conn:
        if alias_name:
            conn.execute("""INSERT INTO device_aliases(network_id,identity,alias_name,notes) VALUES(?,?,?,?)
                ON CONFLICT(network_id,identity) DO UPDATE SET alias_name=excluded.alias_name,
                notes=excluded.notes,updated_at=datetime('now')""", (network_id, identity, alias_name, notes.strip()))
        else:
            conn.execute("DELETE FROM device_aliases WHERE network_id=? AND identity=?", (network_id, identity))
    return JSONResponse({"ok": True})


@app.post("/alias/delete")
def alias_delete(network_id: int = Form(...), identity: str = Form(...)):
    with db() as conn:
        conn.execute("DELETE FROM device_aliases WHERE network_id=? AND identity=?", (network_id, identity))
    return JSONResponse({"ok": True})


@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request, "networks": get_networks()})


@app.post("/settings/save")
def settings_save(payload: str = Form("")):
    try:
        items = json.loads(payload or "[]")
        if not isinstance(items, list):
            raise ValueError("Ungültiges Datenformat.")
        save_networks(items)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
