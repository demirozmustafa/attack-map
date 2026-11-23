#!/usr/bin/env python3
"""Live attack map.

Firewall / IDS syslog (UDP) or Suricata eve.json  ->  parse  ->  GeoIP  ->  browser (Server-Sent Events).
Every setting lives in DATA_DIR/config.json and is edited from the web UI (/settings).

Supported inputs
  * pfSense / OPNsense  filterlog  (blocked, inbound packets)
  * Suricata EVE JSON   alerts     (via syslog or by tailing eve.json)
  * FortiGate           key=value  (deny/blocked traffic, IPS, anomaly, WAF, AV)

Only dependency outside the standard library: `maxminddb`.
"""
import base64
import collections
import copy
import datetime as dt
import hashlib
import hmac
import io
import ipaddress
import json
import os
import queue
import random
import re
import secrets
import socket
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
DATA = Path(os.getenv("DATA_DIR", str(HERE / "data"))).resolve()
DATA.mkdir(parents=True, exist_ok=True)

HTTP_HOST = os.getenv("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5514"))
PUBLIC_SYSLOG_PORT = int(os.getenv("PUBLIC_SYSLOG_PORT", str(SYSLOG_PORT)))  # host port, shown in the GUI help
EVE_ROOT = os.getenv("EVE_ROOT", "")  # when set, eve.json must live under this folder (Docker: /eve)
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"  # only behind the bundled HTTPS proxy

TYPE_KEYS = ("brute", "web", "scan", "ddos", "c2")
SOURCE_KEYS = ("filterlog", "suricata", "fortigate")


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


# ================================================================ config

DEFAULTS = {
    "site": {"name": "EDGE-1", "lat": 41.01, "lon": 28.98},
    "allowed_senders": [],
    "locations": [],  # extra sites: {"name","lat","lon","senders":[ip/cidr]}; unmatched senders go to "site"
    "sources": {k: True for k in SOURCE_KEYS},
    "eve_file": "",
    "max_eps": 40,
    "public_map": False,
    "demo": False,
    "geoip": {"account_id": "", "license_key": "", "auto_update": True, "last_update": None, "file": ""},
    "admin": {"salt": "", "hash": ""},
}


def merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = merge(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else v
    return out


class Config:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stored = {}
        self.data = merge(DEFAULTS, stored)
        self._derive()
        self._save()

    def __getitem__(self, k):
        return self.data[k]

    def update(self, fn):
        with self.lock:
            fn(self.data)
            self._save()
            self._derive()

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def _derive(self):
        nets = []
        for s in self.data["allowed_senders"]:
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                pass
        self.allowed = nets
        locs = []
        for i, loc in enumerate(self.data.get("locations") or []):
            ln = []
            for s in loc.get("senders", []):
                try:
                    ln.append(ipaddress.ip_network(s, strict=False))
                except ValueError:
                    pass
            locs.append((i + 1, ln))
        self.loc_nets = locs

    def sites(self):
        """Main site first, then the extra locations. An event's "loc" is an index into this list."""
        out = [dict(self.data["site"])]
        for loc in self.data.get("locations") or []:
            out.append({"name": loc["name"], "lat": loc["lat"], "lon": loc["lon"]})
        return out

    def location_for(self, addr):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return 0
        for idx, nets in self.loc_nets:
            if any(ip in n for n in nets):
                return idx
        return 0

    @property
    def configured(self):
        return bool(self.data["admin"]["hash"])

    def sender_allowed(self, addr):
        if not self.allowed:  # empty allow list = accept everyone (as before locations existed)
            return True
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in n for n in self.allowed) or any(ip in n for _, nets in self.loc_nets for n in nets)

    def public_view(self):
        d = copy.deepcopy(self.data)
        d.pop("admin")
        key = d["geoip"]["license_key"]
        d["geoip"]["license_key"] = ""
        d["geoip"]["license_key_set"] = bool(key)
        return d


CONF = Config(DATA / "config.json")


def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 300_000).hex()
    return salt, h


def check_password(pw):
    a = CONF["admin"]
    if not a["hash"]:
        return False
    return hmac.compare_digest(hash_password(pw, a["salt"])[1], a["hash"])


# ================================================================ classification + parsers

BRUTE_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 2222, 3306, 3389, 5432, 5900}
WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}
AMP_PORTS = {19, 53, 123, 161, 389, 1900, 11211}

KW = [
    ("c2", re.compile(r"trojan|malware|command and control|\bc2\b|\bcnc\b|botnet|virus|ransom", re.I)),
    ("ddos", re.compile(r"denial of service|\bd?dos\b|flood|anomaly", re.I)),
    ("brute", re.compile(r"brute|ssh|rdp|telnet|login|password|auth", re.I)),
    ("web", re.compile(r"web application|sql|xss|http|php|wordpress|apache|nginx|waf|log4j|struts", re.I)),
    ("scan", re.compile(r"scan|recon|probe|nmap|masscan|zgrab", re.I)),
]


def classify(port, proto, text=""):
    if text:
        for key, rx in KW:
            if rx.search(text):
                return key
    if port in BRUTE_PORTS:
        return "brute"
    if port in WEB_PORTS:
        return "web"
    if proto == "udp" and port in AMP_PORTS:
        return "ddos"
    return "scan"


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# BSD style "filterlog[123]: 5,,,..." and RFC 5424 style "filterlog 123 - - 5,,,..."
FILTERLOG = re.compile(r"filterlog.*?[\s:](\d+,\S+)")


def parse_filterlog(msg):
    """pfSense / OPNsense filterlog CSV. Keeps inbound blocks only."""
    m = FILTERLOG.search(msg)
    if not m:
        return None
    f = m.group(1).split(",")
    if len(f) < 10 or f[6] != "block" or f[7] != "in":
        return None
    if f[8] == "4" and len(f) >= 20:
        proto, src, rest = f[16].lower(), f[18], f[20:]
    elif f[8] == "6" and len(f) >= 17:
        proto, src, rest = f[12].lower(), f[15], f[17:]
    else:
        return None
    port = to_int(rest[1]) if proto in ("tcp", "udp") and len(rest) >= 2 else None
    return {"src": src, "port": port, "proto": proto, "detail": f"Blocked on {f[4]}", "sensor": "firewall", "text": ""}


def parse_eve(obj):
    """Suricata EVE alert object."""
    if not isinstance(obj, dict) or obj.get("event_type") != "alert":
        return None
    a = obj.get("alert") or {}
    sig, cat = str(a.get("signature", "")), str(a.get("category", ""))
    return {
        "src": obj.get("src_ip"),
        "port": to_int(obj.get("dest_port")),
        "proto": str(obj.get("proto", "")).lower(),
        "detail": sig or cat or "IDS alert",
        "sensor": "ids",
        "text": f"{cat} {sig}",
    }


KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
FORTI_BLOCK = {"deny", "blocked", "block", "dropped", "drop", "reset", "clear_session", "server-rst", "client-rst"}


def parse_forti(msg):
    """FortiGate key=value log."""
    kv = {m.group(1): (m.group(2) if m.group(2) is not None else m.group(3)) for m in KV.finditer(msg)}
    if "srcip" not in kv:
        return None
    sub, action = kv.get("subtype", "").lower(), kv.get("action", "").lower()
    if sub not in ("ips", "anomaly", "waf", "virus", "webfilter") and action not in FORTI_BLOCK:
        return None
    text = " ".join(filter(None, [kv.get("attack"), kv.get("msg"), kv.get("catdesc"), "anomaly" if sub == "anomaly" else ""]))
    detail = kv.get("attack") or kv.get("msg") or f"{action or sub} {kv.get('policyname', '')}".strip()
    return {
        "src": kv.get("srcip"),
        "port": to_int(kv.get("dstport")),
        "proto": {"6": "tcp", "17": "udp", "1": "icmp"}.get(kv.get("proto", ""), kv.get("proto", "").lower()),
        "detail": detail,
        "sensor": (kv.get("devname") or "fortigate")[:32],  # several FortiGates: the feed shows which one saw it
        "text": text,
    }


def parse_line(msg, sources=None):
    on = sources or {k: True for k in SOURCE_KEYS}
    if '"event_type"' in msg:
        if not on.get("suricata"):
            return None
        i = msg.find("{")
        if i >= 0:
            try:
                return parse_eve(json.loads(msg[i:]))
            except ValueError:
                return None
    if "filterlog" in msg:
        return parse_filterlog(msg) if on.get("filterlog") else None
    if "srcip=" in msg:
        return parse_forti(msg) if on.get("fortigate") else None
    return None


# ================================================================ GeoIP

GEO_DL_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"


class Geo:
    def __init__(self):
        self.reader = None
        self.lookup = lambda ip: None
        self.state = "missing"  # missing | ready | downloading | error
        self.message = "GeoIP veritabanı yok."
        self.meta = {}
        self.dl_lock = threading.Lock()
        self.load()

    def _mmdb(self):
        try:
            import maxminddb  # noqa: PLC0415
            return maxminddb
        except ImportError:
            self.state, self.message = "error", "maxminddb Python paketi kurulu değil."
            return None

    def load(self):
        name = CONF["geoip"].get("file")
        path = DATA / name if name else None
        if not path or not path.is_file():
            return
        mm = self._mmdb()
        if not mm:
            return
        try:
            self._swap(mm.open_database(str(path)))
        except Exception as e:  # corrupt file
            self.state, self.message = "error", f"Veritabanı açılamadı: {e}"

    def _swap(self, reader):
        md = reader.metadata()
        old, self.reader = self.reader, reader
        self.meta = {"type": md.database_type, "built": dt.datetime.fromtimestamp(md.build_epoch, dt.timezone.utc).strftime("%Y-%m-%d")}

        @lru_cache(maxsize=200_000)
        def lookup(ip):
            r = reader.get(ip) or {}
            loc = r.get("location") or {}
            c = r.get("country") or r.get("registered_country") or {}
            if "latitude" not in loc or not c.get("iso_code"):
                return None
            return {"lat": round(loc["latitude"], 2), "lon": round(loc["longitude"], 2), "cc": c["iso_code"],
                    "country": (c.get("names") or {}).get("en", c["iso_code"])}

        self.lookup = lookup
        self.state, self.message = "ready", f"{self.meta['type']} · {self.meta['built']}"
        if old:
            try:
                old.close()
            except Exception:
                pass

    def install(self, data):
        """Validate .mmdb bytes, store them under a new name and switch to them."""
        mm = self._mmdb()
        if not mm:
            raise ValueError(self.message)
        name = f"GeoLite2-City-{int(time.time())}.mmdb"
        path = DATA / name
        path.write_bytes(data)
        try:
            r = mm.open_database(str(path))
            if "City" not in r.metadata().database_type:
                r.close()
                raise ValueError("Bu bir City veritabanı değil. GeoLite2-City (.mmdb) gerekli; Country sürümünde konum yok.")
        except ValueError:
            path.unlink(missing_ok=True)
            raise
        except Exception as e:
            path.unlink(missing_ok=True)
            log("Rejected GeoIP upload:", e)
            raise ValueError("Geçerli bir MaxMind .mmdb dosyası değil.") from e
        old_name = CONF["geoip"].get("file")
        self._swap(r)
        self.last_error = ""

        def upd(c):
            c["geoip"]["file"] = name
            c["geoip"]["last_update"] = int(time.time())
        CONF.update(upd)
        if old_name and old_name != name:
            try:
                (DATA / old_name).unlink(missing_ok=True)
            except OSError:
                pass  # still mapped on Windows; harmless

    def download(self):
        g = CONF["geoip"]
        if not (g["account_id"] and g["license_key"]):
            raise ValueError("Önce MaxMind Account ID ve License Key girin.")
        if not self.dl_lock.acquire(blocking=False):
            raise ValueError("İndirme zaten sürüyor.")
        prev = (self.state, self.message)
        self.state, self.message = "downloading", "MaxMind'dan indiriliyor…"

        def run():
            try:
                req = urllib.request.Request(GEO_DL_URL, headers={"User-Agent": "attack-map/1.0"})
                token = base64.b64encode(f"{g['account_id']}:{g['license_key']}".encode()).decode()
                req.add_unredirected_header("Authorization", "Basic " + token)  # not forwarded to the storage redirect
                with urllib.request.urlopen(req, timeout=120) as resp:
                    blob = resp.read(250 * 1024 * 1024)
                with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
                    member = next((m for m in tf.getmembers() if m.isfile() and m.name.endswith(".mmdb")), None)
                    if not member:
                        raise ValueError("Arşivde .mmdb bulunamadı.")
                    data = tf.extractfile(member).read()
                self.install(data)
                log("GeoIP database updated:", self.message)
            except urllib.error.HTTPError as e:
                msg = "Account ID veya License Key hatalı." if e.code in (401, 403) else f"MaxMind HTTP {e.code}"
                self.state, self.message = ("error", msg) if prev[0] != "ready" else prev
                self.last_error = msg
                log("GeoIP download failed:", msg)
            except Exception as e:
                msg = f"İndirme başarısız: {e}"
                self.state, self.message = ("error", msg) if prev[0] != "ready" else prev
                self.last_error = msg
                log("GeoIP download failed:", e)
            finally:
                self.dl_lock.release()

        self.last_error = ""
        threading.Thread(target=run, daemon=True).start()

    def auto_update_loop(self):
        while True:
            g = CONF["geoip"]
            stale = not g.get("last_update") or time.time() - g["last_update"] > 7 * 86400
            if g["auto_update"] and g["account_id"] and g["license_key"] and (stale or self.state != "ready"):
                try:
                    self.download()
                except ValueError:
                    pass
            time.sleep(6 * 3600)


GEO = Geo()

# ================================================================ state + fan-out


class Status:
    def __init__(self):
        self.lock = threading.Lock()
        self.received = self.parsed = self.ignored = self.unlocated = self.private = self.rejected = 0
        self.senders = {}
        self.started = time.time()

    def sender(self, addr, allowed, parsed=None):
        with self.lock:
            s = self.senders.get(addr)
            if s is None:
                if len(self.senders) >= 50:
                    return
                s = self.senders[addr] = {"count": 0, "parsed": 0, "last": 0, "allowed": allowed}
            s["count"] += 1
            s["last"] = int(time.time())
            s["allowed"] = allowed
            if parsed:
                s["parsed"] += 1

    def snapshot(self):
        with self.lock:
            return {
                "received": self.received, "parsed": self.parsed, "ignored": self.ignored,
                "unlocated": self.unlocated, "private": self.private, "rejected": self.rejected,
                "senders": [{"ip": k, **v, "loc": CONF.sites()[CONF.location_for(k)]["name"] if v["allowed"] else ""}
                            for k, v in sorted(self.senders.items(), key=lambda kv: -kv[1]["last"])],
                "uptime": int(time.time() - self.started),
            }


STATUS = Status()


class Hub:
    BUCKET_S = 10
    BUCKETS = 90  # 15 minutes

    def __init__(self):
        self.lock = threading.Lock()
        self.clients = set()
        self.recent = collections.deque(maxlen=200)
        self.names = {}
        self.day = dt.date.today()
        self.total = 0
        self.ips = set()
        self.countries = set()
        self.buckets = collections.deque(maxlen=self.BUCKETS)
        self.bucket_id = None
        self.tokens = 40.0
        self.last_refill = time.monotonic()
        self.dropped = 0
        self.seq = 0

    @staticmethod
    def _empty():
        return {"n": 0, "cc": collections.Counter(), "type": collections.Counter()}

    def _bucket(self, now):
        bid = int(now // self.BUCKET_S)
        if bid != self.bucket_id:
            if self.bucket_id is not None:
                for _ in range(min(bid - self.bucket_id - 1, self.BUCKETS)):
                    self.buckets.append(self._empty())
            self.buckets.append(self._empty())
            self.bucket_id = bid
        return self.buckets[-1]

    def add(self, ev):
        now = time.time()
        max_eps = float(CONF["max_eps"])
        with self.lock:
            today = dt.date.today()
            if today != self.day:
                self.day, self.total, self.ips, self.countries = today, 0, set(), set()
            self.total += 1
            if len(self.ips) < 500_000:
                self.ips.add(ev["ip"])
            self.countries.add(ev["cc"])
            self.names[ev["cc"]] = ev["country"]
            b = self._bucket(now)
            b["n"] += 1
            b["cc"][ev["cc"]] += 1
            b["type"][ev["type"]] += 1
            t = time.monotonic()
            self.tokens = min(max_eps, self.tokens + (t - self.last_refill) * max_eps)
            self.last_refill = t
            if self.tokens < 1:
                self.dropped += 1
                return
            self.tokens -= 1
            self.seq += 1
            ev["id"] = self.seq
            self.recent.append(ev)
            clients = list(self.clients)
        self.send(clients, "attack", ev)

    def stats(self):
        with self.lock:
            self._bucket(time.time())
            cc, ty, n15 = collections.Counter(), collections.Counter(), 0
            for b in self.buckets:
                cc.update(b["cc"])
                ty.update(b["type"])
                n15 += b["n"]
            return {
                "total_today": self.total,
                "unique_ips": len(self.ips),
                "countries": len(self.countries),
                "per_min": sum(b["n"] for b in list(self.buckets)[-6:]),
                "last_15m": n15,
                "top": [[c, self.names.get(c, c), n] for c, n in cc.most_common(7)],
                "types": {k: ty.get(k, 0) for k in TYPE_KEYS},
                "sampled": self.dropped > 0,
                "geoip_ready": GEO.state == "ready" or CONF["demo"],
                "demo": CONF["demo"],
            }

    def snapshot(self):
        with self.lock:
            recent = list(self.recent)
        return {"site": CONF["site"], "sites": CONF.sites(), "recent": recent[-150:], "stats": self.stats()}

    def subscribe(self):
        q = queue.Queue(maxsize=2000)
        with self.lock:
            self.clients.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.clients.discard(q)

    def send(self, clients, kind, data):
        msg = f"event: {kind}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n".encode()
        for q in clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    def broadcast(self, kind, data):
        with self.lock:
            clients = list(self.clients)
        self.send(clients, kind, data)

    def stats_loop(self):
        while True:
            time.sleep(2)
            self.broadcast("stats", self.stats())


HUB = Hub()


def handle(rec, geo_override=None, loc=0):
    if not rec or not rec.get("src"):
        return False
    try:
        ip = ipaddress.ip_address(str(rec["src"]).strip())
    except ValueError:
        return False
    if not ip.is_global:
        STATUS.private += 1
        return False
    g = geo_override or GEO.lookup(str(ip))
    if not g:
        STATUS.unlocated += 1
        return False
    HUB.add({
        "ts": int(time.time() * 1000),
        "ip": str(ip),
        "cc": g["cc"],
        "country": g["country"],
        "lat": g["lat"],
        "lon": g["lon"],
        "type": classify(rec.get("port"), rec.get("proto", ""), rec.get("text", "")),
        "port": rec.get("port"),
        "proto": rec.get("proto", ""),
        "detail": str(rec.get("detail", ""))[:160],
        "sensor": rec.get("sensor", ""),
        "loc": loc,
    })
    return True


# ================================================================ inputs

def syslog_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("0.0.0.0", SYSLOG_PORT))
    log(f"Syslog UDP listening on :{SYSLOG_PORT}")
    while True:
        data, (addr, _port) = sock.recvfrom(65535)
        if not CONF.sender_allowed(addr):
            STATUS.rejected += 1
            STATUS.sender(addr, False)
            continue
        loc = CONF.location_for(addr)
        for line in data.decode("utf-8", "replace").splitlines():
            STATUS.received += 1
            try:
                rec = parse_line(line, CONF["sources"])
            except Exception as e:  # one bad line must never stop the listener
                rec = None
                log("parse error:", e)
            if rec:
                STATUS.parsed += 1
                handle(rec, loc=loc)
            else:
                STATUS.ignored += 1
            STATUS.sender(addr, True, bool(rec))


def eve_worker():
    fh, ino, path = None, None, None
    while True:
        want = CONF["eve_file"] if CONF["sources"]["suricata"] else ""
        if want != path:
            if fh:
                fh.close()
            fh, ino, path = None, None, want
            if want:
                log("Tailing Suricata EVE file", want)
        if not path:
            time.sleep(2)
            continue
        try:
            st = os.stat(path)
            if fh is None or st.st_ino != ino or st.st_size < fh.tell():
                first = fh is None and ino is None
                if fh:
                    fh.close()
                fh, ino = open(path, encoding="utf-8", errors="replace"), st.st_ino
                if first:
                    fh.seek(0, os.SEEK_END)
            line = fh.readline()
            if not line:
                time.sleep(0.25)
                continue
            STATUS.received += 1
            try:
                rec = parse_eve(json.loads(line))
            except ValueError:
                rec = None
            if rec:
                STATUS.parsed += 1
                handle(rec)
            else:
                STATUS.ignored += 1
        except OSError:
            time.sleep(2)


DEMO_GEO = [
    ("CN", "China", 31.23, 121.47, 18), ("US", "United States", 37.75, -97.82, 12), ("RU", "Russia", 55.75, 37.62, 11),
    ("BR", "Brazil", -23.55, -46.63, 7), ("IN", "India", 19.08, 72.88, 7), ("VN", "Vietnam", 21.03, 105.85, 6),
    ("NL", "Netherlands", 52.37, 4.89, 6), ("DE", "Germany", 50.11, 8.68, 4), ("IR", "Iran", 35.69, 51.39, 4),
    ("KR", "South Korea", 37.57, 126.98, 4), ("ID", "Indonesia", -6.21, 106.85, 4), ("SG", "Singapore", 1.35, 103.82, 3),
    ("RO", "Romania", 44.43, 26.1, 3), ("UA", "Ukraine", 50.45, 30.52, 3), ("FR", "France", 48.86, 2.35, 2),
]
DEMO_SIGS = [
    ("ET SCAN Potential SSH Scan", "Attempted Information Leak", 22),
    ("ET WEB_SERVER Possible SQL Injection Attempt", "Web Application Attack", 443),
    ("ET MALWARE Possible Mirai Botnet C2 Traffic", "A Network Trojan was detected", 23),
    ("ET DOS Possible NTP DDoS Inbound", "Attempted Denial of Service", 123),
]


def synthetic(sensor_label):
    """One synthetic line in a random format, run through the real parsers, with a made-up location."""
    cc, name, lat, lon, _w = random.choices(DEMO_GEO, weights=[g[4] for g in DEMO_GEO])[0]
    geo = {"cc": cc, "country": name, "lat": round(lat + random.uniform(-3, 3), 2), "lon": round(lon + random.uniform(-3, 3), 2)}
    src = f"{random.choice([45, 61, 80, 103, 112, 176, 185, 193, 194, 222])}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    kind = random.random()
    if kind < 0.55:
        port = random.choice([22, 22, 3389, 443, 80, 23, 445, 8080, 5060, 1433, 6379, 53, 123])
        proto = "udp" if port in (53, 123, 5060) else "tcp"
        pid = "17" if proto == "udp" else "6"
        line = (f"filterlog[1]: 5,,,1000000103,wan,match,block,in,4,0x0,,52,0,0,DF,"
                f"{pid},{proto},60,{src},203.0.113.10,{random.randint(1024, 65000)},{port},0,S,1,,64240,,mss")
    elif kind < 0.85:
        sig, cat, port = random.choice(DEMO_SIGS)
        line = "suricata[42]: " + json.dumps({
            "event_type": "alert", "src_ip": src, "dest_ip": "203.0.113.10", "dest_port": port,
            "proto": "UDP" if port == 123 else "TCP", "alert": {"signature": sig, "category": cat, "severity": 2}})
    else:
        line = (f'type="utm" subtype="ips" action="dropped" srcip={src} dstip=203.0.113.10 dstport=80 proto=6 '
                f'attack="Apache.Log4j.Error.Log.Remote.Code.Execution"')
    rec = parse_line(line)
    if rec:
        rec["sensor"] = sensor_label
        handle(rec, geo_override=geo, loc=random.randrange(len(CONF.sites())))


def demo_worker():
    rate = 5.0
    while True:
        if not CONF["demo"]:
            time.sleep(1)
            continue
        rate = max(1.5, min(12, rate + random.uniform(-0.6, 0.6)))
        time.sleep(random.expovariate(rate))
        synthetic("demo")


# ================================================================ HTTP

SESSIONS = {}  # token -> expiry
SESSION_TTL = 30 * 86400
LOGIN_FAILS = collections.defaultdict(list)
SETUP_CODE = None if CONF.configured else "-".join(secrets.token_hex(2).upper() for _ in range(3))

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".json": "application/json", ".js": "text/javascript", ".css": "text/css; charset=utf-8"}
PAGES = {"/": "index.html", "/settings": "settings.html", "/login": "login.html", "/setup": "setup.html"}
PUBLIC_FILES = {"ui.css", "land-110m.json"}


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


def v_str(v, maxlen, name):
    if not isinstance(v, str) or len(v) > maxlen:
        raise ApiError(400, f"{name} geçersiz.")
    return v.strip()


def v_num(v, lo, hi, name):
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ApiError(400, f"{name} bir sayı olmalı.") from None
    if not lo <= f <= hi:
        raise ApiError(400, f"{name} {lo} ile {hi} arasında olmalı.")
    return f


def apply_settings(body):
    """Validate a partial settings object from the GUI and store it."""
    changes = []
    if "site" in body:
        s = body["site"]
        site = {
            "name": v_str(s.get("name", ""), 32, "Konum adı") or "EDGE-1",
            "lat": round(v_num(s.get("lat"), -90, 90, "Enlem"), 4),
            "lon": round(v_num(s.get("lon"), -180, 180, "Boylam"), 4),
        }
        changes.append(lambda c: c.__setitem__("site", site))
    if "allowed_senders" in body:
        lst = body["allowed_senders"]
        if not isinstance(lst, list) or len(lst) > 100:
            raise ApiError(400, "İzinli gönderici listesi geçersiz.")
        clean = []
        for item in lst:
            item = v_str(item, 64, "Gönderici")
            if not item:
                continue
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ApiError(400, f"'{item}' geçerli bir IP adresi veya ağ (ör. 192.168.1.1 ya da 10.0.0.0/24) değil.") from None
            clean.append(item)
        changes.append(lambda c: c.__setitem__("allowed_senders", clean))
    if "locations" in body:
        lst = body["locations"]
        if not isinstance(lst, list) or len(lst) > 30:
            raise ApiError(400, "Konum listesi geçersiz (en fazla 30 ek konum).")
        locs = []
        for i, l in enumerate(lst, 1):
            if not isinstance(l, dict):
                raise ApiError(400, "Konum listesi geçersiz.")
            name = v_str(l.get("name", ""), 32, f"{i}. konumun adı")
            if not name:
                raise ApiError(400, f"{i}. ek konumun adı boş.")
            senders = []
            raw = l.get("senders", [])
            if not isinstance(raw, list) or len(raw) > 50:
                raise ApiError(400, f"{name}: firewall IP listesi geçersiz.")
            for item in raw:
                item = v_str(item, 64, "Firewall IP")
                if not item:
                    continue
                try:
                    ipaddress.ip_network(item, strict=False)
                except ValueError:
                    raise ApiError(400, f"{name}: '{item}' geçerli bir IP adresi veya ağ değil.") from None
                senders.append(item)
            locs.append({"name": name, "lat": round(v_num(l.get("lat"), -90, 90, f"{name} enlemi"), 4),
                         "lon": round(v_num(l.get("lon"), -180, 180, f"{name} boylamı"), 4), "senders": senders})
        changes.append(lambda c: c.__setitem__("locations", locs))
    if "sources" in body:
        src = {k: bool(body["sources"].get(k, CONF["sources"][k])) for k in SOURCE_KEYS}
        changes.append(lambda c: c.__setitem__("sources", src))
    if "eve_file" in body:
        p = v_str(body["eve_file"], 300, "EVE dosya yolu")
        if p:
            rp = os.path.realpath(p)
            if not os.path.isabs(p):
                raise ApiError(400, "EVE dosya yolu tam yol olmalı (ör. /eve/eve.json).")
            if EVE_ROOT and os.path.commonpath([rp, os.path.realpath(EVE_ROOT)]) != os.path.realpath(EVE_ROOT):
                raise ApiError(400, f"EVE dosyası {EVE_ROOT} klasörünün içinde olmalı.")
        changes.append(lambda c: c.__setitem__("eve_file", p))
    for key, lo, hi in (("max_eps", 1, 500),):
        if key in body:
            val = int(v_num(body[key], lo, hi, "Saniyedeki yay sayısı"))
            changes.append(lambda c, k=key, v=val: c.__setitem__(k, v))
    for key in ("public_map", "demo"):
        if key in body:
            val = bool(body[key])
            changes.append(lambda c, k=key, v=val: c.__setitem__(k, v))
    if "geoip" in body:
        g = body["geoip"]
        upd = {}
        if "account_id" in g:
            aid = v_str(str(g["account_id"]), 20, "Account ID")
            if aid and not aid.isdigit():
                raise ApiError(400, "Account ID yalnızca rakamlardan oluşur.")
            upd["account_id"] = aid
        if g.get("license_key"):
            upd["license_key"] = v_str(g["license_key"], 100, "License Key")
        if g.get("clear_license_key"):
            upd["license_key"] = ""
        if "auto_update" in g:
            upd["auto_update"] = bool(g["auto_update"])
        changes.append(lambda c: c["geoip"].update(upd))

    def run(c):
        for fn in changes:
            fn(c)
    CONF.update(run)


class Handler(BaseHTTPRequestHandler):
    server_version = "AttackMap/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---------- helpers
    def _client_ip(self):
        if TRUST_PROXY:
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def _session(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "am_session" and v in SESSIONS:
                if SESSIONS[v] > time.time():
                    return v
                SESSIONS.pop(v, None)
        return None

    def _is_admin(self):
        return self._session() is not None

    def _can_view(self):
        return CONF["public_map"] or self._is_admin()

    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Frame-Options", "DENY")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, headers=None):
        self._send(code, json.dumps(obj).encode(), "application/json", headers)

    def _redirect(self, to):
        self._send(302, b"", headers={"Location": to})

    def _body_json(self, limit=64 * 1024):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise ApiError(413, "İstek çok büyük.")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ApiError(400, "Geçersiz JSON.") from None

    def _cookie(self, token, max_age):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "") == "https" else ""
        return f"am_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

    def _new_session(self):
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = time.time() + SESSION_TTL
        return {"Set-Cookie": self._cookie(token, SESSION_TTL)}

    # ---------- GET
    def do_HEAD(self):
        self.do_GET()

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionError, OSError):
            self.close_connection = True
        except Exception as e:  # never leave a request without an answer
            log("request error:", repr(e))
            try:
                self._json(500, {"error": "Sunucu hatası."})
            except OSError:
                pass
            self.close_connection = True

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self._send(200, b"ok")
        if path in PAGES:
            if not CONF.configured and path != "/setup":
                return self._redirect("/setup")
            if CONF.configured and path == "/setup":
                return self._redirect("/")
            if path == "/" and not self._can_view():
                return self._redirect("/login")
            if path == "/settings" and not self._is_admin():
                return self._redirect("/login?next=/settings")
            return self._static(PAGES[path])
        if path.lstrip("/") in PUBLIC_FILES:
            return self._static(path.lstrip("/"))
        try:
            if path == "/api/me":
                return self._json(200, {"admin": self._is_admin(), "configured": CONF.configured, "public_map": CONF["public_map"]})
            if path in ("/api/state", "/events"):
                if not self._can_view():
                    raise ApiError(401, "Giriş gerekli.")
                return self._json(200, HUB.snapshot()) if path == "/api/state" else self._sse()
            if not self._is_admin():
                raise ApiError(401, "Giriş gerekli.")
            if path == "/api/config":
                return self._json(200, CONF.public_view())
            if path == "/api/status":
                return self._json(200, {
                    **STATUS.snapshot(),
                    "geoip": {"state": GEO.state, "message": GEO.message, "last_error": getattr(GEO, "last_error", "")},
                    "syslog_port": PUBLIC_SYSLOG_PORT,
                    "eve_root": EVE_ROOT,
                    "eve_ok": bool(CONF["eve_file"]) and os.path.isfile(CONF["eve_file"]),
                    "map": HUB.stats(),
                })
            raise ApiError(404, "Bulunamadı.")
        except ApiError as e:
            self._json(e.code, {"error": e.msg})

    def _static(self, name):
        f = (STATIC / name).resolve()
        if STATIC not in f.parents or not f.is_file():
            return self._send(404, b"Not found")
        self._send(200, f.read_bytes(), CONTENT_TYPES.get(f.suffix, "application/octet-stream"))

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q = HUB.subscribe()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=15)
                except queue.Empty:
                    msg = b": ping\n\n"
                if not self._can_view():
                    break
                self.wfile.write(msg)
                self.wfile.flush()
        except OSError:
            pass
        finally:
            HUB.unsubscribe(q)
            self.close_connection = True

    # ---------- POST / PUT
    def do_POST(self):
        self._mutate()

    def do_PUT(self):
        self._mutate()

    def _mutate(self):
        path = self.path.split("?")[0]
        try:
            # custom header => browsers cannot send this cross-site without a CORS preflight we never grant
            if self.headers.get("X-Requested-With") != "attackmap":
                raise ApiError(403, "Geçersiz istek.")
            if path == "/api/setup":
                return self._setup()
            if path == "/api/login":
                return self._login()
            if path == "/api/logout":
                tok = self._session()
                SESSIONS.pop(tok, None)
                return self._json(200, {"ok": True}, {"Set-Cookie": self._cookie("", 0)})
            if not self._is_admin():
                raise ApiError(401, "Giriş gerekli.")
            if path == "/api/config":
                apply_settings(self._body_json())
                return self._json(200, CONF.public_view())
            if path == "/api/password":
                b = self._body_json()
                if not check_password(str(b.get("current", ""))):
                    raise ApiError(400, "Mevcut şifre yanlış.")
                new = str(b.get("new", ""))
                if len(new) < 10:
                    raise ApiError(400, "Yeni şifre en az 10 karakter olmalı.")
                salt, h = hash_password(new)
                CONF.update(lambda c: c.__setitem__("admin", {"salt": salt, "hash": h}))
                SESSIONS.clear()
                return self._json(200, {"ok": True}, self._new_session())
            if path == "/api/geoip/download":
                try:
                    GEO.download()
                except ValueError as e:
                    raise ApiError(400, str(e)) from None
                return self._json(202, {"ok": True})
            if path == "/api/geoip/upload":
                n = int(self.headers.get("Content-Length") or 0)
                if not 0 < n <= 250 * 1024 * 1024:
                    raise ApiError(400, "Dosya boş ya da 250 MB'tan büyük.")
                data, left = bytearray(), n
                while left:
                    chunk = self.rfile.read(min(left, 1 << 20))
                    if not chunk:
                        break
                    data += chunk
                    left -= len(chunk)
                try:
                    GEO.install(bytes(data))
                except ValueError as e:
                    raise ApiError(400, str(e)) from None
                return self._json(200, {"ok": True, "message": GEO.message})
            if path == "/api/test-event":
                for _ in range(8):
                    synthetic("test")
                return self._json(200, {"ok": True})
            raise ApiError(404, "Bulunamadı.")
        except ApiError as e:
            self._json(e.code, {"error": e.msg})

    def _setup(self):
        global SETUP_CODE
        if CONF.configured:
            raise ApiError(409, "Kurulum zaten tamamlandı.")
        self._throttle()
        b = self._body_json()
        if not hmac.compare_digest(str(b.get("code", "")).strip().upper(), SETUP_CODE or "x"):
            self._fail()
            raise ApiError(400, "Kurulum kodu yanlış. Kodu sunucu loglarında bulabilirsiniz.")
        pw = str(b.get("password", ""))
        if len(pw) < 10:
            raise ApiError(400, "Şifre en az 10 karakter olmalı.")
        apply_settings({k: b[k] for k in ("site", "geoip", "demo", "allowed_senders") if k in b})
        salt, h = hash_password(pw)
        CONF.update(lambda c: c.__setitem__("admin", {"salt": salt, "hash": h}))
        SETUP_CODE = None
        log("Setup completed.")
        g = CONF["geoip"]
        if g["account_id"] and g["license_key"]:
            try:
                GEO.download()
            except ValueError:
                pass
        self._json(200, {"ok": True}, self._new_session())

    def _throttle(self):
        now = time.time()
        fails = [t for t in LOGIN_FAILS[self._client_ip()] if now - t < 900]
        LOGIN_FAILS[self._client_ip()] = fails
        if len(fails) >= 5:
            raise ApiError(429, "Çok fazla hatalı deneme. 15 dakika sonra tekrar deneyin.")

    def _fail(self):
        LOGIN_FAILS[self._client_ip()].append(time.time())

    def _login(self):
        if not CONF.configured:
            raise ApiError(409, "Önce kurulumu tamamlayın.")
        self._throttle()
        b = self._body_json()
        if not check_password(str(b.get("password", ""))):
            self._fail()
            time.sleep(0.5)
            raise ApiError(400, "Şifre yanlış.")
        LOGIN_FAILS.pop(self._client_ip(), None)
        self._json(200, {"ok": True}, self._new_session())


def main():
    if "--demo" in sys.argv:
        CONF.update(lambda c: c.__setitem__("demo", True))
    for target in (syslog_listener, eve_worker, demo_worker, HUB.stats_loop, GEO.auto_update_loop):
        threading.Thread(target=target, daemon=True).start()
    srv = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), Handler)
    srv.daemon_threads = True
    log(f"Attack map on http://{HTTP_HOST}:{HTTP_PORT}/   syslog udp/{SYSLOG_PORT}   data {DATA}")
    if SETUP_CODE:
        log("=" * 56)
        log(f"  SETUP CODE: {SETUP_CODE}")
        log("  Open the page in a browser and enter this code.")
        log("=" * 56)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
