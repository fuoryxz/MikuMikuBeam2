import argparse
import hashlib
import hmac
import json
import os
import random
import socket
import string
import sys
import threading
import time
import uuid

HMAC_WINDOW = 300.0
BUF = 65536
RECONNECT_BASE = 5.0
RECONNECT_MAX = 60.0

# Опасные команды, которые фейковый бот НЕ выполняет, а только логирует.
DANGEROUS_PREFIXES = ("ddos_start", "install_persist", "uninstall_persist", "exit")


def parse_hex32(s: str) -> bytes:
    if not s or len(s) != 64:
        raise ValueError(f"PSK must be 64 hex chars, got {len(s) if s else 0}")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise ValueError(f"PSK is not valid hex: {e}")


def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def hash8(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:8]


def payload_for_hash(typ: str, cmd: str, data: str) -> str:
    if typ in ("CMD", "CMD_ACK", "CMD_RESULT"):
        return cmd or ""
    if typ == "OUT":
        return data or ""
    return ""


def sign_frame(key: bytes, bid: str, ts: int, nonce: str, typ: str,
               cid: str = "", cmd: str = "", data: str = "") -> str:
    ph = hash8(payload_for_hash(typ, cmd, data))
    msg = f"{bid}|{ts}|{nonce}|{typ}|{cid or ''}|{ph}".encode()
    return hmac_hex(key, msg)


def gen_nonce() -> str:
    return uuid.uuid4().hex[:16]


def make_bot_id() -> str:
    return str(uuid.uuid4())


def recv_line(sock: socket.socket, buf: bytearray) -> str | None:
    """Читает одну строку (до \n). Возвращает None при обрыве."""
    while b"\n" not in buf:
        try:
            chunk = sock.recv(BUF)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    line, _, rest = bytes(buf).partition(b"\n")
    buf.clear()
    buf.extend(rest)
    return line.decode(errors="replace")


class FakeBot:
    def __init__(self, host: str, port: int, psk: bytes,
                 bot_id: str | None = None,
                 hostname: str = "fake",
                 os_name: str = "linux", arch: str = "x64",
                 simulate_cmd: bool = False,
                 ping_interval: float = 15.0,
                 reconnect: bool = True,
                 log_prefix: str = ""):
        self.host = host
        self.port = port
        self.psk = psk
        self.bot_id = bot_id or make_bot_id()
        self.hostname = hostname
        self.os_name = os_name
        self.arch = arch
        self.simulate_cmd = simulate_cmd
        self.ping_interval = ping_interval
        self.reconnect = reconnect
        self.log_prefix = log_prefix or self.bot_id[:8]

        self.sock: socket.socket | None = None
        self.alive = True
        self._stop = threading.Event()
        self._ping_thread: threading.Thread | None = None
        self._reader_thread: threading.Thread | None = None
        self._send_lock = threading.Lock()
        self._cmd_count = 0
        self._connected_once = False

    # ---------- logging ----------
    def log(self, msg: str, kind: str = "info"):
        colors = {"info": "\033[36m", "ok": "\033[32m", "warn": "\033[33m",
                  "err": "\033[31m", "dim": "\033[90m"}
        c = colors.get(kind, "")
        r = "\033[0m" if c else ""
        print(f"{c}[{self.log_prefix}]{r} {msg}", flush=True)

    # ---------- transport ----------
    def _send_json(self, obj: dict) -> bool:
        if not self.sock:
            return False
        try:
            data = (json.dumps(obj, ensure_ascii=False) + "\n").encode()
            with self._send_lock:
                self.sock.sendall(data)
            return True
        except OSError:
            return False

    def _sign_and_send(self, obj: dict) -> bool:
        typ = obj.get("type", "")
        cid = obj.get("cmd_id", "")
        cmd = obj.get("cmd", "") or ""
        data = obj.get("data", "") or ""
        obj["ts"] = int(time.time())
        obj["nonce"] = gen_nonce()
        obj["hmac"] = sign_frame(self.psk, self.bot_id, obj["ts"], obj["nonce"],
                                 typ, cid, cmd, data)
        return self._send_json(obj)

    # ---------- handshake ----------
    def _connect_and_hello(self) -> bool:
        try:
            s = socket.create_connection((self.host, self.port), timeout=10.0)
        except OSError as e:
            self.log(f"connect failed: {e}", "err")
            return False
        s.settimeout(1.0)
        self.sock = s

        ts = int(time.time())
        nonce = gen_nonce()
        msg = f"{self.bot_id}|{ts}|{nonce}".encode()
        mac = hmac_hex(self.psk, msg)
        hello = {
            "type": "HELLO",
            "id": self.bot_id,
            "host": self.hostname,
            "os": self.os_name,
            "arch": self.arch,
            "ts": ts,
            "nonce": nonce,
            "hmac": mac,
        }
        if not self._send_json(hello):
            self.log("HELLO send failed", "err")
            try: s.close()
            except OSError: pass
            self.sock = None
            return False
        self._connected_once = True
        self.log(f"HELLO sent → {self.host}:{self.port}", "ok")
        return True

    # ---------- reader ----------
    def _reader_loop(self):
        buf = bytearray()
        while not self._stop.is_set() and self.sock:
            line = recv_line(self.sock, buf)
            if line is None:
                self.log("connection closed by server", "warn")
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self.log(f"bad JSON: {line[:80]}", "warn")
                continue
            self._handle_msg(msg)
        self.alive = False
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _handle_msg(self, msg: dict):
        typ = msg.get("type", "")
        if typ == "PONG":
            self.log("PONG", "dim")
        elif typ == "CMD":
            self._handle_cmd(msg)
        else:
            self.log(f"unknown type: {typ}", "warn")

    def _handle_cmd(self, msg: dict):
        cid = msg.get("cmd_id", "")
        cmd = msg.get("cmd", "") or ""
        self._cmd_count += 1

        # ACK всегда
        self._sign_and_send({"type": "CMD_ACK", "id": self.bot_id, "cmd_id": cid})

        is_dangerous = any(cmd.startswith(p) for p in DANGEROUS_PREFIXES)

        if not self.simulate_cmd:
            # По умолчанию: не выполняем, но отвечаем, что «отвергнуто»
            self.log(f"CMD (ignored): {cmd[:60]!r}", "dim")
            self._sign_and_send({
                "type": "CMD_RESULT", "id": self.bot_id, "cmd_id": cid,
                "code": -99, "timed_out": 0,
            })
            return

        if is_dangerous:
            # Симулируем: команда «принята», но не выполняется
            self.log(f"CMD (dangerous, simulated): {cmd[:60]!r}", "warn")
            # Немного «поработаем» для правдоподобия
            time.sleep(random.uniform(0.05, 0.3))
            self._sign_and_send({
                "type": "CMD_RESULT", "id": self.bot_id, "cmd_id": cid,
                "code": 0, "timed_out": 0,
            })
            return

        # Безопасные команды — «выполняем» (эхо)
        self.log(f"CMD (simulated): {cmd[:60]!r}", "info")
        time.sleep(random.uniform(0.02, 0.15))
        # OUT: эхо
        out_data = f"fake output for: {cmd[:40]}"
        self._sign_and_send({
            "type": "OUT", "id": self.bot_id, "cmd_id": cid,
            "stream": "stdout", "data": out_data,
        })
        self._sign_and_send({
            "type": "CMD_RESULT", "id": self.bot_id, "cmd_id": cid,
            "code": 0, "timed_out": 0,
        })

    # ---------- ping ----------
    def _ping_loop(self):
        while not self._stop.is_set():
            # спим кусками, чтобы быстро реагировать на stop
            slept = 0.0
            while slept < self.ping_interval and not self._stop.is_set():
                time.sleep(min(0.2, self.ping_interval - slept))
                slept += 0.2
            if self._stop.is_set():
                break
            if not self.sock:
                break
            if not self._sign_and_send({"type": "PING", "id": self.bot_id}):
                self.log("PING send failed", "err")
                break

    # ---------- public ----------
    def start(self):
        """Один цикл: connect → hello → reader+ping. Возвращает управление после обрыва."""
        if not self._connect_and_hello():
            return False
        self.alive = True
        self._stop.clear()
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._ping_thread = threading.Thread(target=self._ping_loop, daemon=True)
        self._reader_thread.start()
        self._ping_thread.start()
        return True

    def wait(self):
        """Ждёт, пока reader не завершится."""
        if self._reader_thread:
            self._reader_thread.join()
        if self._ping_thread:
            self._ping_thread.join(timeout=2.0)

    def stop(self):
        self._stop.set()
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def run_forever(self):
        """Цикл connect → hello → serve → reconnect с backoff."""
        attempt = 0
        while not self._stop.is_set():
            ok = self.start()
            if ok:
                attempt = 0
                self.wait()
                if self._stop.is_set():
                    break
                if not self.reconnect:
                    break
                self.log("reconnecting...", "warn")
            else:
                attempt += 1
                if not self.reconnect:
                    break
            delay = min(RECONNECT_MAX, RECONNECT_BASE * (2 ** min(attempt, 5)))
            # jitter ±30%
            delay *= random.uniform(0.7, 1.3)
            self.log(f"backoff {delay:.1f}s", "dim")
            slept = 0.0
            while slept < delay and not self._stop.is_set():
                time.sleep(min(0.2, delay - slept))
                slept += 0.2


def random_hostname(prefix: str) -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}-{suffix}"


def main():
    ap = argparse.ArgumentParser(description="Fake C2 bots for testing")
    ap.add_argument("host", help="C2 server host")
    ap.add_argument("port", type=int, help="C2 server port")
    ap.add_argument("--psk", default=None, help="PSK hex (64 chars)")
    ap.add_argument("--psk-env", default="C2_PSK",
                    help="env var with PSK (default: C2_PSK)")
    ap.add_argument("--count", type=int, default=1, help="number of bots")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="delay between bot starts (sec)")
    ap.add_argument("--simulate-cmd", action="store_true",
                    help="respond to CMD as a real bot (but do NOT execute dangerous ones)")
    ap.add_argument("--host-prefix", default="fake", help="hostname prefix")
    ap.add_argument("--os", default="linux", help="OS in HELLO")
    ap.add_argument("--arch", default="x64", help="arch in HELLO")
    ap.add_argument("--ping-interval", type=float, default=15.0)
    ap.add_argument("--no-reconnect", action="store_true",
                    help="do not reconnect after disconnect")
    ap.add_argument("--seed", type=int, default=None, help="random seed")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    psk_hex = args.psk
    if not psk_hex:
        psk_hex = os.environ.get(args.psk_env, "")
    if not psk_hex:
        print(f"[!] PSK not provided. Use --psk <64hex> or --psk-env {args.psk_env}",
              file=sys.stderr)
        return 1
    try:
        psk = parse_hex32(psk_hex)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    if args.count < 1:
        print("[!] --count must be >= 1", file=sys.stderr)
        return 1

    print(f"[*] Spawning {args.count} fake bot(s) → {args.host}:{args.port}")
    print(f"[*] simulate_cmd={args.simulate_cmd} reconnect={not args.no_reconnect}")
    print(f"[*] PSK: {psk_hex[:8]}...{psk_hex[-4:]} (hidden)")
    print()

    bots: list[FakeBot] = []
    for i in range(args.count):
        bot_id = make_bot_id()
        hn = random_hostname(args.host_prefix)
        b = FakeBot(
            host=args.host, port=args.port, psk=psk,
            bot_id=bot_id, hostname=hn,
            os_name=args.os, arch=args.arch,
            simulate_cmd=args.simulate_cmd,
            ping_interval=args.ping_interval,
            reconnect=not args.no_reconnect,
            log_prefix=f"bot{i:02d}/{bot_id[:8]}",
        )
        bots.append(b)
        t = threading.Thread(target=b.run_forever, daemon=True)
        t.start()
        if i < args.count - 1 and args.interval > 0:
            time.sleep(args.interval)

    print(f"[*] All {len(bots)} bots started. Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1.0)
            # краткий статус раз в 30 секунд
            if int(time.time()) % 30 == 0:
                alive = sum(1 for b in bots if b.alive and b.sock)
                cmds = sum(b._cmd_count for b in bots)
                print(f"[*] status: alive={alive}/{len(bots)} cmds_received={cmds}",
                      flush=True)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        for b in bots:
            b.stop()
        for b in bots:
            try: b.wait()
            except Exception: pass
        print("[*] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
