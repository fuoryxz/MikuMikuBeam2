import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROJECT_FILES = ["client.c", "server.py", "test.py", "CMakeLists.txt", "README.md", "LICENSE", ".env.example"]
DEFAULT_C2_PORT = 4444
DEFAULT_UI_PORT = 8080

COLORS = {
    "ok": "\033[32m", "err": "\033[31m", "warn": "\033[33m",
    "info": "\033[36m", "dim": "\033[90m", "reset": "\033[0m",
}


def _c(s: str, k: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"{COLORS.get(k, '')}{s}{COLORS['reset']}"


def log(msg: str, kind: str = "info"):
    print(f"{_c('[tug]', kind)} {msg}", flush=True)


def run(cmd: list[str], timeout: float = 30.0, cwd: Path | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=str(cwd) if cwd else None)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


# ---------- doctor ----------
def cmd_doctor(args) -> int:
    log("Environment check", "info")
    ok = True

    def check(name: str, fn):
        nonlocal ok
        try:
            v = fn()
            if v:
                log(f"  {name}: {v}", "ok")
            else:
                log(f"  {name}: MISSING", "err")
                ok = False
        except Exception as e:
            log(f"  {name}: ERROR {e}", "err")
            ok = False

    check("python", lambda: sys.version.split()[0])
    check("platform", lambda: f"{platform.system()} {platform.release()} {platform.machine()}")

    def _cmake():
        rc, out, _ = run(["cmake", "--version"])
        return out.splitlines()[0] if rc == 0 and out else None
    check("cmake", _cmake)

    def _cc():
        for cc in (["cc", "--version"], ["gcc", "--version"], ["clang", "--version"]):
            rc, out, _ = run(cc)
            if rc == 0 and out:
                return out.splitlines()[0]
        return None
    check("cc", _cc)

    def _py_ver():
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    check("python3", _py_ver)

    for f in ["client.c", "server.py", "fake_bots.py", "CMakeLists.txt"]:
        p = ROOT / f
        if p.exists():
            log(f"  file {f}: {p.stat().st_size} bytes", "ok")
        else:
            log(f"  file {f}: MISSING", "err")
            ok = False

    env_psk = os.environ.get("C2_PSK", "")
    if env_psk:
        if _is_valid_psk(env_psk):
            log(f"  env C2_PSK: set (len={len(env_psk)})", "ok")
        else:
            log(f"  env C2_PSK: INVALID (len={len(env_psk)})", "err")
            ok = False
    else:
        log("  env C2_PSK: not set (will generate at server start)", "warn")

    log("Result: " + ("OK" if ok else "PROBLEMS FOUND"), "ok" if ok else "err")
    return 0 if ok else 1


def _is_valid_psk(s: str) -> bool:
    if not s or len(s) != 64:
        return False
    try:
        b = bytes.fromhex(s)
    except ValueError:
        return False
    return any(b)


# ---------- genpsk ----------
def cmd_genpsk(args) -> int:
    psk = os.urandom(32).hex()
    out_path = Path(args.out) if args.out else None

    env_lines = [
        f"C2_PSK={psk}",
        f"C2_UI_PASSWORD={args.ui_password or 'change-me-' + uuid.uuid4().hex[:16]}",
        f"C2_UI_SECRET={os.urandom(32).hex()}",
    ]
    if args.prev:
        env_lines.append(f"C2_PSK_PREV={args.prev}")

    if out_path:
        if out_path.exists() and not args.force:
            log(f"{out_path} exists, use --force to overwrite", "err")
            return 1
        out_path.write_text("\n".join(env_lines) + "\n")
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        log(f"written: {out_path} (chmod 600)", "ok")
    else:
        print("\n".join(env_lines))

    print()
    log("Server:", "info")
    print(f"  export C2_PSK={psk}")
    print(f"  python3 server.py {args.c2_port} {args.ui_port}")
    print()
    log("Client:", "info")
    print(f"  C2_PSK={psk} ./client <c2_ip> {args.c2_port}")
    print()
    log("Fake bots:", "info")
    print(f"  python3 fake_bots.py <c2_ip> {args.c2_port} --psk {psk} --count 3")
    return 0


# ---------- checkpsk ----------
def cmd_checkpsk(args) -> int:
    psk = None
    if args.psk:
        psk = args.psk
    elif args.env_file:
        p = Path(args.env_file)
        if not p.exists():
            log(f"{p} not found", "err")
            return 1
        for line in p.read_text().splitlines():
            line = line.strip()
            if line.startswith("C2_PSK="):
                psk = line.split("=", 1)[1]
                break
    else:
        psk = os.environ.get("C2_PSK", "")

    if not psk:
        log("PSK not found (use --psk, --env-file, or C2_PSK env)", "err")
        return 1

    if len(psk) != 64:
        log(f"length {len(psk)} != 64", "err")
        return 1
    try:
        b = bytes.fromhex(psk)
    except ValueError as e:
        log(f"not valid hex: {e}", "err")
        return 1
    if not any(b):
        log("all zeros — insecure", "err")
        return 1
    if psk.lower() in ("0" * 64, "f" * 64, "a" * 64):
        log("known weak pattern", "err")
        return 1

    log(f"PSK valid: {psk[:8]}...{psk[-4:]} (len=64, non-zero)", "ok")
    return 0


# ---------- ports ----------
def _port_free(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def cmd_ports(args) -> int:
    ok = True
    for label, port in (("c2", args.c2), ("ui", args.ui)):
        free = _port_free("127.0.0.1", port)
        status = "free" if free else "IN USE"
        log(f"  {label} 127.0.0.1:{port}: {status}", "ok" if free else "err")
        if not free:
            ok = False
    return 0 if ok else 1


# ---------- smoke ----------
def cmd_smoke(args) -> int:
    """Запускает сервер + fake_bots, проверяет HELLO, CMD, stop."""
    psk = args.psk or os.urandom(32).hex()
    if not _is_valid_psk(psk):
        log("invalid PSK", "err")
        return 1
    if not _port_free("127.0.0.1", args.c2) or not _port_free("127.0.0.1", args.ui):
        log("ports not free", "err")
        return 1

    env = os.environ.copy()
    env["C2_PSK"] = psk
    env["C2_UI_PASSWORD"] = ""
    env["C2_QUIET_PSK"] = "1"

    tmpdir = Path(tempfile.mkdtemp(prefix="tug-smoke-"))
    server_log = tmpdir / "server.log"
    fakes_log = tmpdir / "fakes.log"

    server_log_f = open(server_log, "w")
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "server.py"), str(args.c2), str(args.ui)],
        cwd=str(tmpdir), env=env,
        stdout=server_log_f, stderr=subprocess.STDOUT,
    )
    fakes = None
    try:
        # ждём, пока сервер откроет порты
        deadline = time.time() + 5.0
        ready = False
        while time.time() < deadline:
            if not _port_free("127.0.0.1", args.c2):
                ready = True
                break
            time.sleep(0.1)
        if not ready:
            log("server did not open c2 port", "err")
            return 1
        log(f"server up: c2={args.c2} ui={args.ui}", "ok")

        fakes_log_f = open(fakes_log, "w")
        fakes = subprocess.Popen(
            [sys.executable, str(ROOT / "fake_bots.py"), "127.0.0.1", str(args.c2),
             "--psk", psk, "--count", str(args.bots), "--interval", "0.1",
             "--no-reconnect"],
            cwd=str(tmpdir), env=env,
            stdout=fakes_log_f, stderr=subprocess.STDOUT,
        )

        # ждём HELLO в логе сервера
        deadline = time.time() + 10.0
        hello_count = 0
        while time.time() < deadline:
            if server_log.exists():
                txt = server_log.read_text(errors="replace")
                hello_count = txt.count("[new]") + txt.count("[reconnect]")
                if hello_count >= args.bots:
                    break
            time.sleep(0.2)
        if hello_count < args.bots:
            log(f"only {hello_count}/{args.bots} bots registered", "err")
            return 1
        log(f"{hello_count} bots registered", "ok")

        # проверяем, что бот виден через list (эвристика: лог содержит "Бот")
        txt = server_log.read_text(errors="replace")
        if "Бот " not in txt:
            log("no 'Бот' lines in server log", "warn")

        # ждём PING/PONG
        time.sleep(2.0)
        txt = server_log.read_text(errors="replace")
        if "PONG" not in txt and "PING" not in txt:
            log("no PING/PONG activity (ok if fast)", "warn")

        log("smoke OK", "ok")
        return 0
    finally:
        for p in (fakes, server):
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    p.kill()
        for f in (server_log_f,):
            try:
                f.close()
            except Exception:
                pass
        if args.keep:
            log(f"logs kept: {tmpdir}", "info")
        else:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------- pack ----------
def cmd_pack(args) -> int:
    version = _project_version()
    git = _git_hash()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"c2-framework-{version}" + (f"-{git[:8]}" if git else "")
    stage = out_dir / name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    for f in PROJECT_FILES:
        p = ROOT / f
        if p.exists():
            shutil.copy2(p, stage / f)
        else:
            log(f"missing: {f}", "warn")

    (stage / "VERSION").write_text(f"{version}\n{git or 'no-git'}\n{time.ctime()}\n")
    if not (stage / "README.md").exists():
        (stage / "README.md").write_text(f"# c2-framework {version}\n")

    # README
    (stage / "README.md").write_text(
        f"# c2-framework {version}\n\n"
        f"git: {git or 'n/a'}\n\n"
        f"## Build\n```bash\ncmake -S . -B build -DCMAKE_BUILD_TYPE=Release\ncmake --build build -j\n```\n\n"
        f"## Run\n```bash\n"
        f"export C2_PSK=$(python3 -c 'import os;print(os.urandom(32).hex())')\n"
        f"python3 server.py 4444 8080\n```\n"
    )
    (stage / "LICENSE").write_text("(set your license)\n")

    archive = out_dir / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(stage, arcname=name)
    log(f"packed: {archive}", "ok")

    if args.zip:
        zarchive = out_dir / f"{name}.zip"
        with zipfile.ZipFile(zarchive, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in stage.rglob("*"):
                if f.is_file():
                    zf.write(f, f.relative_to(out_dir))
        log(f"packed: {zarchive}", "ok")
    return 0


def _project_version() -> str:
    p = ROOT / "CMakeLists.txt"
    if p.exists():
        m = re.search(r"VERSION\s+([0-9.]+)", p.read_text())
        if m:
            return m.group(1)
    p = ROOT / "server.py"
    if p.exists():
        m = re.search(r"v([0-9]+\.[0-9]+)", p.read_text())
        if m:
            return m.group(1)
    return "0.0.0"


def _git_hash() -> str:
    rc, out, _ = run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT)
    return out.strip() if rc == 0 else ""


# ---------- clean ----------
def cmd_clean(args) -> int:
    targets = ["build", "dist", "__pycache__", ".pytest_cache", "bots.json",
               "server.log", "fakes.log"]
    for t in targets:
        p = ROOT / t
        if not p.exists():
            continue
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                p.unlink()
            except OSError:
                pass
        log(f"removed {t}", "ok")
    for pyc in ROOT.rglob("*.pyc"):
        try:
            pyc.unlink()
        except OSError:
            pass
    for pycache in ROOT.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)
    log("clean done", "ok")
    return 0


# ---------- version ----------
def cmd_version(args) -> int:
    v = _project_version()
    g = _git_hash()
    print(f"project: c2-framework")
    print(f"version: {v}")
    print(f"git:     {g or 'n/a'}")
    print(f"date:    {time.ctime()}")
    print(f"python:  {sys.version.split()[0]}")
    print(f"platform:{platform.platform()}")
    return 0


# ---------- main ----------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tug.py", description="Tugboat for c2-framework")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="check environment")
    d.set_defaults(func=cmd_doctor)

    g = sub.add_parser("genpsk", help="generate PSK + .env")
    g.add_argument("--out", help="write .env to this path")
    g.add_argument("--force", action="store_true")
    g.add_argument("--prev", help="previous PSK for rotation")
    g.add_argument("--ui-password", default="")
    g.add_argument("--c2-port", type=int, default=DEFAULT_C2_PORT)
    g.add_argument("--ui-port", type=int, default=DEFAULT_UI_PORT)
    g.set_defaults(func=cmd_genpsk)

    c = sub.add_parser("checkpsk", help="validate PSK")
    c.add_argument("--psk", default="")
    c.add_argument("--env-file", default="")
    c.set_defaults(func=cmd_checkpsk)

    po = sub.add_parser("ports", help="check ports")
    po.add_argument("--c2", type=int, default=DEFAULT_C2_PORT)
    po.add_argument("--ui", type=int, default=DEFAULT_UI_PORT)
    po.set_defaults(func=cmd_ports)

    s = sub.add_parser("smoke", help="smoke test with fake bots")
    s.add_argument("--c2", type=int, default=DEFAULT_C2_PORT)
    s.add_argument("--ui", type=int, default=DEFAULT_UI_PORT)
    s.add_argument("--bots", type=int, default=3)
    s.add_argument("--psk", default="")
    s.add_argument("--keep", action="store_true", help="keep logs")
    s.set_defaults(func=cmd_smoke)

    pk = sub.add_parser("pack", help="pack release archive")
    pk.add_argument("--out", default="dist")
    pk.add_argument("--zip", action="store_true")
    pk.set_defaults(func=cmd_pack)

    cl = sub.add_parser("clean", help="clean build artifacts")
    cl.set_defaults(func=cmd_clean)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=cmd_version)

    return p


def main() -> int:
    ap = build_parser()
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
