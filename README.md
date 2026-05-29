# GSTF — gRPC Security Testing Framework

> Automated security testing framework for gRPC APIs, built as part of a Master's thesis at Swiss German University.

**Thesis:** *Contract Testing: A Framework for Security Evaluation in gRPC*  
**Author:** Muhamad Zaenul Hasan Basri — Master of Information Technology, Swiss German University (2025)

---

## Overview

GSTF automates security testing for gRPC APIs by parsing `.proto` files, generating test stubs, and systematically sending attack payloads across all service parameters. It reduces manual testing time by **99%** compared to tools like Postman or gRPCurl.

### How It Works — 4 Phases

```
Phase 1 ── Extraction of Payload    Load attack payloads from YAML
Phase 2 ── Code Generation          Compile .proto → Python stubs (auto)
Phase 3 ── Test Case Creation       Build test cases per service/param/attack
Phase 4 ── Execution                Send requests, detect & validate findings
```

---

## Features

| Category | Feature |
|----------|---------|
| **Detection** | 14 attack types, string matching, time-based blind detection |
| **Anti-FP** | Reflection detection, per-attack exclude lists, confidence scoring |
| **Auth** | Auto login flow, Bearer token injection, custom metadata headers |
| **Filtering** | Attack type filter, service filter |
| **Efficiency** | Early exit after N vulnerabilities per attack, proto caching |
| **Output** | Colored console, Excel report (Results + Unique Findings + Summary) |
| **CI/CD** | Exit code 0 (clean) / 1 (vulnerabilities found) |
| **Proxy** | Traffic interception via mitmproxy or Burp Suite |
| **Robustness** | Per-request timeout, multi-service proto support, baseline-aware timing |

---

## Installation

```bash
git clone https://github.com/N3-Z/GSTF.git
cd GSTF
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Basic scan
python main.py -f protos/auth.proto -u localhost:50051

# Quiet mode (show only vulnerabilities)
python main.py -f protos/auth.proto -u localhost:50051 -q

# With Bearer token
python main.py -f protos/auth.proto -u localhost:50051 \
  -m "authorization=Bearer eyJhbGci..."

# Auto-login then scan
python main.py -f protos/auth.proto -u localhost:50051 \
  --auth-rpc Login \
  --auth-data "username=admin" \
  --auth-data "password=admin123"

# Targeted scan — SQL injection only on Login endpoint
python main.py -f protos/auth.proto -u localhost:50051 \
  --attack sqli --service Login

# CI/CD pipeline
python main.py -f service.proto -u grpc-service:50051 -q
echo "Exit: $?"   # 0 = no vulnerabilities, 1 = found
```

---

## CLI Reference

```
usage: main.py [-h] -f FILE -u URL [-s] [-m KEY=VALUE]
               [--auth-rpc RPC] [--auth-data KEY=VALUE]
               [--auth-field FIELD] [--auth-header KEY=TEMPLATE]
               [--attack TYPES] [--service NAMES]
               [-q] [--delay MS] [--timeout SEC]
               [--max-per-attack N] [--payloads PATH] [--proxy URL]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-f`, `--file` | *(required)* | Path to `.proto` file |
| `-u`, `--url` | *(required)* | gRPC server URL, e.g. `localhost:50051` |
| `-s`, `--secure` | `False` | Enable TLS/SSL |
| `-m KEY=VALUE` | — | Metadata header. Repeatable. e.g. `-m "authorization=Bearer token"` |
| `--auth-rpc` | — | RPC name for auto-login, e.g. `Login` |
| `--auth-data KEY=VALUE` | — | Auth request data. Repeatable. |
| `--auth-field` | `token` | Response field containing the token |
| `--auth-header` | `authorization=Bearer {token}` | Header template for injecting the token |
| `--attack` | all | Comma-separated attack types, e.g. `sqli,xss,lfi` |
| `--service` | all | Comma-separated service names, e.g. `Login,Signup` |
| `-q`, `--quiet` | `False` | Show only vulnerable results |
| `--delay` | `0` | Delay in ms between requests |
| `--timeout` | `30` | Per-request timeout in seconds |
| `--max-per-attack` | `2` | Stop testing an attack after N findings (0 = disabled) |
| `--payloads` | `./core/modules/payloads.yaml` | Custom payload file path |
| `--proxy` | — | HTTP proxy URL, e.g. `http://127.0.0.1:8080` |

---

## Attack Types

| Attack | Type | Detection |
|--------|------|-----------|
| `sqli` | SQL Injection | Error-based + Time-based (4s threshold) |
| `xss` | Cross-Site Scripting | Reflection in response |
| `lfi` | Local File Inclusion | File content patterns |
| `ssrf` | Server-Side Request Forgery | Cloud metadata, internal endpoints |
| `rce` | Remote Code Execution | Command output patterns |
| `xpath_injection` | XPath Injection | XPath error messages |
| `command_injection` | Command Injection | OS command output + Time-based (4s) |
| `ldap_injection` | LDAP Injection | LDAP exception messages |
| `nosql_injection` | NoSQL/MongoDB Injection | MongoDB error classes |
| `ssti` | Server-Side Template Injection | Evaluated math expressions |
| `xxe` | XML External Entity | File content / metadata via XML |
| `format_string` | Format String | Memory corruption indicators |
| `crlf_injection` | CRLF / Header Injection | Injected header reflection |
| `business_logic` | Integer Boundary | Overflow, out-of-range responses |

---

## Output

### Console

```
================================================================
  GSTF - gRPC Security Testing Framework
  Swiss German University | MIT Thesis 2025
================================================================
  Target  : localhost:50051
  Proto   : protos/auth.proto
  Started : 2025-01-01 10:00:00

[PHASE 1] Extracting payloads...
  -> 14 attack types | 122 payloads total

[PHASE 2] Compiling proto & generating stub...
  -> Done in 4 ms | Services: Login, Signup, VerifyToken

[PHASE 3] Building test cases...
  -> 696 test cases across 3 services

[PHASE 4] Executing tests...  [timeout: 30s/req | early exit after 2 vuln/attack]
...
  [   1/696] SQLI                 | username       | VULNERABLE [63% Medium] | SQL Syntax Error...
  [->] Early exit: SQLI on 'username' — 2 found, skipping 9 remaining payload(s)
...
================================================================
  SCAN COMPLETE
================================================================
  Total Planned                 : 696
    Executed                    : 678
    Skipped (early exit)        : 18
  Vulnerable (total)            : 4 (0.6%)
  Unique Vulnerabilities        : 2
  Not Vulnerable                : 674
  Total Time                    : 11119 ms
  Report                        : vulnerability_list_20250101_100005.xlsx
================================================================
```

### Excel Report

The report contains 3 sheets:

| Sheet | Contents |
|-------|---------|
| **Results** | All test cases — red/orange = vulnerable, green = safe |
| **Unique Findings** | Deduplicated vulnerable findings, sorted by confidence |
| **Summary** | Scan statistics, configuration, and metadata |

---

## Proxy Integration (mitmproxy / Burp Suite)

GSTF can route traffic through an interception proxy to inspect, replay, or modify gRPC requests during a scan.

### Why gRPC shows 1 connection in the proxy

gRPC uses **HTTP/2 multiplexing** — all requests are sent over a **single TCP connection** using separate stream IDs, unlike HTTP/1.1 which creates a new connection per request. This is by design and is one of gRPC's performance advantages.

When using a forward proxy (`--proxy`), gRPC creates an HTTP CONNECT tunnel through the proxy. The proxy sees **one TCP tunnel** containing all multiplexed streams, not individual requests.

```
Forward proxy mode (--proxy):
GSTF ──[HTTP CONNECT]──▶ proxy ══[TCP tunnel]══▶ gRPC server
                          proxy sees: 1 tunnel (raw bytes)
```

### Recommended: Reverse Proxy Mode (see individual requests)

To see each gRPC request as a separate entry in the proxy, run the proxy in **reverse proxy mode** and point GSTF directly at the proxy — no `--proxy` flag needed.

```
Reverse proxy mode:
GSTF ──[HTTP/2]──▶ proxy ──[HTTP/2]──▶ gRPC server
                   proxy sees: individual streams/requests
```

#### mitmproxy (recommended for gRPC)

```bash
# Terminal 1 — start mitmproxy as reverse proxy
mitmproxy --mode reverse:localhost:50051 --listen-port 8082

# Terminal 2 — point GSTF to mitmproxy's port (not the real server)
python main.py -f protos/auth.proto -u localhost:8082
```

To decode protobuf messages, give mitmproxy the `.proto` file:
```bash
mitmproxy --mode reverse:localhost:50051 --listen-port 8082 \
  --set content_view_open_browser=true
```

#### Burp Suite Pro (HTTP/2 support)

```bash
# In Burp: Proxy → Options → add listener on 127.0.0.1:8082
#          enable "Support HTTP/2"
# Set target to your gRPC server in the listener settings

python main.py -f protos/auth.proto -u localhost:8082
```

### Forward Proxy Mode (`--proxy` flag)

Use this if you want all traffic routed through the proxy but don't need to inspect individual requests (e.g., for logging total bytes, or network-level filtering):

```bash
# mitmproxy
mitmproxy --listen-port 8082
python main.py -f protos/auth.proto -u localhost:50051 --proxy http://127.0.0.1:8082

# Burp Suite
python main.py -f protos/auth.proto -u localhost:50051 --proxy http://127.0.0.1:8080
```

| Mode | Individual requests visible | Setup |
|------|----------------------------|-------|
| Reverse proxy (recommended) | ✅ Yes | Point GSTF to proxy port |
| Forward proxy (`--proxy`) | ❌ One TCP tunnel | Use `--proxy` flag |

---

## Custom Payloads

Create a `my_payloads.yaml` alongside a `mapping.yaml` in the same directory:

```yaml
# my_payloads.yaml
payload:
  custom_attack:
    param:
      - "malicious_payload_1"
      - "malicious_payload_2"
    resp:
      - "error indicator"
    exclude:
      - "normal response pattern"
    time: 0
```

```yaml
# mapping.yaml (same directory)
string:
  - custom_attack
int:
  - business_logic
```

```bash
python main.py -f service.proto -u localhost:50051 --payloads ./my_payloads.yaml
```

---

## Project Structure

```
gstf/
├── main.py                     # CLI entry point
├── requirements.txt
├── protos/
│   └── auth.proto              # Sample proto file
└── core/
    ├── scan.py                 # Main orchestrator (4-phase engine)
    ├── payload.py              # Payload loader & combiner
    ├── grpc_module.py          # gRPC stub builder & proto compiler
    ├── gpt.py                  # Optional: AI-assisted data generation
    └── modules/
        ├── payloads.yaml       # Attack payload library
        └── mapping.yaml        # Proto type → attack type mapping
```

> `core/grpc_code/` is auto-generated at runtime and excluded from version control.

---

## Requirements

- Python 3.8+
- See `requirements.txt`

---

## License

This project is part of an academic thesis. All rights reserved © 2025 Muhamad Zaenul Hasan Basri.
