# llama-predator

Black-box vulnerability hunter for [llama.cpp](https://github.com/ggerganov/llama.cpp) HTTP servers.

Zero-install standalone. Point it at a target; it fingerprints the server, discovers live endpoints, and runs the selected attack mode.

## Install

```bash
pip install requests
# or
pip install llama-predator
```

## Usage

```bash
python3 llama_predator.py --url http://TARGET:8080 --mode recon
python3 llama_predator.py --url http://TARGET:8080 --mode all
python3 llama_predator.py --url http://TARGET:8080 --mode ghost --cycles 300
python3 llama_predator.py --url http://TARGET:8080 --mode rot --rot-min 30
python3 llama_predator.py --url http://TARGET:8080 --mode fuzz --endpoint /completion
```

## Modes

| Mode | What it does |
|------|-------------|
| `recon` | Map HTTP surface, fingerprint llama.cpp endpoints, detect open inference routes |
| `schema` | Probe JSON contract — field presence, type sensitivity, extreme values, field injection |
| `fuzz` | Parameter + payload fuzzer — 300 generated cases, concurrency-parallel |
| `stress` | Concurrency storm — N workers hammering inference simultaneously |
| `ghost` | Cross-request KV-cache poisoning — poison request followed by benign, detect bleed |
| `determinism` | Repeated same-prompt nondeterminism detector — flags temperature=0 variance |
| `order` | Order-sensitivity / session-illusion probe — detect multi-turn state leakage |
| `grammar` | BNF grammar bomb — exponential backtrack, OOM, and crash triggers |
| `streaming` | Protocol desync via truncated / dropped streaming connections |
| `shape` | Response schema/contract drift detector — N requests, flag schema mutations |
| `rot` | Long-run latency rot detector — `--rot-min` duration, samples P50/P95/P99 |
| `all` | Run everything except `rot` (which needs `--rot-min`) |

## Options

```
--url        Target URL, e.g. http://10.0.0.42:8080  (required)
--mode       Attack mode (required, see table above)
--endpoint   Force endpoint path — skips recon phase
--workers    Concurrency workers (default: 8)
--cycles     Ghost mode cycles (default: 300)
--count      Fuzz / determinism iteration count (default: 300)
--rot-min    Rot test duration in minutes (default: 30)
--out        Output directory (default: llama-predator-out)
```

## Output

Findings written to `llama-predator-out/findings.json`.

```json
[
  {
    "severity": "HIGH",
    "title": "/slots exposed (unauthenticated)",
    "detail": "Slot management endpoint reachable — reveals concurrency state, enables slot targeting",
    "evidence": { "path": "/slots", "status": 200, "bytes": 1024 }
  }
]
```

Severity levels: `CRIT` / `HIGH` / `MED` / `INFO`

## What it finds

- Unauthenticated inference endpoints (`/completion`, `/v1/chat/completions`, etc.)
- Exposed slot management (`/slots`) — side-channel for active session enumeration
- Model inventory leakage (`/v1/models`, `/props`)
- Prometheus metrics exposure (`/metrics`)
- KV-cache bleed between sessions (ghost mode)
- Schema contract violations and crash surfaces (fuzz/grammar modes)
- Long-run stability issues (rot mode)

## Authorized use only

For security research, authorized penetration testing, and CTF environments only.
