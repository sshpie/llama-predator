# llama-predator

Black-box vulnerability hunter for [llama.cpp](https://github.com/ggerganov/llama.cpp) HTTP servers.

## Modes

| Mode | Description |
|------|-------------|
| `recon` | Map HTTP surface, fingerprint llama.cpp endpoints |
| `schema` | Probe JSON contract (field presence, type sensitivity, extremes) |
| `fuzz` | Parameter + payload fuzzer |
| `stress` | Concurrency storm |
| `ghost` | Cross-request KV-cache poisoning (poison vs benign) |
| `determinism` | Repeated same-request nondeterminism detector |
| `order` | Order-sensitivity / session-illusion probe |
| `grammar` | BNF grammar bomb (exponential backtrack, OOM, crash) |
| `streaming` | Protocol desync via truncated/dropped connections |
| `shape` | Response schema/contract drift detector |
| `rot` | Long-run time-bomb / latency rot detector |
| `all` | Run everything except `rot` |

## Usage

```bash
pip install requests

python3 llama_predator.py --url http://TARGET:8080 --mode recon
python3 llama_predator.py --url http://TARGET:8080 --mode all
python3 llama_predator.py --url http://TARGET:8080 --mode ghost --cycles 300
python3 llama_predator.py --url http://TARGET:8080 --mode fuzz --endpoint /completion
python3 llama_predator.py --url http://TARGET:8080 --mode rot --rot-min 30
```

## Output

Findings written to `llama-predator-out/findings.json`. Severity levels: CRIT / HIGH / MED / INFO.

## Authorized use only

For security research, authorized penetration testing, and CTF environments only.
