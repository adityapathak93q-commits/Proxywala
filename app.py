"""
Proxy Suite web app: a Flask front end for proxy_suite.py.

Run locally:   python app.py
Run on Render: gunicorn app:app --workers 1 --threads 8 --timeout 120

Jobs run in background threads and live in memory, so keep ONE gunicorn worker.
"""
import ipaddress
import json
import os
import random
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from urllib.parse import unquote

import requests
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

import proxy_suite as ps

ps.NO_COLOR = True  # plain text in server logs

# ── Limits (override with environment variables on Render) ─────────
THREADS = int(os.getenv("MAX_THREADS", "60"))             # parallel checks per job
CHECK_TIMEOUT = float(os.getenv("CHECK_TIMEOUT", "8"))    # seconds per proxy
MAX_TEST = int(os.getenv("MAX_PROXIES_PER_JOB", "600"))   # proxies tested per job
MAX_JOBS = int(os.getenv("MAX_CONCURRENT_JOBS", "2"))     # jobs running at once
PER_SOURCE_CAP = 25000                                    # proxies kept per source
MAX_BYTES = 3_000_000                                     # bytes read per source
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
JOB_TTL = 30 * 60                                         # keep finished jobs 30 min
TEST_URL = os.getenv("TEST_URL", "http://httpbin.org/get")  # must return httpbin-style JSON
PROTOCOLS = ("http", "socks4", "socks5")
ANON_RANK = {"elite": 0, "anonymous": 1, "transparent": 2, "unknown": 3}

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)  # real client IP behind Render's proxy

JOBS: dict = {}
LOCK = threading.Lock()


class Job:
    def __init__(self, mode: str, client: str):
        self.id = uuid.uuid4().hex[:12]
        self.mode = mode
        self.client = client
        self.status = "running"      # running | done | error
        self.stage = "queued"        # queued | collecting | testing | locating | done
        self.created = time.time()
        self.finished = None
        self.collected = 0
        self.total = 0
        self.alive = 0
        self.cells: list = []        # "a" (working) / "d" (dead), in completion order
        self.results: list = []
        self.notes: list = []
        self.sources: list = []      # per-source report
        self.error = None

    def public(self) -> dict:
        d = {
            "id": self.id, "mode": self.mode, "status": self.status,
            "stage": self.stage, "collected": self.collected,
            "total": self.total, "tested": len(self.cells),
            "alive": self.alive, "cells": "".join(self.cells),
            "notes": self.notes, "sources": self.sources, "error": self.error,
        }
        if self.status == "done":
            d["results"] = self.results
        return d


# ── Helpers ────────────────────────────────────────────────────────
def is_public_ip(host: str) -> bool:
    """Only test public addresses so the server can't be pointed at internal networks."""
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False


LINE_RE = re.compile(
    r"^(?:(?P<proto>https?|socks4|socks5)://)?"
    r"(?:(?P<user>[^:@\s]+):(?P<pwd>[^@\s]+)@)?"
    r"(?P<host>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})",
    re.I,
)


def parse_proxies(text: str, default_protocol: str):
    proxies, seen, skipped = [], set(), 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            skipped += 1
            continue
        host, port = m.group("host"), int(m.group("port"))
        proto = (m.group("proto") or default_protocol).lower()
        if proto == "https":
            proto = "http"
        if not (1 <= port <= 65535) or not is_public_ip(host):
            skipped += 1
            continue
        key = (host, port, proto)
        if key in seen:
            continue
        seen.add(key)
        proxies.append(ps.Proxy(host=host, port=port, protocol=proto,
                                username=unquote(m.group("user")) if m.group("user") else None,
                                password=unquote(m.group("pwd")) if m.group("pwd") else None))
    return proxies, skipped


def read_capped(url: str, timeout: float) -> str:
    with requests.get(url, headers={"User-Agent": UA, "Accept": "*/*"},
                      timeout=timeout, stream=True) as r:
        r.raise_for_status()
        buf = bytearray()
        for chunk in r.iter_content(65536):
            buf += chunk
            if len(buf) >= MAX_BYTES:
                break
        return bytes(buf).decode("utf-8", "ignore")


def parse_source(kind: str, text: str, proto: str):
    """Yield (host, port, protocol) from one source's raw text."""
    if kind == "json":
        data = json.loads(text)
        items = data.get("data", data) if isinstance(data, dict) else data
        for item in items:
            host, port = item.get("ip") or item.get("host"), item.get("port")
            protos = item.get("protocols")
            if host and port:
                yield str(host), str(port), str(protos[0] if protos else proto).lower()
        return
    if kind == "html":
        from bs4 import BeautifulSoup
        for tr in BeautifulSoup(text, "html.parser").select("table tr"):
            tds = tr.find_all("td")
            if len(tds) >= 2:
                host, port = tds[0].get_text(strip=True), tds[1].get_text(strip=True)
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                    yield host, port, proto
    for m in ps.ProxyScraper.IP_PORT_RE.finditer(text):
        yield m.group(1), m.group(2), proto


def describe_error(e: Exception) -> str:
    if isinstance(e, requests.HTTPError) and e.response is not None:
        return f"HTTP {e.response.status_code}"
    if isinstance(e, requests.Timeout):
        return "Timed out"
    if isinstance(e, requests.ConnectionError):
        return "Connection failed"
    if isinstance(e, ValueError):
        return "Unreadable response"
    return type(e).__name__


def collect(job: Job, names: list, protocols: list) -> dict:
    """Fetch the chosen sources in parallel. Returns {(host, port, proto): source}.
    Stores plain tuples, not Proxy objects, so tens of thousands of entries stay cheap."""
    found: dict = {}
    lock = threading.Lock()

    def work(name: str):
        kind, url = ps.SOURCES[name]
        default = ps.SOURCE_PROTOCOL.get(name, "http")
        n, error = 0, None
        try:
            for host, port, proto in parse_source(kind, read_capped(url, 15), default):
                proto = "http" if proto == "https" else proto
                if proto not in protocols or not port.isdigit() or not (1 <= int(port) <= 65535):
                    continue
                if not is_public_ip(host):
                    continue
                key = (host, int(port), proto)
                with lock:
                    if key in found:
                        continue
                    found[key] = name
                n += 1
                if n >= PER_SOURCE_CAP:
                    break
        except Exception as e:
            error = describe_error(e)
        job.sources.append({"name": name, "protocol": default, "found": n, "error": error})

    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(work, names))
    return found


def geo_batch(ips: list) -> dict:
    """One request per 100 IPs (ip-api.com free tier allows 15 batch calls/min)."""
    out = {}
    ips = list(dict.fromkeys(ips))
    for i in range(0, len(ips), 100):
        try:
            r = requests.post(
                "http://ip-api.com/batch?fields=status,country,countryCode,isp,as,hosting,query",
                json=ips[i:i + 100], timeout=10)
            for d in r.json():
                if d.get("status") == "success":
                    out[d["query"]] = d
        except Exception:
            pass
    return out


def geo_key(p, validator) -> str:
    return p.host if p.exit_ip == validator.real_ip else p.exit_ip


def run_job(job: Job, proxies: list, opts: dict):
    try:
        # If the test endpoint is down, every proxy would look dead. Say so instead.
        try:
            pre = requests.get(TEST_URL, timeout=10)
            bad = pre.status_code != 200 or "origin" not in pre.json()
        except (requests.RequestException, ValueError):
            bad = True
        if bad:
            raise RuntimeError("The test server (httpbin.org) isn't responding right now, "
                               "so no proxy can be checked. Try again in a few minutes.")

        if job.mode == "scrape":
            job.stage = "collecting"
            found = collect(job, opts["sources"], opts["protocols"])
            job.collected = len(found)
            if not found:
                raise RuntimeError("No proxies came back from the selected sources. "
                                   "Check the source report below, or try again in a minute.")
            keys = list(found)
            if len(keys) > opts["limit"]:
                keys = random.sample(keys, opts["limit"])
                job.notes.append(f"Collected {job.collected:,} proxies and tested a random {opts['limit']:,}.")
            proxies = [ps.Proxy(host=h, port=p, protocol=pr, source=found[(h, p, pr)])
                       for h, p, pr in keys]
            found.clear()

        job.total = len(proxies)
        job.stage = "testing"
        validator = WebValidator(timeout=opts["timeout"], threads=THREADS,
                                 test_url=TEST_URL, geo_lookup=False)
        if not validator.real_ip:
            job.notes.append("Couldn't detect this server's own IP, so transparent proxies may show as elite.")

        good = []
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            futures = {ex.submit(validator.validate, p): p for p in proxies}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    p = fut.result()
                except Exception as e:
                    p.error = type(e).__name__
                # A proxy only counts if it returned the JSON we asked for.
                # Some return junk pages with status 200.
                ok = bool(p.alive and p.exit_ip)
                if p.alive and not ok:
                    p.alive, p.error = False, "bad_response"
                job.cells.append("a" if ok else "d")
                if ok:
                    good.append(p)
                    job.alive += 1

        good.sort(key=lambda p: (ANON_RANK.get(p.anonymity, 9), p.latency_ms))

        rank = {"any": 3, "anonymous": 1, "elite": 0}[opts["min_anon"]]
        kept = [p for p in good if ANON_RANK.get(p.anonymity, 9) <= rank]
        if len(kept) < len(good):
            job.notes.append(f"{len(good) - len(kept):,} working proxies were hidden by the anonymity filter.")
        good = kept

        if opts["geo"] and good:
            job.stage = "locating"
            info = geo_batch([geo_key(p, validator) for p in good])
            for p in good:
                g = info.get(geo_key(p, validator))
                if g:
                    p.country = g.get("country")
                    p.country_code = g.get("countryCode")
                    p.isp = g.get("isp")
                    p.asn = g.get("as")
                    p.hosting = "datacenter" if g.get("hosting") else "residential"

        job.results = [asdict(p) for p in good]
        job.stage = "done"
        job.status = "done"
    except Exception as e:
        job.status = "error"
        job.error = str(e) or type(e).__name__
    finally:
        job.finished = time.time()


def cleanup():
    now = time.time()
    with LOCK:
        for jid in [j.id for j in JOBS.values()
                    if j.finished and now - j.finished > JOB_TTL]:
            JOBS.pop(jid, None)


class WebValidator(ps.ProxyValidator):
    """The CLI classifier only looked at the proxy's *response* headers, so it called
    almost everything elite. This also reads what the test server saw: request headers
    echoed in the JSON body, and extra hops in the 'origin' field (X-Forwarded-For)."""

    def _classify(self, headers, body):
        merged = dict(headers)
        origin = ""
        try:
            data = json.loads(body)
            merged.update(data.get("headers") or {})
            origin = str(data.get("origin") or "")
        except Exception:
            pass
        level = super()._classify(merged, body)
        if level == "elite" and "," in origin:
            level = "anonymous"      # the test server saw a forwarding chain
        return level


def err(message: str, code: int = 400):
    return jsonify({"error": message}), code


# ── Routes ─────────────────────────────────────────────────────────
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/healthz")
def healthz():
    return "ok"


def num_opt(data: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(data.get(key, default))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


@app.get("/api/sources")
def list_sources():
    return jsonify([{"name": n, "protocol": ps.SOURCE_PROTOCOL.get(n, "http")}
                    for n in ps.SOURCES])


@app.post("/api/jobs")
def create_job():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode")
    min_anon = data.get("min_anonymity", "any")
    if min_anon not in ("any", "anonymous", "elite"):
        return err("Unknown anonymity filter.")
    opts = {
        "geo": bool(data.get("geo", True)),
        "timeout": num_opt(data, "timeout", int(CHECK_TIMEOUT), 3, 15),
        "limit": num_opt(data, "limit", MAX_TEST, 50, MAX_TEST),
        "min_anon": min_anon,
        "protocols": [], "sources": [],
    }
    proxies, skipped = [], 0

    if mode == "scrape":
        opts["protocols"] = [p for p in data.get("protocols", []) if p in PROTOCOLS]
        if not opts["protocols"]:
            return err("Pick at least one protocol.")
        requested = data.get("sources")
        names = list(ps.SOURCES) if requested is None else [n for n in requested if n in ps.SOURCES]
        opts["sources"] = [n for n in names if ps.SOURCE_PROTOCOL.get(n, "http") in opts["protocols"]]
        if not opts["sources"]:
            return err("None of the selected sources match the chosen protocols.")
    elif mode == "check":
        default = data.get("default_protocol", "http")
        if default not in PROTOCOLS:
            return err("Unknown default protocol.")
        proxies, skipped = parse_proxies(str(data.get("proxies", "")), default)
        if not proxies:
            return err("No usable proxies found. Paste one ip:port per line (public addresses only).")
        if len(proxies) > MAX_TEST:
            return err(f"Too many proxies. The limit is {MAX_TEST:,} per run.")
    else:
        return err("Choose a mode.")

    client = request.remote_addr or "unknown"
    cleanup()
    with LOCK:
        running = [j for j in JOBS.values() if j.status == "running"]
        if any(j.client == client for j in running):
            return err("You already have a run in progress. Wait for it to finish.", 429)
        if len(running) >= MAX_JOBS:
            return err("The server is busy with other runs. Try again in a minute.", 429)
        job = Job(mode, client)
        JOBS[job.id] = job

    if mode == "check" and skipped:
        job.notes.append(f"Skipped {skipped:,} lines (invalid or private addresses).")

    threading.Thread(target=run_job, args=(job, proxies, opts), daemon=True).start()
    return jsonify({"id": job.id}), 202


@app.get("/api/jobs/<job_id>")
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return err("This run expired or the server restarted. Start it again.", 404)
    resp = jsonify(job.public())
    resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
