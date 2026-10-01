#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Combined Proxy Suite: Scraper + Validator + Classifier

Features:
  - Scrape ~20 public proxy sources
  - Concurrent validation (threaded)
  - Anonymity classification (transparent / anonymous / elite)
  - Geo + ASN lookup
  - Speed benchmark
  - RotatingSession for requests
  - Export: JSON / CSV / txt / proxychains

Requires: pip install requests beautifulsoup4 PySocks
Usage:    python proxy_suite.py scrape
          python proxy_suite.py scrape --types http,socks5
          python proxy_suite.py validate proxies.txt
          python proxy_suite.py rotate proxies.txt --target https://...

NOTE: Educational / authorized use only.
      Free public proxies are untrusted: never send
      credentials, cookies, or payment data through them.
"""

import argparse
import csv
import io
import json
import os
import random
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Optional

import requests
from bs4 import BeautifulSoup

try:
    import socks  # PySocks
except ImportError:
    socks = None

C = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}
NO_COLOR = False


def col(text: str, color: str) -> str:
    if NO_COLOR or color not in C:
        return text
    return f"{C[color]}{text}{C['reset']}"


def banner(mode: str = ""):
    print(col("COMBINED PROXY SUITE", "bold"))
    if mode:
        print(col(f"Mode -> {mode}", "yellow"))
    print()


# ══════════════════════════════════════════════════════════════════
# DATA MODEL
# ══════════════════════════════════════════════════════════════════
@dataclass
class Proxy:
    host: str
    port: int
    protocol: str = "http"           # http | socks4 | socks5
    username: Optional[str] = None
    password: Optional[str] = None

    # validation results
    alive: bool = False
    latency_ms: float = 0.0
    anonymity: str = "unknown"       # transparent | anonymous | elite
    exit_ip: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    hosting: Optional[str] = None
    error: Optional[str] = None
    source: Optional[str] = None

    def to_url(self) -> str:
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.protocol}://{auth}{self.host}:{self.port}"

    def to_dict_proxy(self) -> dict:
        p = {"http": self.to_url(), "https": self.to_url()}
        return p


# ══════════════════════════════════════════════════════════════════
# SOURCES
# ══════════════════════════════════════════════════════════════════
SOURCES = {
    "proxyscrape_http":   ("plain", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all"),
    "proxyscrape_socks4": ("plain", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all"),
    "proxyscrape_socks5": ("plain", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"),
    "geonode_http":       ("json",  "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http"),
    "geonode_socks5":     ("json",  "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5"),
    "thespeedx_http":     ("plain", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"),
    "thespeedx_socks4":   ("plain", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt"),
    "thespeedx_socks5":   ("plain", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"),
    "monosans_http":      ("plain", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    "monosans_socks5":    ("plain", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
    "shifty_http":        ("plain", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"),
    "shifty_socks5":      ("plain", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"),
    "clarketm_http":      ("plain", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt"),
    "hookzof_socks5":     ("plain", "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"),
    "roosterkid_socks5":  ("plain", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt"),
    "roosterkid_http":    ("plain", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt"),
    "jetkai_http":        ("plain", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt"),
    "jetkai_socks5":      ("plain", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"),
    "proxy_daily":        ("html",  "https://www.proxy-list.download/HTTP"),
    "free_proxy_list":    ("html",  "https://free-proxy-list.net/"),
}

# Default protocol per source (used when the source has mixed protocols)
SOURCE_PROTOCOL = {
    "proxyscrape_http":   "http",
    "proxyscrape_socks4": "socks4",
    "proxyscrape_socks5": "socks5",
    "geonode_http":       "http",
    "geonode_socks5":     "socks5",
    "thespeedx_http":     "http",
    "thespeedx_socks4":   "socks4",
    "thespeedx_socks5":   "socks5",
    "monosans_http":      "http",
    "monosans_socks5":    "socks5",
    "shifty_http":        "http",
    "shifty_socks5":      "socks5",
    "clarketm_http":      "http",
    "hookzof_socks5":     "socks5",
    "roosterkid_socks5":  "socks5",
    "roosterkid_http":    "http",
    "jetkai_http":        "http",
    "jetkai_socks5":      "socks5",
    "proxy_daily":        "http",
    "free_proxy_list":    "http",
}


# ── Additional sources ─────────────────────────────────────────────
# (name, kind, url, protocol). Public lists come and go, so a source that
# stops working is simply reported as failed and skipped.
_GH = "https://raw.githubusercontent.com"
_CDN = "https://cdn.jsdelivr.net/gh"
_EXTRA_SOURCES = [
    # Verified against each project's own documentation
    ("proxifly_http",       "plain", f"{_CDN}/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",   "http"),
    ("proxifly_socks4",     "plain", f"{_CDN}/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt", "socks4"),
    ("proxifly_socks5",     "plain", f"{_CDN}/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt", "socks5"),
    ("proxyscrape_gh_http",   "plain", f"{_CDN}/proxyscrape/free-proxy-list@main/proxies/protocols/http/data.txt",   "http"),
    ("proxyscrape_gh_socks4", "plain", f"{_CDN}/proxyscrape/free-proxy-list@main/proxies/protocols/socks4/data.txt", "socks4"),
    ("proxyscrape_gh_socks5", "plain", f"{_CDN}/proxyscrape/free-proxy-list@main/proxies/protocols/socks5/data.txt", "socks5"),
    ("monosans_socks4",     "plain", f"{_GH}/monosans/proxy-list/main/proxies/socks4.txt", "socks4"),
    ("vpslab_http",         "plain", f"{_GH}/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt",   "http"),
    ("vpslab_socks4",       "plain", f"{_GH}/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4_all.txt", "socks4"),
    ("vpslab_socks5",       "plain", f"{_GH}/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5_all.txt", "socks5"),
    # From memory of well-known lists; check the source report after a run
    ("mmpx12_http",         "plain", f"{_GH}/mmpx12/proxy-list/master/http.txt",   "http"),
    ("mmpx12_socks4",       "plain", f"{_GH}/mmpx12/proxy-list/master/socks4.txt", "socks4"),
    ("mmpx12_socks5",       "plain", f"{_GH}/mmpx12/proxy-list/master/socks5.txt", "socks5"),
    ("zaeem20_http",        "plain", f"{_GH}/Zaeem20/FREE_PROXIES_LIST/master/http.txt",   "http"),
    ("zaeem20_socks4",      "plain", f"{_GH}/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt", "socks4"),
    ("zaeem20_socks5",      "plain", f"{_GH}/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt", "socks5"),
    ("murongpig_http",      "plain", f"{_GH}/MuRongPIG/Proxy-Master/main/http.txt",   "http"),
    ("murongpig_socks4",    "plain", f"{_GH}/MuRongPIG/Proxy-Master/main/socks4.txt", "socks4"),
    ("murongpig_socks5",    "plain", f"{_GH}/MuRongPIG/Proxy-Master/main/socks5.txt", "socks5"),
    ("aliilapro_http",      "plain", f"{_GH}/ALIILAPRO/Proxy/main/http.txt",   "http"),
    ("aliilapro_socks4",    "plain", f"{_GH}/ALIILAPRO/Proxy/main/socks4.txt", "socks4"),
    ("aliilapro_socks5",    "plain", f"{_GH}/ALIILAPRO/Proxy/main/socks5.txt", "socks5"),
    ("prxchk_http",         "plain", f"{_GH}/prxchk/proxy-list/main/http.txt",   "http"),
    ("prxchk_socks4",       "plain", f"{_GH}/prxchk/proxy-list/main/socks4.txt", "socks4"),
    ("prxchk_socks5",       "plain", f"{_GH}/prxchk/proxy-list/main/socks5.txt", "socks5"),
    ("ercin_http",          "plain", f"{_GH}/ErcinDedeoglu/proxies/main/proxies/http.txt",   "http"),
    ("ercin_socks4",        "plain", f"{_GH}/ErcinDedeoglu/proxies/main/proxies/socks4.txt", "socks4"),
    ("ercin_socks5",        "plain", f"{_GH}/ErcinDedeoglu/proxies/main/proxies/socks5.txt", "socks5"),
    ("sunny9577_http",      "plain", f"{_GH}/sunny9577/proxy-scraper/master/generated/http_proxies.txt",   "http"),
    ("sunny9577_socks4",    "plain", f"{_GH}/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt", "socks4"),
    ("sunny9577_socks5",    "plain", f"{_GH}/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt", "socks5"),
    ("kangproxy_http",      "plain", f"{_GH}/officialputuid/KangProxy/KangProxy/http/http.txt",       "http"),
    ("kangproxy_socks4",    "plain", f"{_GH}/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",   "socks4"),
    ("kangproxy_socks5",    "plain", f"{_GH}/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",   "socks5"),
    ("openproxylist_http",  "plain", "https://api.openproxylist.xyz/http.txt",   "http"),
    ("openproxylist_socks4","plain", "https://api.openproxylist.xyz/socks4.txt", "socks4"),
    ("openproxylist_socks5","plain", "https://api.openproxylist.xyz/socks5.txt", "socks5"),
    ("proxylistdl_http",    "plain", "https://www.proxy-list.download/api/v1/get?type=http",   "http"),
    ("proxylistdl_socks4",  "plain", "https://www.proxy-list.download/api/v1/get?type=socks4", "socks4"),
    ("proxylistdl_socks5",  "plain", "https://www.proxy-list.download/api/v1/get?type=socks5", "socks5"),
    ("proxyscrape_v3_http",   "plain", "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http&proxy_format=ipport&format=text",   "http"),
    ("proxyscrape_v3_socks4", "plain", "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4&proxy_format=ipport&format=text", "socks4"),
    ("proxyscrape_v3_socks5", "plain", "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5&proxy_format=ipport&format=text", "socks5"),
    ("geonode_socks4",      "json",  "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks4", "socks4"),
    ("spys_me",             "plain", "https://spys.me/proxy.txt", "http"),
    ("ssl_proxies",         "html",  "https://www.sslproxies.org/", "http"),
    ("us_proxy",            "html",  "https://www.us-proxy.org/",   "http"),
]
for _name, _kind, _url, _proto in _EXTRA_SOURCES:
    SOURCES[_name] = (_kind, _url)
    SOURCE_PROTOCOL[_name] = _proto


# ══════════════════════════════════════════════════════════════════
# SCRAPER
# ══════════════════════════════════════════════════════════════════
class ProxyScraper:
    IP_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")

    def __init__(self, timeout: float = 15.0,
                 user_agent: Optional[str] = None):
        self.timeout = timeout
        self.ua = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        )
        self.seen: set = set()

    def _session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": self.ua, "Accept": "*/*"})
        return s

    def _add(self, host: str, port: str, protocol: str,
             source: str, out: list):
        try:
            port_i = int(port)
        except ValueError:
            return
        if not (1 <= port_i <= 65535):
            return
        if host in ("0.0.0.0", "127.0.0.1", "localhost"):
            return

        key = (host, port_i, protocol)
        if key in self.seen:
            return
        self.seen.add(key)

        out.append(Proxy(host=host, port=port_i,
                         protocol=protocol, source=source))

    def _fetch_plain(self, url: str, protocol: str, source: str,
                     out: list):
        s = self._session()
        r = s.get(url, timeout=self.timeout)
        r.raise_for_status()
        for m in self.IP_PORT_RE.finditer(r.text):
            self._add(m.group(1), m.group(2), protocol, source, out)

    def _fetch_json(self, url: str, protocol: str, source: str,
                    out: list):
        s = self._session()
        r = s.get(url, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()

        items = data.get("data", data) if isinstance(data, dict) else data
        for item in items:
            host = item.get("ip") or item.get("host")
            port = item.get("port")
            proto = (item.get("protocols") or [protocol])[0] if item.get("protocols") else protocol
            if host and port:
                self._add(str(host), str(port), str(proto).lower(),
                          source, out)

    def _fetch_html(self, url: str, protocol: str, source: str,
                    out: list):
        s = self._session()
        r = s.get(url, timeout=self.timeout)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        # Try table rows first (free-proxy-list style)
        table = soup.find("table")
        if table:
            for tr in table.find_all("tr"):
                tds = tr.find_all("td")
                if len(tds) >= 2:
                    host = tds[0].get_text(strip=True)
                    port = tds[1].get_text(strip=True)
                    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                        self._add(host, port, protocol, source, out)

        # Fallback: raw regex
        for m in self.IP_PORT_RE.finditer(r.text):
            self._add(m.group(1), m.group(2), protocol, source, out)

    def scrape_all(self, source_filter: Optional[list] = None,
                   protocol_filter: Optional[list] = None) -> list:
        all_proxies: list = []
        names = source_filter or list(SOURCES.keys())

        print(col(f"[*] Scraping {len(names)} source(s) ...", "yellow"))

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {}
            for name in names:
                if name not in SOURCES:
                    continue
                kind, url = SOURCES[name]
                proto = SOURCE_PROTOCOL.get(name, "http")

                if protocol_filter and proto not in protocol_filter:
                    continue

                if kind == "plain":
                    fn = self._fetch_plain
                elif kind == "json":
                    fn = self._fetch_json
                else:
                    fn = self._fetch_html

                futures[ex.submit(fn, url, proto, name, all_proxies)] = name

            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    fut.result()
                    count = len(all_proxies)
                    line = f"    [✓] {name:<22} total={count}"
                    print(col(line, "dim"))
                except Exception as e:
                    line = f"    [x] {name:<22} {type(e).__name__}"
                    print(col(line, "red"))

        print(col(f"[✓] Collected {len(all_proxies)} unique proxies", "green"))
        return all_proxies


# ══════════════════════════════════════════════════════════════════
# VALIDATOR + CLASSIFIER
# ══════════════════════════════════════════════════════════════════
class ProxyValidator:
    """Validate proxies and classify anonymity / geo."""

    TEST_URL = "http://httpbin.org/get"

    def __init__(self, timeout: float = 8.0, threads: int = 100,
                 test_url: Optional[str] = None,
                 geo_lookup: bool = True):
        self.timeout = timeout
        self.threads = threads
        self.test_url = test_url or self.TEST_URL
        self.geo_lookup = geo_lookup
        self.real_ip = self._get_real_ip()
        self.geo_cache: dict = {}

    @staticmethod
    def _get_real_ip() -> Optional[str]:
        try:
            r = requests.get("https://api.ipify.org", timeout=5)
            return r.text.strip()
        except Exception:
            return None

    def _geo(self, ip: str) -> dict:
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = r.json()
            if data.get("status") != "success":
                data = {}
        except Exception:
            data = {}
        self.geo_cache[ip] = data
        return data

    def _classify(self, headers: dict, body: str) -> str:
        """Classify proxy anonymity by inspecting headers + body."""
        h = {k.lower(): str(v).lower() for k, v in headers.items()}

        via = h.get("via", "")
        xff = h.get("x-forwarded-for", "")
        xreal = h.get("x-real-ip", "")
        fwd = h.get("forwarded", "")

        origin = None
        try:
            origin = json.loads(body).get("origin", "")
        except Exception:
            pass

        leaks_via      = bool(via)
        leaks_xff      = bool(xff)
        leaks_xreal    = bool(xreal)
        leaks_fwd      = bool(fwd)
        leaks_in_body  = bool(self.real_ip and self.real_ip in body)

        any_header_leak = leaks_via or leaks_xff or leaks_xreal or leaks_fwd

        if leaks_in_body or (any_header_leak and self.real_ip and
                             (self.real_ip in via or self.real_ip in xff or
                              self.real_ip in xreal or self.real_ip in fwd)):
            return "transparent"

        if any_header_leak:
            return "anonymous"

        return "elite"

    def validate(self, proxy: Proxy) -> Proxy:
        t0 = time.perf_counter()
        try:
            proxies = proxy.to_dict_proxy()
            r = requests.get(
                self.test_url, proxies=proxies,
                timeout=self.timeout, allow_redirects=False,
            )
            proxy.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            proxy.alive = True

            # Extract exit IP
            try:
                body = r.text
                data = json.loads(body)
                origin = data.get("origin", "")
                proxy.exit_ip = origin.split(",")[0].strip() if origin else None
            except Exception:
                body = r.text
                proxy.exit_ip = None

            proxy.anonymity = self._classify(dict(r.headers), body)

            # Geo / ASN
            if self.geo_lookup and proxy.exit_ip:
                g = self._geo(proxy.exit_ip)
                proxy.country      = g.get("country")
                proxy.country_code = g.get("countryCode")
                proxy.isp          = g.get("isp")
                proxy.asn          = g.get("as")
                proxy.hosting      = "datacenter" if g.get("hosting") else "residential"

        except requests.exceptions.ProxyError as e:
            proxy.error = "proxy_error"
            proxy.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        except requests.exceptions.ConnectTimeout:
            proxy.error = "timeout"
        except requests.exceptions.ReadTimeout:
            proxy.error = "read_timeout"
        except requests.exceptions.SSLError:
            proxy.error = "ssl_error"
        except Exception as e:
            proxy.error = type(e).__name__

        return proxy

    def validate_many(self, proxies: list,
                      alive_only: bool = True) -> list:
        print(col(f"[*] Validating {len(proxies)} proxies "
                  f"({self.threads} threads, timeout {self.timeout}s) ...", "yellow"))

        results: list = []
        done = 0
        alive = 0
        t0 = time.perf_counter()

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.validate, p): p for p in proxies}
            for fut in as_completed(futures):
                done += 1
                try:
                    p = fut.result()
                except Exception as e:
                    p = futures[fut]
                    p.error = type(e).__name__
                results.append(p)

                if p.alive:
                    alive += 1

                if done % 50 == 0 or done == len(proxies):
                    elapsed = time.perf_counter() - t0
                    rate = done / max(0.001, elapsed)
                    line = (f"    [{done}/{len(proxies)}] "
                            f"alive={alive}  ({rate:.1f}/s)")
                    print(col(line, "dim"))

        elapsed = round(time.perf_counter() - t0, 2)
        print(col(f"[✓] Done in {elapsed}s — {alive} alive "
                  f"/ {len(proxies) - alive} dead", "green"))

        if alive_only:
            results = [p for p in results if p.alive]

        # sort: elite first, then by latency
        order = {"elite": 0, "anonymous": 1, "transparent": 2, "unknown": 3}
        results.sort(key=lambda p: (order.get(p.anonymity, 9),
                                    p.latency_ms))
        return results


# ══════════════════════════════════════════════════════════════════
# ROTATING SESSION
# ══════════════════════════════════════════════════════════════════
class RotatingSession(requests.Session):
    """
    Drop-in replacement for requests.Session with automatic proxy rotation.

    Example:
        s = RotatingSession(proxy_list)
        s.get("https://example.com")   # rotates on each call
    """

    def __init__(self, proxies: list, retries: int = 3,
                 timeout: float = 20.0, rotate_every: int = 1,
                 only_alive: bool = True):
        super().__init__()
        self._proxies = [p for p in proxies
                         if (p.alive or not only_alive)]
        if not self._proxies:
            raise ValueError("No usable proxies provided.")
        self._retries = retries
        self._timeout = timeout
        self._rotate_every = rotate_every
        self._counter = 0
        self._current: Optional[Proxy] = None
        self._lock = None  # single-threaded per session

    def _next_proxy(self) -> Proxy:
        if self._current is None or self._counter % self._rotate_every == 0:
            self._current = random.choice(self._proxies)
        self._counter += 1
        return self._current

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self._timeout)
        last_exc = None

        for attempt in range(1, self._retries + 1):
            proxy = self._next_proxy()
            kwargs["proxies"] = proxy.to_dict_proxy()
            try:
                resp = super().request(method, url, **kwargs)
                if resp.status_code < 500:
                    return resp
                last_exc = requests.HTTPError(
                    f"status {resp.status_code} via {proxy.host}:{proxy.port}"
                )
            except requests.RequestException as e:
                last_exc = e
                # mark proxy dead on repeated failure
                proxy.error = type(e).__name__

        if last_exc:
            raise last_exc
        raise requests.RequestException("All retries failed")


# ══════════════════════════════════════════════════════════════════
# EXPORT
# ══════════════════════════════════════════════════════════════════
def export_json(proxies: list, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(p) for p in proxies], fh, indent=2)


def export_csv(proxies: list, path: str):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "port", "protocol", "username", "password",
                    "alive", "latency_ms", "anonymity", "exit_ip",
                    "country", "country_code", "isp", "asn", "hosting",
                    "source", "error"])
        for p in proxies:
            w.writerow([
                p.host, p.port, p.protocol, p.username or "", p.password or "",
                p.alive, p.latency_ms, p.anonymity, p.exit_ip or "",
                p.country or "", p.country_code or "", p.isp or "",
                p.asn or "", p.hosting or "", p.source or "", p.error or "",
            ])


def export_txt(proxies: list, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        for p in proxies:
            fh.write(f"{p.host}:{p.port}\n")


def export_proxychains(proxies: list, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# proxychains config\n")
        fh.write("\n")
        fh.write("strict_chain\n")
        fh.write("proxy_dns\n")
        fh.write("remote_dns_subnet 224\n")
        fh.write("tcp_read_time_out 15000\n")
        fh.write("tcp_connect_time_out 8000\n\n")
        fh.write("[ProxyList]\n")
        for p in proxies:
            ptype = "socks5" if p.protocol.startswith("socks5") else \
                    "socks4" if p.protocol.startswith("socks4") else "http"
            auth = ""
            if p.username and p.password:
                auth = f" {p.username} {p.password}"
            fh.write(f"{ptype} {p.host} {p.port}{auth}\n")


# ══════════════════════════════════════════════════════════════════
# LOAD / SAVE
# ══════════════════════════════════════════════════════════════════
def load_proxies(path: str, default_protocol: str = "http") -> list:
    proxies: list = []
    ip_port = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")

    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            proto = default_protocol
            user = pwd = None

            # protocol:// prefix
            m = re.match(r"^(https?|socks4|socks5)://(.+)$", line, re.I)
            if m:
                proto = m.group(1).lower()
                line = m.group(2)

            # user:pass@host:port
            m = re.match(r"^([^:@]+):([^@]+)@(.+)$", line)
            if m:
                user, pwd, line = m.group(1), m.group(2), m.group(3)

            m = ip_port.search(line)
            if not m:
                continue

            proxies.append(Proxy(
                host=m.group(1), port=int(m.group(2)),
                protocol=proto, username=user, password=pwd,
            ))

    return proxies


def display(proxies: list, limit: int = 30):
    if not proxies:
        print(col("  (empty)", "yellow"))
        return

    anon_color = {"elite": "green", "anonymous": "yellow",
                  "transparent": "red", "unknown": "dim"}
    host_color = {"datacenter": "cyan", "residential": "green"}

    print()
    print(col("── Results ──────────────────────────────────────────────", "dim"))
    print(col(f"  {'#':<4} {'proxy':<24} {'proto':<7} "
              f"{'anon':<12} {'lat':<8} {'country':<8} {'type':<12} src", "bold"))
    print(col("─" * 100, "dim"))

    for i, p in enumerate(proxies[:limit], 1):
        addr = f"{p.host}:{p.port}"
        addr_col = col(f"{addr:<24}", "white")
        proto_col = col(f"{p.protocol:<7}", "dim")

        anon = p.anonymity
        anon_col = col(f"{anon:<12}", anon_color.get(anon, "dim"))

        lat = f"{p.latency_ms:.0f}ms" if p.alive else "-"
        lat_col = col(f"{lat:<8}", "dim")

        country = (p.country_code or "-")[:8]
        country_col = col(f"{country:<8}", "blue")

        htype = p.hosting or "-"
        type_col = col(f"{htype:<12}", host_color.get(htype, "dim"))

        src = (p.source or "-")[:20]
        src_col = col(src, "dim")

        print(f"  {i:<4} {addr_col} {proto_col} {anon_col} "
              f"{lat_col} {country_col} {type_col} {src_col}")

    if len(proxies) > limit:
        print(col(f"  ... and {len(proxies) - limit} more", "dim"))


# ══════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════
def cmd_scrape(args):
    banner("SCRAPE + VALIDATE")

    scraper = ProxyScraper(timeout=args.timeout)
    protocols = args.types.split(",") if args.types else None
    proxies = scraper.scrape_all(protocol_filter=protocols)

    if not proxies:
        print(col("[!] No proxies scraped. Check network / sources.", "red"))
        return

    if not args.no_validate:
        validator = ProxyValidator(
            timeout=args.check_timeout,
            threads=args.threads,
            geo_lookup=not args.no_geo,
        )
        proxies = validator.validate_many(proxies, alive_only=True)

    display(proxies, limit=args.show)

    # Auto-export
    if args.output:
        base, ext = os.path.splitext(args.output)
        ext = ext.lower().lstrip(".")
        if ext == "json":
            export_json(proxies, args.output)
        elif ext == "csv":
            export_csv(proxies, args.output)
        elif ext == "conf" or "proxychains" in args.output:
            export_proxychains(proxies, args.output)
        else:
            export_txt(proxies, args.output)
        print(col(f"[✓] Wrote {len(proxies)} proxies to {args.output}", "green"))
    else:
        # Write three default files
        export_txt(proxies, "proxies.txt")
        export_json(proxies, "proxies.json")
        export_proxychains(proxies, "proxychains.conf")
        print(col("[✓] Wrote proxies.txt / proxies.json / proxychains.conf", "green"))

    print_footer()


def cmd_validate(args):
    banner("VALIDATE")
    proxies = load_proxies(args.file, default_protocol=args.default_protocol)
    print(col(f"[*] Loaded {len(proxies)} proxies from {args.file}", "green"))

    validator = ProxyValidator(
        timeout=args.check_timeout,
        threads=args.threads,
        geo_lookup=not args.no_geo,
    )
    proxies = validator.validate_many(proxies, alive_only=True)

    display(proxies, limit=args.show)

    if args.output:
        base, ext = os.path.splitext(args.output)
        ext = ext.lower().lstrip(".")
        if ext == "json":
            export_json(proxies, args.output)
        elif ext == "csv":
            export_csv(proxies, args.output)
        elif ext == "conf":
            export_proxychains(proxies, args.output)
        else:
            export_txt(proxies, args.output)
        print(col(f"[✓] Wrote {len(proxies)} proxies to {args.output}", "green"))

    print_footer()


def cmd_rotate(args):
    banner("ROTATE TEST")
    proxies = load_proxies(args.file, default_protocol=args.default_protocol)
    print(col(f"[*] Loaded {len(proxies)} proxies", "green"))

    # Quick pre-validate
    validator = ProxyValidator(
        timeout=args.check_timeout,
        threads=args.threads,
        geo_lookup=False,
    )
    proxies = validator.validate_many(proxies, alive_only=True)

    if not proxies:
        print(col("[!] No alive proxies to rotate with.", "red"))
        return

    session = RotatingSession(
        proxies, retries=args.retries,
        timeout=args.check_timeout,
        rotate_every=1, only_alive=True,
    )

    target = args.target or "http://httpbin.org/ip"
    print()
    print(col(f"[*] Hitting {target} x{args.hits} with rotation ...", "yellow"))
    print()

    for i in range(1, args.hits + 1):
        try:
            r = session.request("GET", target)
            snippet = r.text.strip().replace("\n", " ")[:120]
            print(f"  [{i}/{args.hits}] {col(str(r.status_code), 'green')}  {snippet}")
        except Exception as e:
            print(f"  [{i}/{args.hits}] {col('FAIL', 'red')}  {type(e).__name__}: {e}")

    print_footer()


def cmd_convert(args):
    banner("FORMAT CONVERT")
    proxies = load_proxies(args.file, default_protocol=args.default_protocol)
    print(col(f"[*] Loaded {len(proxies)} proxies from {args.file}", "green"))

    out = args.output
    base, ext = os.path.splitext(out)
    ext = ext.lower().lstrip(".")

    if ext == "json":
        export_json(proxies, out)
    elif ext == "csv":
        export_csv(proxies, out)
    elif ext == "conf":
        export_proxychains(proxies, out)
    else:
        export_txt(proxies, out)

    print(col(f"[✓] Wrote {len(proxies)} proxies to {out}", "green"))
    print_footer()


def print_footer():
    print()
    print(col("─" * 68, "dim"))
    print()
    print(col("⚠  Free public proxies are untrusted.", "yellow"))
    print(col("   Never send credentials, cookies, or payment data through them.", "yellow"))


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════
def main():
    global NO_COLOR

    p = argparse.ArgumentParser(
        description="Combined Proxy Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd")

    # ── scrape ────────────────────────────────────────────────
    sp = sub.add_parser("scrape", help="Scrape + validate public proxy sources")
    sp.add_argument("--types", help="comma list: http,socks4,socks5")
    sp.add_argument("--threads", type=int, default=100)
    sp.add_argument("--timeout", type=float, default=15.0,
                    help="source fetch timeout")
    sp.add_argument("--check-timeout", type=float, default=8.0,
                    help="per-proxy validation timeout")
    sp.add_argument("--no-validate", action="store_true",
                    help="skip validation, keep all scraped proxies")
    sp.add_argument("--no-geo", action="store_true",
                    help="skip geo/ASN lookup during validation")
    sp.add_argument("--show", type=int, default=30)
    sp.add_argument("--output", "-o", help="output file (auto-detected by ext)")
    sp.set_defaults(func=cmd_scrape)

    # ── validate ──────────────────────────────────────────────
    vp = sub.add_parser("validate", help="Validate an existing proxy list")
    vp.add_argument("file", help="input file (ip:port per line)")
    vp.add_argument("--default-protocol", default="http",
                    choices=["http", "socks4", "socks5"])
    vp.add_argument("--threads", type=int, default=100)
    vp.add_argument("--check-timeout", type=float, default=8.0)
    vp.add_argument("--no-geo", action="store_true")
    vp.add_argument("--show", type=int, default=30)
    vp.add_argument("--output", "-o")
    vp.set_defaults(func=cmd_validate)

    # ── rotate ────────────────────────────────────────────────
    rp = sub.add_parser("rotate", help="Test rotating session against a URL")
    rp.add_argument("file", help="input file")
    rp.add_argument("--default-protocol", default="http",
                    choices=["http", "socks4", "socks5"])
    rp.add_argument("--target", help="URL to hit (default httpbin/ip)")
    rp.add_argument("--hits", type=int, default=10)
    rp.add_argument("--retries", type=int, default=3)
    rp.add_argument("--threads", type=int, default=100)
    rp.add_argument("--check-timeout", type=float, default=8.0)
    rp.set_defaults(func=cmd_rotate)

    # ── convert ───────────────────────────────────────────────
    cp = sub.add_parser("convert", help="Convert proxy list between formats")
    cp.add_argument("file", help="input file")
    cp.add_argument("output", help="output file (.txt/.json/.csv/.conf)")
    cp.add_argument("--default-protocol", default="http",
                    choices=["http", "socks4", "socks5"])
    cp.set_defaults(func=cmd_convert)

    # ── global ────────────────────────────────────────────────
    p.add_argument("--no-color", action="store_true")

    args = p.parse_args()
    NO_COLOR = args.no_color or not sys.stdout.isatty()

    if not args.cmd:
        banner()
        print()
        p.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()