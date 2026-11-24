#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ExposedScan — find sensitive files and directories exposed on a LIVE website.

Checks a target base URL for commonly-leaked paths (.git/config, .env,
backups, wp-config.php, phpinfo.php, .DS_Store, keys...), confirms real
exposure by content heuristics, and writes a severity-ranked report.

Scope: only public paths on targets you own or are authorized to test.

Author:   Baran Avisat <baranavisat@gmail.com>
Storefront: https://baranavi.gumroad.com/
License:  MIT
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:
    import certifi  # type: ignore
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:  # noqa: BLE001
    SSL_CTX = ssl.create_default_context()

USER_AGENT = "ExposedScan/1.0 (authorized security audit)"

# path -> (severity, confirmation heuristic or None)
# heuristic: fn(body_lower) -> True when the content really is sensitive
def _has_eq(b: str) -> bool:
    return "=" in b and len(b) > 5

def _is_gitconfig(b: str) -> bool:
    return "[core]" in b

def _is_git_head(b: str) -> bool:
    return "ref:" in b

def _is_dsstore(b: str) -> bool:
    return "buds" in b or "dsstore" in b or len(b) > 0

SENSITIVE_PATHS: Dict[str, Tuple[str, Optional[Callable[[str], bool]]]] = {
    "/.env":                    ("critical", _has_eq),
    "/.env.local":              ("critical", _has_eq),
    "/.env.backup":             ("critical", _has_eq),
    "/.git/config":             ("critical", _is_gitconfig),
    "/.git/HEAD":               ("critical", _is_git_head),
    "/.svn/entries":            ("high", None),
    "/id_rsa":                  ("critical", lambda b: "private key" in b),
    "/.aws/credentials":        ("critical", lambda b: "aws" in b),
    "/wp-config.php":           ("critical", None),
    "/config.php":              ("high", None),
    "/config.json":             ("high", None),
    "/phpinfo.php":             ("high", lambda b: "php version" in b),
    "/info.php":                ("high", lambda b: "php version" in b),
    "/backup.zip":              ("high", None),
    "/backup.tar.gz":           ("high", None),
    "/dump.sql":                ("high", None),
    "/database.sql":            ("high", None),
    "/.DS_Store":               ("medium", _is_dsstore),
    "/.htaccess":               ("medium", None),
    "/web.config":              ("medium", None),
    "/.bash_history":           ("high", None),
    "/server-status":           ("medium", None),
    "/.well-known/security.txt": ("info", None),
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FIX_HINTS = {
    "critical": "Remove from the server NOW and rotate every credential it exposed.",
    "high": "Delete the file, block these paths at the web server, and audit git history for leaks.",
    "medium": "Remove or restrict to internal access (firewall / auth).",
    "info": "Intentional disclosure file — verify it is the one you meant to publish.",
}


@dataclass
class FindResult:
    url: str
    path: str
    status: Optional[int]
    severity: str
    label: str          # EXPOSED | CONFIRMED | SUSPICIOUS | PROTECTED | ABSENT | REDIRECT | ERROR
    content_length: int = 0
    final_url: str = ""
    note: str = ""

    @property
    def fix(self) -> str:
        if self.label in ("EXPOSED", "CONFIRMED"):
            return FIX_HINTS.get(self.severity, "")
        return ""


def http_get(url: str, timeout: float, max_bytes: int = 64_000) -> dict:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept": "*/*"})
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=SSL_CTX))
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes)
            charset = resp.headers.get_content_charset() or "utf-8"
            return {"status": getattr(resp, "status", 200),
                    "body": body.decode(charset, errors="replace"),
                    "final_url": resp.geturl(),
                    "error": None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": "", "final_url": url, "error": None}
    except Exception as e:  # noqa: BLE001
        return {"status": None, "body": "", "final_url": url,
                "error": f"{type(e).__name__}: {e}"}


def classify(status: Optional[int], body: str, path: str) -> Tuple[str, str, str]:
    """Return (label, severity, note) for one probe."""
    severity = SENSITIVE_PATHS.get(path, ("medium", None))[0]
    if status is None:
        return "ERROR", severity, "connection failed"
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT", severity, "redirected — follow manually"
    if status in (404, 410):
        return "ABSENT", severity, ""
    if status in (401, 403):
        return "PROTECTED", severity, "exists but access-controlled"
    if status == 200:
        _, confirm = SENSITIVE_PATHS.get(path, (severity, None))
        body_l = body.lower()
        if confirm is None:
            return "EXPOSED", severity, ""
        if confirm(body_l):
            return "CONFIRMED", severity, "content heuristics matched"
        return "SUSPICIOUS", severity, "200 but content did not match heuristic"
    return "ERROR", severity, f"unexpected status {status}"


def probe(base_url: str, path: str, timeout: float) -> FindResult:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    res = http_get(url, timeout=timeout)
    label, severity, note = classify(res["status"], res["body"], path)
    return FindResult(url=url, path=path, status=res["status"],
                      severity=severity, label=label,
                      content_length=len(res["body"]),
                      final_url=res["final_url"], note=note)


def scan(base_url: str, timeout: float, delay: float,
         paths: Optional[List[str]] = None) -> List[FindResult]:
    results = []
    for p in (paths or list(SENSITIVE_PATHS)):
        results.append(probe(base_url, p, timeout))
        if delay:
            time.sleep(delay)
    return results


def render_markdown(base_url: str, results: List[FindResult]) -> str:
    hits = [r for r in results if r.label in ("EXPOSED", "CONFIRMED", "SUSPICIOUS")]
    hits.sort(key=lambda r: (SEVERITY_ORDER.get(r.severity, 9), r.path))
    protected = [r for r in results if r.label == "PROTECTED"]
    lines = [
        "# ExposedScan Report",
        "",
        f"- **Target:** `{base_url}`",
        f"- **Paths probed:** {len(results)}",
        f"- **Findings (exposed/suspicious):** {len(hits)}",
        f"- **Access-controlled:** {len(protected)}",
        f"- **Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    if hits:
        lines += ["## 🔴 Findings (severity-ranked)", "",
                  "| Severity | Path | Status | Label | Fix |",
                  "|---|---|---|---|---|"]
        for r in hits:
            lines.append(f"| **{r.severity.upper()}** | `{r.path}` | "
                         f"{r.status} | {r.label} | {r.fix} |")
        lines += ["", "## Immediate action list", ""]
        for i, r in enumerate(hits, 1):
            lines.append(f"{i}. `{r.path}` ({r.severity}) — {r.fix}")
    else:
        lines += ["## 🟢 No exposed sensitive files detected",
                  "All probed paths were absent or access-controlled. "
                  "Re-run after every deploy.", ""]
    lines += ["", "---",
              "*Generated by ExposedScan — © 2026 Baran Avisat — "
              "support: baranavisat@gmail.com — "
              "test only targets you own or are authorized to assess.*", ""]
    return "\n".join(lines)


def render_json(base_url: str, results: List[FindResult]) -> str:
    return json.dumps({
        "tool": "ExposedScan", "owner": "Baran Avisat", "target": base_url,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "results": [asdict(r) | {"fix": r.fix} for r in results],
    }, ensure_ascii=False, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="exposedscan",
        description="Find sensitive files/directories exposed on a live site.")
    ap.add_argument("targets", nargs="+", help="base URL(s), e.g. https://example.com")
    ap.add_argument("--out", default=".", help="output directory")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--delay", type=float, default=0.4,
                    help="politeness delay between probes")
    args = ap.parse_args(argv)

    all_findings: Dict[str, List[FindResult]] = {}
    for base in args.targets:
        print(f"[*] Scanning {base} ({len(SENSITIVE_PATHS)} paths)...")
        all_findings[base] = scan(base, args.timeout, args.delay)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for base, results in all_findings.items():
        host = urllib.parse.urlsplit(base).netloc.replace(":", "_") or "target"
        (out / f"exposedscan-{host}.md").write_text(
            render_markdown(base, results), encoding="utf-8")
        (out / f"exposedscan-{host}.json").write_text(
            render_json(base, results), encoding="utf-8")
        hits = [r for r in results if r.label in ("EXPOSED", "CONFIRMED", "SUSPICIOUS")]
        print(f"  -> {len(hits)} finding(s) on {base}")
    print(f"[+] Reports written to {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
