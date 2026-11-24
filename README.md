# ExposedScan — Find sensitive files exposed on your LIVE website

> **Your `.env`, `.git/config` and `wp-config.php` might be one URL away from public.**
> Repos get scanned thousands of times a day — but the files sitting on your **live server** are where real breaches start.
> ExposedScan probes 23 high-risk paths, **confirms real exposure by content**, and hands you a severity-ranked fix list.
> **One command. One-time $19. No subscription.**

---

## The problem

- Secrets scanners (Gitleaks, TruffleHog) check your **git history** — nothing checks what your **web server is actually serving right now**.
- `.env` files, `.git/config`, database dumps, `phpinfo.php`, `.DS_Store` and backups leak through bad deploys, zip-extraction mistakes, and misconfigured servers **daily**.
- Paid exposure-monitoring services cost $35–89 **per month**. This is a check you should run after **every deploy**.

**ExposedScan = the after-deploy security check your pipeline is missing.**

## What it does

1. **Probes** 23 sensitive paths per target: `.env`, `.git/config`, `.git/HEAD`, `id_rsa`, `.aws/credentials`, `wp-config.php`, `backup.zip`, `dump.sql`, `.DS_Store`, `phpinfo.php`, and more
2. **Classifies** every response: `CONFIRMED` / `EXPOSED` / `SUSPICIOUS` / `PROTECTED` (401/403) / `ABSENT` / `REDIRECT` / `ERROR`
3. **Confirms with content heuristics** — a 200 response alone isn't proof; `.env` must contain `key=value`, `.git/config` must contain `[core]`, `id_rsa` must look like a private key (no false alarms from soft-404 pages)
4. **Ranks by severity**: critical → high → medium → info, each with a concrete fix
5. **Reports** in client-ready Markdown + JSON

## Install

```bash
git clone https://github.com/aoodiakdiro0001-ops/exposedscan.git
cd exposedscan
# Python 3.9+ standard library only (certifi optional on Windows)
```

## Usage

```bash
python exposedscan.py https://example.com
python exposedscan.py https://a.com https://b.com --out ./report --delay 0.4
```

### Sample output

```
[*] Scanning https://example.com (23 paths)...
  -> 1 finding(s) on https://example.com
```

```markdown
| Severity | Path | Status | Label | Fix |
|---|---|---|---|---|
| **CRITICAL** | `/.env` | 200 | CONFIRMED | Remove from the server NOW and rotate every credential it exposed. |
| **HIGH** | `/.git/config` | 200 | CONFIRMED | Delete the file, block these paths at the web server, and audit git history for leaks. |
```

## Scope & fairness

**Only test targets you own or are explicitly authorized to assess.** ExposedScan sends one polite `ExposedScan/1.0` user-agent with a configurable delay — it is a diagnostic tool for defensive use, not a penetration-testing weapon. Unauthorized scanning may be illegal in your jurisdiction.

## Support

- **Author:** Baran Avisat — `baranavisat@gmail.com`
- **Store:** [baranavi.gumroad.com](https://baranavi.gumroad.com/)
- **License:** MIT — © 2026 Baran Avisat

---

© 2026 Baran Avisat. All rights reserved. Free updates for life.
