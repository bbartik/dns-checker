# DNS Propagation Checker (A records)

A fast, concurrent CLI to check **A record** resolution for a domain across many public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS, AdGuard, etc.). Useful for validating propagation after making DNS changes.

> Script: `dns_propagation_checker.py`

---

## Features

- Queries dozens of well-known public resolvers **in parallel** (asyncio).
- Shows **answers and TTLs** per resolver.
- Optional **expected IP(s)** check: mark resolvers that have the “new” record.
- **Subset** (default) vs **strict** matching modes.
- **Watch mode** to recheck periodically until everything matches.
- **JSON output** for automation.
- **Custom resolver list** support (`--resolvers-file`).

---

## Requirements

- Python **3.8+**
- [dnspython](https://pypi.org/project/dnspython/) (required)
- [rich](https://pypi.org/project/rich/) (optional, for prettier tables)

```bash
pip install dnspython rich
```

---

## Quick Start

1) See what resolvers return for your domain:
```bash
python dns_propagation_checker.py --domain example.com
```

2) Verify that everyone returns a specific IP (subset match):
```bash
python dns_propagation_checker.py --domain example.com --expected 203.0.113.10
```

3) Require **exact** set match (no extras, no missing):
```bash
python dns_propagation_checker.py --domain example.com \
  --expected 203.0.113.10,203.0.113.11 --strict
```

4) Re-check every 30s until all resolvers match:
```bash
python dns_propagation_checker.py --domain example.com --expected 203.0.113.10 --watch 30
```

5) Use your own resolver list:
```bash
# my_resolvers.txt (one per line)
# Either "IP" or "Name,IP"
8.8.8.8
Cloudflare,1.1.1.1

python dns_propagation_checker.py --domain example.com --resolvers-file my_resolvers.txt
```

---

## CLI Options

```
--domain, -d           The domain to query (required).
--expected, -e         Comma-separated expected A record(s). Example: 203.0.113.10,203.0.113.11
--strict               Require an exact set match. Default is subset (expected ⊆ answers).
--timeout              Per-resolver timeout in seconds (default: 3.0).
--concurrency          Max concurrent resolver queries (default: 50).
--resolvers-file       Path to a custom resolver list file (see format above).
--json                 Output machine-readable JSON instead of a table.
--watch                Seconds between repeat checks. Stops when all match (with --expected).
--max-iterations       With --watch, stop after N iterations (0 = unlimited).
```

**Matching behavior**  
- **Subset** (default): Only requires your expected IP(s) to be present in each resolver’s answers. Extra IPs are allowed (handy when some resolvers return full pools).
- **Strict**: Requires the exact same set as `--expected` (no more, no less).

---

## Output

### Table mode (default)
Shows one row per resolver with:
- Resolver name & IP
- Answer list (comma-separated)
- TTL
- Status: `OK` (matches expectation), `MISMATCH` (doesn’t match), or blank if no `--expected`
- Error (if the query failed)

### JSON mode (`--json`)
Emits an array of objects like:
```json
[
  {
    "resolver_name": "Google",
    "resolver_ip": "8.8.8.8",
    "answers": ["203.0.113.10"],
    "ttl": 300,
    "ok": true,
    "error": null
  }
]
```

- `answers`: list of IPv4 strings (A records).
- `ttl`: integer or null if not present.
- `ok`: true/false when `--expected` is provided; null otherwise.
- `error`: string if the query errored (timeout, NXDOMAIN, NoAnswer, etc.).

---

## Defaults: Included Public Resolvers

The script includes a curated set (non-exhaustive) of well-known recursive resolvers:
- **Google**: `8.8.8.8`, `8.8.4.4`
- **Cloudflare**: `1.1.1.1`, `1.0.0.1`
- **Quad9**: `9.9.9.9`, `149.112.112.112`
- **OpenDNS**: `208.67.222.222`, `208.67.220.220`
- **AdGuard**: `94.140.14.14`, `94.140.15.15`
- **Verisign**: `64.6.64.6`, `64.6.65.6`
- **Neustar**: `156.154.70.5`, `156.154.71.5`
- **Level3/CenturyLink**: `4.2.2.1`, `4.2.2.2`
- **CleanBrowsing**: `185.228.168.9`, `185.228.169.9`
- **Comodo**: `8.26.56.26`, `8.20.247.20`
- **Yandex**: `77.88.8.8`, `77.88.8.1`

> You can override/extend these with `--resolvers-file`.

---

## Watch Mode Details

When `--watch SECONDS` is used **with** `--expected`:
- The script keeps re-checking until **all resolvers** match the expected set, or until you stop it (Ctrl+C), or `--max-iterations` is reached.
- Useful for tracking propagation without babysitting.

---

## Notes & Troubleshooting

- **A-Record only**: This tool queries A records. (AAAA/CNAME/etc. would require extending the script.)
- **Caching/TTL**: High TTLs or intermediate caches may delay updates. Use `--strict` if you need exact-set equality.
- **Timeouts**: Slow/filtered networks can cause timeouts; increase `--timeout` or lower `--concurrency` if needed.
- **NXDOMAIN/NoAnswer**: The `error` column shows these conditions explicitly.
- **Local resolvers**: This tool uses *public* resolvers by IP, not your system’s resolver. If you need to include on-prem resolvers, add them via `--resolvers-file`.

---

## Example Workflows

- **Simple propagation check:**
  ```bash
  python dns_propagation_checker.py -d yourdomain.com -e 203.0.113.10
  ```

- **Continuous watch until all match:**
  ```bash
  python dns_propagation_checker.py -d yourdomain.com -e 203.0.113.10 --watch 30
  ```

- **Automation-friendly JSON for CI/CD hooks:**
  ```bash
  python dns_propagation_checker.py -d yourdomain.com -e 203.0.113.10 --json > results.json
  ```

---

## Contributing

- Open to improvements (e.g., AAAA, resolver discovery, DoH/DoT support, exit status on mismatch, etc.).
- Keep concurrency reasonable and be mindful of public resolver rate limits.

---

## Disclaimer

This tool sends DNS queries to third-party resolvers. Use responsibly and in accordance with applicable policies/laws. No warranty expressed or implied.
