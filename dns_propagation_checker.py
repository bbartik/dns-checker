#!/usr/bin/env python3

"""
dns_propagation_checker.py

Check a domain's A record across many public DNS resolvers (Google, Cloudflare, Quad9,
OpenDNS, AdGuard, etc.) concurrently. Optionally compare results to an expected set of
IPs to see which resolvers have the updated record.

Requires: dnspython (pip install dnspython)
Optional: rich (for prettier tables) (pip install rich)

Usage examples:
  # Just see what each resolver returns
  python dns_propagation_checker.py --domain example.com

  # Verify that the record has updated everywhere to 203.0.113.10
  python dns_propagation_checker.py --domain example.com --expected 203.0.113.10

  # Verify two IPs (subset match by default)
  python dns_propagation_checker.py --domain example.com --expected 203.0.113.10,203.0.113.11

  # Strict mode: require the exact set (no extras, no missing)
  python dns_propagation_checker.py --domain example.com --expected 203.0.113.10,203.0.113.11 --strict

  # Watch until all resolvers return the expected set, checking every 30 seconds
  python dns_propagation_checker.py --domain example.com --expected 203.0.113.10 --watch 30

  # Use your own resolvers list (one IP per line)
  python dns_propagation_checker.py --domain example.com --resolvers-file my_resolvers.txt
"""
import argparse
import asyncio
import ipaddress
import json
import sys
from typing import Dict, List, Optional, Set, Tuple

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
except Exception as e:
    print("This script requires dnspython. Install with: pip install dnspython", file=sys.stderr)
    raise

# Optional pretty output
RICH_AVAILABLE = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
except Exception:
    pass

DEFAULT_RESOLVERS: Dict[str, List[str]] = {
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
    "AdGuard": ["94.140.14.14", "94.140.15.15"],
    "Verisign": ["64.6.64.6", "64.6.65.6"],
    "Neustar": ["156.154.70.5", "156.154.71.5"],
    "Level3/CenturyLink": ["4.2.2.1", "4.2.2.2"],
    "CleanBrowsing": ["185.228.168.9", "185.228.169.9"],
    "Comodo": ["8.26.56.26", "8.20.247.20"],
    "Yandex": ["77.88.8.8", "77.88.8.1"],
}

def _flatten_resolvers(mapping: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for name, ips in mapping.items():
        for ip in ips:
            out.append((name, ip))
    return out

def _load_resolvers_file(path: str) -> List[Tuple[str, str]]:
    resolvers: List[Tuple[str, str]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            # allow "Name,IP" or just "IP"
            if "," in raw:
                maybe_name, maybe_ip = [x.strip() for x in raw.split(",", 1)]
                try:
                    ipaddress.ip_address(maybe_ip)
                    resolvers.append((maybe_name or maybe_ip, maybe_ip))
                except ValueError:
                    continue
            else:
                try:
                    ipaddress.ip_address(raw)
                    resolvers.append((raw, raw))
                except ValueError:
                    continue
    return resolvers

async def query_resolver(resolver_ip: str, domain: str, timeout: float = 3.0) -> Dict:
    """Query one resolver for A records for the domain."""
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.timeout = timeout
    r.lifetime = timeout
    result: Dict = {
        "resolver_ip": resolver_ip,
        "answers": [],
        "ttl": None,
        "error": None,
    }
    try:
        # Disable search domains; ask exactly for the FQDN
        answer = await r.resolve(domain, rdtype="A", search=False, raise_on_no_answer=False)
        if answer.rrset is None:
            result["answers"] = []
            result["ttl"] = None
        else:
            result["answers"] = [rr.address for rr in answer]
            result["ttl"] = answer.rrset.ttl
    except (dns.exception.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = f"Unexpected: {e.__class__.__name__}: {e}"
    return result

def compare_answers(answers: List[str], expected: Optional[Set[str]], strict: bool) -> Optional[bool]:
    """Return True/False if comparison is possible, else None when no expected set provided."""
    if not expected:
        return None
    aset = set(answers)
    if strict:
        return aset == expected
    # subset match: expected must be contained in the answer set
    return expected.issubset(aset)

async def run_once(domain: str,
                   expected: Optional[Set[str]],
                   strict: bool,
                   resolvers: List[Tuple[str, str]],
                   timeout: float,
                   concurrency: int) -> List[Dict]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []

    async def worker(name_ip: Tuple[str, str]) -> Dict:
        name, ip = name_ip
        async with sem:
            r = await query_resolver(ip, domain, timeout=timeout)
            r["resolver_name"] = name
            r["ok"] = compare_answers(r.get("answers", []), expected, strict)
            return r

    tasks = [asyncio.create_task(worker(nip)) for nip in resolvers]
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    return results

def print_table(domain: str, expected: Optional[Set[str]], strict: bool, results: List[Dict]) -> None:
    if RICH_AVAILABLE:
        console = Console()
        table = Table(title=f"DNS A record check for {domain}", box=box.SIMPLE_HEAVY)
        table.add_column("Resolver", style="bold")
        table.add_column("IP")
        table.add_column("Answer(s)")
        table.add_column("TTL")
        table.add_column("Status")
        table.add_column("Error")
        for r in sorted(results, key=lambda x: (x["resolver_name"], x["resolver_ip"])):
            ans = ",".join(r.get("answers") or [])
            ttl = str(r.get("ttl")) if r.get("ttl") is not None else ""
            status = ""
            if r.get("ok") is True:
                status = "[green]OK[/green]"
            elif r.get("ok") is False:
                status = "[red]MISMATCH[/red]"
            elif expected:
                status = "[yellow]-[/yellow]"
            err = r.get("error") or ""
            table.add_row(r.get("resolver_name", ""), r.get("resolver_ip", ""), ans, ttl, status, err)
        console.print(table)
        if expected:
            mode = "STRICT equality" if strict else "SUBSET (expected ⊆ answers)"
            console.print(f"[bold]Expected:[/bold] {','.join(sorted(expected))}   [bold]Mode:[/bold] {mode}")
    else:
        print(f"== DNS A record check for {domain} ==")
        header = f"{'Resolver':20} {'IP':16} {'Answers':35} {'TTL':6} {'Status':10} {'Error'}"
        print(header)
        print("-" * len(header))
        for r in sorted(results, key=lambda x: (x["resolver_name"], x["resolver_ip"])):
            ans = ",".join(r.get("answers") or [])
            ttl = str(r.get("ttl")) if r.get("ttl") is not None else ""
            status = ""
            if r.get("ok") is True:
                status = "OK"
            elif r.get("ok") is False:
                status = "MISMATCH"
            elif expected:
                status = "-"
            err = r.get("error") or ""
            print(f"{r.get('resolver_name','')[:20]:20} {r.get('resolver_ip','')[:16]:16} {ans[:35]:35} {ttl:6} {status:10} {err}")
        if expected:
            mode = "STRICT equality" if strict else "SUBSET (expected ⊆ answers)"
            print(f"Expected: {','.join(sorted(expected))}   Mode: {mode}")

def all_ok(results: List[Dict]) -> bool:
    oks = [r.get("ok") for r in results if r.get("ok") is not None]
    return len(oks) > 0 and all(oks)

def parse_expected(s: Optional[str]) -> Optional[Set[str]]:
    if not s:
        return None
    parts = [p.strip() for p in s.split(",") if p.strip()]
    return set(parts) if parts else None

def build_resolver_list(file_path: Optional[str]) -> List[Tuple[str, str]]:
    if file_path:
        return _load_resolvers_file(file_path)
    return _flatten_resolvers(DEFAULT_RESOLVERS)

def to_json(results: List[Dict]) -> List[Dict]:
    out = []
    for r in results:
        out.append({
            "resolver_name": r.get("resolver_name"),
            "resolver_ip": r.get("resolver_ip"),
            "answers": r.get("answers"),
            "ttl": r.get("ttl"),
            "ok": r.get("ok"),
            "error": r.get("error"),
        })
    return out

async def main():
    parser = argparse.ArgumentParser(description="Check a domain's A record across many public DNS resolvers.")
    parser.add_argument("--domain", "-d", required=True, help="The domain name to query (e.g., example.com)")
    parser.add_argument("--expected", "-e", help="Comma-separated expected A record(s) (e.g., 203.0.113.10,203.0.113.11)")
    parser.add_argument("--strict", action="store_true", help="Require exact set match (default: subset match)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-resolver timeout in seconds (default: 3.0)")
    parser.add_argument("--concurrency", type=int, default=50, help="Max concurrent queries (default: 50)")
    parser.add_argument("--resolvers-file", help="Path to a file containing resolver IPs (and optional names). One per line, format 'Name,IP' or 'IP'")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of a table")
    parser.add_argument("--watch", type=int, default=0, help="Seconds between checks; if provided, will repeat until all resolvers match")
    parser.add_argument("--max-iterations", type=int, default=0, help="If --watch is set, stop after this many iterations (0 = unlimited)")
    args = parser.parse_args()

    expected = parse_expected(args.expected)
    resolvers = build_resolver_list(args.resolvers_file)

    if not resolvers:
        print("No resolvers to query. Provide --resolvers-file or use defaults.", file=sys.stderr)
        sys.exit(2)

    iteration = 0
    while True:
        iteration += 1
        results = await run_once(
            domain=args.domain,
            expected=expected,
            strict=args.strict,
            resolvers=resolvers,
            timeout=args.timeout,
            concurrency=args.concurrency,
        )

        if args.json:
            print(json.dumps(to_json(results), indent=2))
        else:
            print_table(args.domain, expected, args.strict, results)

        if args.watch <= 0:
            break

        if expected and all_ok(results):
            # All resolvers reflect the expected IP set
            break

        if args.max-iterations and iteration >= args.max-iterations:
            break

        try:
            await asyncio.sleep(args.watch)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
