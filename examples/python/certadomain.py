#!/usr/bin/env python3
"""Minimal client and command-line tool for the Certadomain API.

Standard library only (Python 3.8+). No API key is needed.

    python3 certadomain.py overview example.com
    python3 certadomain.py dmarc example.com example.org --json
    python3 certadomain.py overview --file domains.txt --csv > result.csv

As a library:

    from certadomain import Client
    result = Client().get("overview", "example.com")
    print(result["grade"], result["score"])
"""

import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://certadomain.com/api/v1"
TOOLS = ("overview", "dmarc", "dnshealth", "phishing", "subdomains", "takeover", "lookalike")
COST = {"takeover": 5, "lookalike": 5}


class ApiError(Exception):
    """A 4xx/5xx answer. `code` is the stable `error` value from the problem body."""

    def __init__(self, status, code, detail):
        super().__init__("%s %s: %s" % (status, code, detail))
        self.status, self.code, self.detail = status, code, detail


class Client:
    def __init__(self, base_url=API, timeout=60, max_retries=3):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.remaining = None  # RateLimit-Remaining from the last response
        self.reset = None      # RateLimit-Reset (seconds) from the last response

    def get(self, tool, domain):
        """Run one analysis tool and return the parsed JSON result."""
        if tool not in TOOLS:
            raise ValueError("unknown tool: %s" % tool)
        url = "%s/%s?%s" % (self.base_url, tool, urllib.parse.urlencode({"domain": domain}))
        return self._request(url)

    def create_report(self, tool, domain):
        """Store a shareable copy of a result for 30 days; returns {"id", ...}."""
        body = json.dumps({"tool": tool, "domain": domain}).encode()
        return self._request(self.base_url + "/reports", body)

    def get_report(self, report_id):
        return self._request("%s/reports/%s" % (self.base_url, urllib.parse.quote(report_id)))

    def _request(self, url, body=None):
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=body, headers={
                "Accept": "application/json",
                "User-Agent": "certadomain-examples/1.0",
            })
            if body is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    self._read_limits(resp.headers)
                    return json.load(resp)
            except urllib.error.HTTPError as err:
                self._read_limits(err.headers)
                if err.code == 429 and attempt < self.max_retries:
                    wait = int(err.headers.get("Retry-After") or self.reset or 60)
                    print("rate limited; waiting %ds" % wait, file=sys.stderr)
                    time.sleep(wait)
                    continue
                raise _to_api_error(err) from None
        raise AssertionError("unreachable")

    def wait_for_budget(self, cost):
        """Sleep until the current window has at least `cost` units left."""
        if self.remaining is not None and self.remaining < cost and self.reset:
            print("waiting %ds for the rate-limit window" % self.reset, file=sys.stderr)
            time.sleep(self.reset + 1)
            self.remaining = None

    def _read_limits(self, headers):
        try:
            self.remaining = int(headers.get("RateLimit-Remaining"))
            self.reset = int(headers.get("RateLimit-Reset"))
        except (TypeError, ValueError):
            pass


def _to_api_error(err):
    # 404 bodies are an HTML page from the CDN, so rely on the status there.
    try:
        problem = json.load(err)
        return ApiError(err.code, problem.get("error", "unknown"), problem.get("detail", problem.get("title", "")))
    except ValueError:
        return ApiError(err.code, "http_%d" % err.code, err.reason)


def summarize(tool, r):
    """One-line summary per tool for the table/CSV output."""
    if tool == "overview":
        return {"grade": r.get("grade"), "score": r.get("score"),
                "email": r.get("email", {}).get("grade"),
                "actions": " ".join(a["code"] for a in r.get("actions", []))}
    if tool == "dmarc":
        return {"grade": r.get("summary", {}).get("grade"),
                "spf_lookups": r.get("spf_lookups", {}).get("count"),
                "problems": " ".join(f["code"] for f in r.get("findings", [])
                                     if f.get("severity") in ("critical", "warning"))}
    if tool == "dnshealth":
        return {"grade": r.get("grade"), "score": r.get("score"), "dnssec": r.get("dnssec"),
                "nameservers": len(r.get("nameservers", []))}
    if tool == "phishing":
        return {"verdict": r.get("verdict"), "score": r.get("score"),
                "registered": (r.get("registration") or {}).get("registered")}
    if tool == "subdomains":
        return {"count": r.get("count")}
    if tool == "takeover":
        return dict(r.get("summary", {}), scanned=r.get("scanned"))
    if tool == "lookalike":
        return dict(r.get("summary", {}), registered=r.get("registered"))
    return {}


def main(argv=None):
    p = argparse.ArgumentParser(description="Check domains with the Certadomain API.")
    p.add_argument("tool", choices=TOOLS)
    p.add_argument("domains", nargs="*", help="domain names (or use --file)")
    p.add_argument("--file", help="read domains from a file, one per line (# comments allowed)")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="print the full JSON results")
    out.add_argument("--csv", action="store_true", help="print a CSV summary")
    args = p.parse_args(argv)

    domains = list(args.domains)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            domains += [l.split("#")[0].strip() for l in fh if l.split("#")[0].strip()]
    if not domains:
        p.error("give at least one domain or --file")

    client = Client()
    rows, results, failed = [], {}, 0
    for domain in domains:
        client.wait_for_budget(COST.get(args.tool, 1))
        try:
            result = client.get(args.tool, domain)
        except ApiError as e:
            print("%s: %s" % (domain, e), file=sys.stderr)
            failed += 1
            continue
        results[domain] = result
        rows.append(dict({"domain": domain}, **summarize(args.tool, result)))

    if args.json:
        json.dump(results if len(domains) > 1 else next(iter(results.values()), {}),
                  sys.stdout, indent=2, ensure_ascii=False)
        print()
    elif rows:
        fields = list(rows[0].keys())
        if args.csv:
            w = csv.DictWriter(sys.stdout, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        else:
            for row in rows:
                print("  ".join("%s=%s" % (k, row[k]) for k in fields))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
