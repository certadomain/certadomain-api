# Certadomain API

OpenAPI specification and sample clients for the [Certadomain](https://certadomain.com) API:
registration-free, DNS-only domain security checks (SPF / DMARC / DKIM, DNS health,
phishing heuristics, Certificate Transparency subdomains, dangling CNAMEs and lookalike domains).

- **Docs:** https://certadomain.com/api-docs.html
- **Spec:** [`openapi.json`](openapi.json) (OpenAPI 3.1), also served live at
  https://certadomain.com/api/v1/openapi.json
- **No API key.** Target web pages are never fetched; every check uses DNS, registry and CT data only.

## Endpoints

Base URL: `https://certadomain.com/api/v1`

| Endpoint | What it does | Cost |
|---|---|---|
| `GET /overview?domain=` | Combined 0-100 score, A-E grade, up to 6 prioritized actions | 1 |
| `GET /dmarc?domain=` (or `POST`) | SPF / DMARC / DKIM / MX analysis with SPF lookup count | 1 |
| `GET /dnshealth?domain=` | Nameservers, SOA consistency, DNSSEC, CAA, MX | 1 |
| `GET /phishing?domain=` | Phishing heuristics (patterns, DNS signals, registration age) | 1 |
| `GET /subdomains?domain=` | Subdomains seen in Certificate Transparency logs | 1 |
| `GET /takeover?domain=` | DNS-only dangling-CNAME scan of CT subdomains | 5 |
| `GET /lookalike?domain=` | Registered typosquatting / homograph domains | 5 |
| `POST /reports` / `GET /reports/{id}` | Store and read a shareable result (30 days) | 1 |

## Quick start

```bash
curl -s "https://certadomain.com/api/v1/overview?domain=example.com"
```

```bash
python3 examples/python/certadomain.py overview example.com
```

```
domain=example.com  grade=A  score=96  email=protected  actions=DMARC_NO_RUA
```

## Examples

### [`examples/curl.sh`](examples/curl.sh)

One curl call per endpoint, plus rate-limit headers and a `jq` filter.

```bash
sh examples/curl.sh example.com
```

### [`examples/python/certadomain.py`](examples/python/certadomain.py)

A small client and command-line tool. Standard library only (Python 3.8+). It waits for the
rate-limit window instead of failing, and retries on `429` using `Retry-After`.

```bash
# One-line summary
python3 examples/python/certadomain.py dmarc example.com example.org

# Full JSON
python3 examples/python/certadomain.py dnshealth example.com --json

# Check a list of domains and save a CSV
python3 examples/python/certadomain.py overview --file domains.txt --csv > result.csv
```

As a library:

```python
from certadomain import Client, ApiError

client = Client()
try:
    r = client.get("dmarc", "example.com")
    for f in r["findings"]:
        if f["severity"] in ("critical", "warning"):
            print(f["code"], f.get("params", {}))
except ApiError as e:
    print(e.status, e.code)
```

## Usage notes

- **Rate limit:** 60 units per 5 minutes per client IP. `takeover` and `lookalike` cost 5,
  everything else 1. Responses carry `RateLimit-Limit`, `RateLimit-Remaining` and
  `RateLimit-Reset`; `429` adds `Retry-After`.
- **Errors** are `application/problem+json` (RFC 9457) with a stable `error` code. The exception is
  `404`, whose body is an HTML page; use the status code.
- **Caching:** results are stored per domain for about 1 hour (CT data 2 hours). `cached` and
  `analyzed_at` tell you which you got.
- **Compatibility:** within `/v1` fields are only added, never removed or renamed. Ignore unknown
  properties, and rely on `findings[].code` rather than scores for decisions.
- **CORS** allows only https://certadomain.com, so call the API from your server or a script.

## Feedback

Questions and bug reports: [GitHub Issues](../../issues) or https://certadomain.com/contact.html

## License

The sample code in this repository is released under the [MIT License](LICENSE).
Use of the API itself is free within the rate limit.
