#!/bin/sh
# Certadomain API - curl examples.
# No API key is needed. Rate limit: 60 units per 5 minutes per IP
# (takeover and lookalike cost 5, everything else 1).
#
#   sh examples/curl.sh example.com

set -eu

API="https://certadomain.com/api/v1"
DOMAIN="${1:-example.com}"

# Combined 0-100 score with an A-E grade and up to 6 prioritized actions.
curl -s "$API/overview?domain=$DOMAIN"
echo

# SPF / DMARC / DKIM / MX analysis (GET or POST).
curl -s "$API/dmarc?domain=$DOMAIN"
echo
curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"domain\": \"$DOMAIN\"}" "$API/dmarc"
echo

# DNS health: nameservers, SOA consistency, DNSSEC, CAA, MX.
curl -s "$API/dnshealth?domain=$DOMAIN"
echo

# Phishing heuristics for a suspicious domain.
curl -s "$API/phishing?domain=$DOMAIN"
echo

# Subdomains seen in Certificate Transparency logs.
curl -s "$API/subdomains?domain=$DOMAIN"
echo

# Show the rate-limit headers only.
curl -s -o /dev/null -D - "$API/overview?domain=$DOMAIN" | grep -i '^ratelimit'

# With jq installed: list the prioritized actions.
if command -v jq >/dev/null 2>&1; then
  curl -s "$API/overview?domain=$DOMAIN" \
    | jq -r '.actions[] | "\(.severity)\t\(.code)"'
fi
