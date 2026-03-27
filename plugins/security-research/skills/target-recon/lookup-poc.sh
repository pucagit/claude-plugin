#!/usr/bin/env bash
set -euo pipefail

# lookup-poc.sh — Look up PoC exploits from the PoC-in-GitHub database
# Co-located with the target-recon skill that invokes it.
#
# Usage:
#   ./lookup-poc.sh <CVE-ID> [--json] [--top N]
#
# Examples:
#   ./lookup-poc.sh CVE-2024-0012 --top 3
#   ./lookup-poc.sh CVE-2020-28500 --json
#   ./lookup-poc.sh CVE-2023-44487

POC_REPO_DIR="${HOME}/cve/PoC-in-GitHub"
POC_REPO_URL="https://github.com/nomi-sec/PoC-in-GitHub.git"

# ─── Defaults ───────────────────────────────────────────────────────────
CVE_ID=""
JSON_OUTPUT=false
TOP_N=10

# ─── Parse arguments ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)  JSON_OUTPUT=true; shift ;;
    --top)   TOP_N="$2"; shift 2 ;;
    CVE-*)   CVE_ID="$1"; shift ;;
    *)       echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$CVE_ID" ]]; then
  echo "Usage: $0 <CVE-ID> [--json] [--top N]" >&2
  echo "Example: $0 CVE-2024-0012 --top 3" >&2
  exit 1
fi

# ─── Step 1: Ensure PoC-in-GitHub repo exists and is up to date ─────────
if [[ ! -d "$POC_REPO_DIR" ]]; then
  echo "Cloning PoC-in-GitHub database..." >&2
  mkdir -p "$(dirname "$POC_REPO_DIR")"
  git clone --depth 1 "$POC_REPO_URL" "$POC_REPO_DIR" 2>&1 >&2
  echo "Clone complete." >&2
else
  echo "Updating PoC-in-GitHub database..." >&2
  git -C "$POC_REPO_DIR" pull --quiet 2>&1 >&2 || echo "WARNING: git pull failed, using existing data" >&2
fi

# ─── Step 2: Extract year from CVE ID ──────────────────────────────────
# CVE format: CVE-YYYY-NNNNN
YEAR=$(echo "$CVE_ID" | sed -n 's/CVE-\([0-9]\{4\}\)-.*/\1/p')

if [[ -z "$YEAR" ]]; then
  echo "Invalid CVE ID format: $CVE_ID (expected CVE-YYYY-NNNNN)" >&2
  exit 1
fi

# ─── Step 3: Look up the JSON file ─────────────────────────────────────
JSON_FILE="${POC_REPO_DIR}/${YEAR}/${CVE_ID}.json"

if [[ ! -f "$JSON_FILE" ]]; then
  if $JSON_OUTPUT; then
    echo "{\"cve_id\": \"$CVE_ID\", \"found\": false, \"results\": []}"
  else
    echo "No PoCs found for $CVE_ID"
  fi
  exit 0
fi

# ─── Step 4: Parse and sort by stars (uses python3 — always available) ──
python3 -c "
import json, sys

cve_id = '$CVE_ID'
top_n = $TOP_N
json_output = $( $JSON_OUTPUT && echo True || echo False )

with open('$JSON_FILE', 'r') as f:
    data = json.load(f)

# Sort by stars descending
data.sort(key=lambda x: x.get('stargazers_count', 0), reverse=True)
top = data[:top_n]

if json_output:
    result = {
        'cve_id': cve_id,
        'found': True,
        'total_pocs': len(data),
        'results': [{
            'html_url': r.get('html_url', ''),
            'full_name': r.get('full_name', ''),
            'description': r.get('description', ''),
            'stargazers_count': r.get('stargazers_count', 0),
            'forks_count': r.get('forks_count', 0),
            'created_at': r.get('created_at', ''),
            'updated_at': r.get('updated_at', ''),
            'topics': r.get('topics', [])
        } for r in top]
    }
    print(json.dumps(result, indent=2))
else:
    print('═══════════════════════════════════════════')
    print(f'PoCs for: {cve_id}')
    print(f'Total repositories: {len(data)} (showing top {top_n})')
    print('═══════════════════════════════════════════')
    print()
    for r in top:
        print(f'  Repository: {r.get(\"full_name\", \"N/A\")}')
        print(f'  URL:        {r.get(\"html_url\", \"N/A\")}')
        print(f'  Stars:      {r.get(\"stargazers_count\", 0)}  Forks: {r.get(\"forks_count\", 0)}')
        print(f'  Description: {r.get(\"description\", \"N/A\") or \"N/A\"}')
        print(f'  Created:    {r.get(\"created_at\", \"N/A\")}')
        print(f'  Updated:    {r.get(\"updated_at\", \"N/A\")}')
        print()
"
