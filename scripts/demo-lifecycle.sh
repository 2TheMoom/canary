#!/usr/bin/env bash
# Drives the demo canary through every state on Bradbury and checks it after each change.
# raw.githubusercontent.com caches for 5 minutes, so each step waits that out.
set -u
cd "$(dirname "$0")/.."
RAW=https://raw.githubusercontent.com/2TheMoom/canary/main/demo/CANARY.txt
ID="$RAW|exampleorg has not received any gag orders|7|400"
WAIT=${WAIT:-360}

step() {
  echo "=== $1  ($(date -u +%H:%M:%S) UTC)"
  git add -A demo && git commit -q -m "demo: $1" && git push -q
  sleep "$WAIT"
  node scripts/live.mjs check "$ID" 2>&1 | grep -E "tx 0x|exec=|\"status\"|last_date|\"checks\"|rror"
}

# 1. reword the statement: the page is still there but no longer says it
printf 'Canary demo statement\n\nThis page is a demo canary for the Canary contract. Nothing here is a real legal statement.\n\nExampleOrg can no longer comment on legal requests.\nSigned: 2026-10-13\n' > demo/CANARY.txt
step "reword the statement"

# 2. delete the page
git rm -q demo/CANARY.txt
step "delete the page"

# 3. restore it with a fresh date
printf 'Canary demo statement\n\nThis page is a demo canary for the Canary contract. Nothing here is a real legal statement.\n\nExampleOrg has not received any gag orders.\nSigned: 2026-10-13\n' > demo/CANARY.txt
step "restore the statement"
echo "=== done"
