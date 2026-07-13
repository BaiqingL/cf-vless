#!/bin/sh
set -eu

if ! command -v git >/dev/null 2>&1; then
  echo "git is required for the tracked-file privacy scan" >&2
  exit 1
fi

tracked_secret_pattern='(gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|cfk_[A-Za-z0-9_-]{20,}|CLOUDFLARE_GLOBAL_TOKEN=[A-Za-z0-9][A-Za-z0-9_-]{19,}|-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----)'
if git grep -I -n -E "$tracked_secret_pattern" -- . ':!third_party/xray-core'; then
  echo "possible credential or private key found in tracked files" >&2
  exit 1
else
  status=$?
  if [ "$status" -ne 1 ]; then
    exit "$status"
  fi
fi

workstation_path_pattern='/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/'
if git grep -I -n -E "$workstation_path_pattern" -- . ':!third_party/xray-core'; then
  echo "absolute operator workstation path found in tracked files" >&2
  exit 1
else
  status=$?
  if [ "$status" -ne 1 ]; then
    exit "$status"
  fi
fi

email_matches=$(git grep -I -n -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' -- . ':!third_party/xray-core' || {
  status=$?
  if [ "$status" -ne 1 ]; then
    exit "$status"
  fi
})
unexpected_email_matches=$(printf '%s\n' "$email_matches" | grep -E -v '@([A-Za-z0-9.-]+\.)?example\.(com|net|org)' || {
  status=$?
  if [ "$status" -ne 1 ]; then
    exit "$status"
  fi
})
if [ -n "$unexpected_email_matches" ]; then
  printf '%s\n' "$unexpected_email_matches"
  echo "non-example email address found in tracked files" >&2
  exit 1
fi

edge_hostname_matches=$(git grep -I -n -E '(^|[^A-Za-z0-9-])edge\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}' -- . ':!third_party/xray-core' || {
  status=$?
  if [ "$status" -ne 1 ]; then
    exit "$status"
  fi
})
unexpected_edge_hostname_matches=$(printf '%s\n' "$edge_hostname_matches" | grep -E -v 'edge\.([A-Za-z0-9-]+\.)*example(\.(com|net|org))?' || {
  status=$?
  if [ "$status" -ne 1 ]; then
    exit "$status"
  fi
})
if [ -n "$unexpected_edge_hostname_matches" ]; then
  printf '%s\n' "$unexpected_edge_hostname_matches"
  echo "non-example edge hostname found in tracked files" >&2
  exit 1
fi

if git grep -I -n -i -E "(api[_-]?token|api[_-]?key|authorization)[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9][^\"']{7,}" -- \
  worker/src worker/wrangler.jsonc worker/cloudflare.config.ts cmd internal \
  ':(exclude,glob)**/*_test.go'; then
  echo "possible hard-coded credential found" >&2
  exit 1
else
  status=$?
  if [ "$status" -ne 1 ]; then
    exit "$status"
  fi
fi

if git grep -I -n -E 'console\.(log|error)|(^|[^A-Za-z])(log|printf|println)\(.*(uuid|path|destination|client[_-]?ip|request\.url)' -- \
  worker/src cmd internal \
  ':(exclude,glob)**/*_test.go'; then
  echo "sensitive logging pattern found" >&2
  exit 1
else
  status=$?
  if [ "$status" -ne 1 ]; then
    exit "$status"
  fi
fi
