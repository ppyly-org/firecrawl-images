#!/usr/bin/env bash
# Populate or verify the exact authenticated builder cache.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="$repo_root/sources/postgresql-18.4-dev.lock"
cache="$repo_root/.cache/builder-debs"
offline=false

usage() { printf 'Usage: %s [--lock PATH] [--cache PATH] [--offline]\n' "$0" >&2; exit 2; }
while (($#)); do
  case "$1" in
    --lock) lock=${2:?missing lock path}; shift 2 ;;
    --cache) cache=${2:?missing cache path}; shift 2 ;;
    --offline) offline=true; shift ;;
    *) usage ;;
  esac
done

[[ -f "$lock" && ! -L "$lock" ]] || { printf 'fetch-builder-debs: lock is not a regular file: %s\n' "$lock" >&2; exit 1; }
if "$offline"; then
  exec python3 "$repo_root/scripts/verify_builder_lock.py" verify-cache --lock "$lock" --cache "$cache"
else
  exec python3 "$repo_root/scripts/verify_builder_lock.py" refresh-cache --lock "$lock" --cache "$cache"
fi
