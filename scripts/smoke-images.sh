#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s {api|playwright|migration|pgcron|mcp} IMAGE\n' "$0" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
readonly component="$1"
readonly image="$2"

[[ -n "$image" ]] || usage
docker image inspect "$image" >/dev/null

case "$component" in
  api)
    docker run --rm --entrypoint /bin/sh "$image" -ec '
      test -s /app/dist/src/harness.js
      test -s /app/sharedLibs/go-html-to-md/libhtml-to-markdown.so
      ! command -v npm
      node --version
      node -e "require(\"./dist/src/config.js\")"
    '
    ;;
  playwright)
    [[ "$(docker image inspect --format '{{json .Config.Cmd}}' "$image")" == '["node","dist/api.js"]' ]]
    docker run --rm --entrypoint /bin/sh "$image" -ec '
      test -s /usr/src/app/dist/api.js
      ! command -v npm
      node --version
      node -e '\''
        const fs = require("fs");
        const { chromium } = require("playwright");
        const executable = chromium.executablePath();
        if (!fs.existsSync(executable)) {
          throw new Error(`Chromium executable is missing: ${executable}`);
        }
        console.log(executable);
      '\''
    '
    ;;
  migration)
    docker run --rm --entrypoint /bin/sh "$image" -ec '
      psql --version | grep -q "PostgreSQL) 18"
      test -s /migrations/nuq.sql
      grep -q "CREATE EXTENSION IF NOT EXISTS pg_cron" /migrations/nuq.sql
      ! command -v npm 2>/dev/null
      id -u | grep -qv "^0$"
    '
    ;;
  pgcron)
    # scratch image: verify the CNPG ImageVolume layout from the exported fs.
    cid="$(docker create "$image" /nonexistent)"
    trap 'docker rm -f "$cid" >/dev/null 2>&1' EXIT
    listing="$(docker export "$cid" | tar -tf -)"
    printf '%s\n' "$listing" | grep -qx 'lib/pg_cron.so'
    printf '%s\n' "$listing" | grep -qx 'share/extension/pg_cron.control'
    printf '%s\n' "$listing" | grep -qE 'share/extension/pg_cron--1\.6\.sql|share/extension/pg_cron--1\.5--1\.6\.sql'
    ;;
  mcp)
    # The server must start, bind, and speak MCP. It exits(1) when neither a
    # credential nor FIRECRAWL_API_URL is set, so supply a dummy URL: this
    # asserts startup and protocol, not connectivity to a real Firecrawl.
    cid="$(docker run -d -e FIRECRAWL_API_URL=http://127.0.0.1:1 -e PORT=3000 "$image")"
    trap 'docker rm -f "$cid" >/dev/null 2>&1' EXIT
    for _ in $(seq 1 30); do
      docker exec "$cid" node -e 'require("net").connect(3000,"127.0.0.1").on("connect",()=>process.exit(0)).on("error",()=>process.exit(1))' && break
      sleep 1
    done
    docker exec "$cid" node -e 'require("net").connect(3000,"127.0.0.1").on("connect",()=>process.exit(0)).on("error",()=>process.exit(1))'
    # npm must not ship in the runtime image (repo hardening rule).
    ! docker run --rm --entrypoint /bin/sh "$image" -c 'command -v npm' >/dev/null 2>&1
    ;;
  *)
    usage
    ;;
esac

printf 'Smoke test passed for %s image %s.\n' "$component" "$image"
