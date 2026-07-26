#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s {api|playwright} IMAGE\n' "$0" >&2
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
  *)
    usage
    ;;
esac

printf 'Smoke test passed for %s image %s.\n' "$component" "$image"
