#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly upstream_dir="$repo_root/vendor/firecrawl"
readonly version="$(tr -d '\n' < "$repo_root/UPSTREAM_VERSION")"
readonly expected_commit="$(tr -d '\n' < "$repo_root/UPSTREAM_COMMIT")"
readonly generated_root="$repo_root/.generated"
readonly materialized_dir="$generated_root/firecrawl"

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]]
test -d "$upstream_dir/.git"

# Only ever replace this repository-owned generated directory. Do not accept an
# arbitrary output path, and reject a symlinked parent before removing anything.
if [[ -L "$generated_root" ]]; then
  printf 'Refusing symlinked generated directory: %s\n' "$generated_root" >&2
  exit 1
fi
mkdir -p "$generated_root"
test -d "$generated_root"
test ! -L "$generated_root"
test "$materialized_dir" = "$repo_root/.generated/firecrawl"
test "$(dirname "$materialized_dir")" = "$generated_root"

"$repo_root/scripts/verify-upstream.sh"
git -C "$upstream_dir" cat-file -e "${expected_commit}^{commit}"

staging_dir="$(mktemp -d "$generated_root/.firecrawl.XXXXXX")"
cleanup() {
  rm -rf -- "$staging_dir"
}
trap cleanup EXIT HUP INT TERM

git -C "$upstream_dir" archive --format=tar "$expected_commit" | tar -x -f - -C "$staging_dir"
test ! -e "$staging_dir/.git"

rm -rf -- "$materialized_dir"
mv -- "$staging_dir" "$materialized_dir"
trap - EXIT HUP INT TERM

printf 'Materialized pristine Firecrawl %s at %s.\n' "$expected_commit" "$materialized_dir"