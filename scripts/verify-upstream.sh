#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly upstream_dir="$repo_root/vendor/firecrawl"
readonly version="$(tr -d '\n' < "$repo_root/UPSTREAM_VERSION")"
readonly expected_commit="$(tr -d '\n' < "$repo_root/UPSTREAM_COMMIT")"

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]]
test -d "$upstream_dir/.git"

test -f "$upstream_dir/apps/api/Dockerfile"
test -f "$upstream_dir/apps/playwright-service-ts/Dockerfile"
test -f "$upstream_dir/apps/nuq-postgres/Dockerfile"
test -f "$upstream_dir/apps/nuq-postgres/nuq.sql"

actual_tag="$(git -C "$upstream_dir" rev-parse "refs/tags/${version}^{commit}")"
actual_head="$(git -C "$upstream_dir" rev-parse HEAD)"
test "$actual_tag" = "$expected_commit"
test "$actual_head" = "$expected_commit"

# GitHub exposes v2.11.0 as an unsigned lightweight tag (a commit ref), not an
# annotated, signed tag. Check that caveat explicitly while relying on the SHA pin.
tag_type="$(git -C "$upstream_dir" cat-file -t "refs/tags/$version")"
test "$tag_type" = "commit"

verify_checksum() {
  local expected_checksum="$1"
  local path="$2"
  local actual_checksum
  actual_checksum="$(sha256sum "$path" | cut -d ' ' -f 1)"
  test "$actual_checksum" = "$expected_checksum"
  printf '%s  %s\n' "$actual_checksum" "${path#"$upstream_dir/"}"
}

verify_checksum 5cb37d2bfbe194d7e2d3182339caa893c7ce9565d64e9a0a725f510e621bf77e "$upstream_dir/apps/api/Dockerfile"
verify_checksum 1ec8e56cb87a68b6be133ebed56772defd6b9c300763ab838ebd9895f6ef5b7d "$upstream_dir/apps/playwright-service-ts/Dockerfile"
verify_checksum 00108183ba9947db346226e3cc120b92b4cfcc60b215b320ad682f7944e93e45 "$upstream_dir/apps/nuq-postgres/Dockerfile"
verify_checksum 44edb370cfc2601076e174c5461ffdfda8a1051b3c2a87c1b5231d002a66ee77 "$upstream_dir/apps/nuq-postgres/nuq.sql"

printf 'Verified Firecrawl %s at %s; tag is unsigned and lightweight.\n' "$version" "$actual_head"
