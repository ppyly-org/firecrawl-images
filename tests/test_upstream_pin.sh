#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

readonly expected_version="v2.11.0"
readonly expected_commit="ef12eb36b2f3382838dfe0a0c1a5add3d5df7fe5"
readonly upstream_dir="vendor/firecrawl"

[[ "$(tr -d '\n' < UPSTREAM_VERSION)" == "$expected_version" ]]
[[ "$(tr -d '\n' < UPSTREAM_COMMIT)" == "$expected_commit" ]]
test -f "$upstream_dir/apps/api/Dockerfile"
test -f "$upstream_dir/apps/playwright-service-ts/Dockerfile"
test -f "$upstream_dir/apps/nuq-postgres/Dockerfile"
test -f "$upstream_dir/apps/nuq-postgres/nuq.sql"

actual_tag="$(git -C "$upstream_dir" rev-parse "refs/tags/${expected_version}^{commit}")"
actual_head="$(git -C "$upstream_dir" rev-parse HEAD)"
test "$actual_tag" = "$expected_commit"
test "$actual_head" = "$expected_commit"
