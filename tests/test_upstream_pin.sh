#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly expected_version="v2.11.0"
readonly expected_commit="ef12eb36b2f3382838dfe0a0c1a5add3d5df7fe5"
readonly upstream_dir="$repo_root/vendor/firecrawl"
readonly generated_dir="$repo_root/.generated/firecrawl"
readonly test_root="$repo_root/.test-upstream-pin"
readonly backup_upstream_dir="$test_root/original-firecrawl"
readonly remote_dir="$test_root/firecrawl.git"

require_failure() {
  if "$@"; then
    printf 'Expected command to fail: %q\n' "$*" >&2
    return 1
  fi
}

cleanup() {
  rm -rf -- "$generated_dir"
  rmdir -- "$repo_root/.generated" 2>/dev/null || true
  if [[ -e "$backup_upstream_dir" ]]; then
    rm -rf -- "$upstream_dir"
    mkdir -p "$(dirname "$upstream_dir")"
    mv -- "$backup_upstream_dir" "$upstream_dir"
  fi
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

cd "$repo_root"
rm -rf -- "$test_root" "$generated_dir"
mkdir -p "$test_root"

if [[ -e "$upstream_dir" ]]; then
  mv -- "$upstream_dir" "$backup_upstream_dir"
fi

git clone --bare "$backup_upstream_dir" "$remote_dir" >/dev/null

UPSTREAM_URL="$remote_dir" scripts/fetch-upstream.sh
UPSTREAM_URL="$remote_dir" scripts/fetch-upstream.sh
UPSTREAM_URL="$remote_dir" scripts/verify-upstream.sh
scripts/materialize-upstream.sh
scripts/materialize-upstream.sh

test -f "$generated_dir/apps/api/Dockerfile"
test ! -e "$generated_dir/.git"
test "$(git -C "$upstream_dir" rev-parse HEAD)" = "$expected_commit"
test "$(git -C "$upstream_dir" rev-parse "refs/tags/${expected_version}^{commit}")" = "$expected_commit"

# Tracked changes outside the recorded checksums, plus untracked and ignored files,
# must not influence the archive-only build context.
printf 'checkout-only tracked change\n' >> "$upstream_dir/README.md"
printf 'untracked contamination\n' > "$upstream_dir/untracked-contamination"
mkdir "$upstream_dir/ignored-contamination"
printf '/ignored-contamination/\n' >> "$upstream_dir/.git/info/exclude"
printf 'ignored contamination\n' > "$upstream_dir/ignored-contamination/payload"
scripts/materialize-upstream.sh
test ! -e "$generated_dir/untracked-contamination"
test ! -e "$generated_dir/ignored-contamination"
test ! -e "$generated_dir/.git"
test "$(sha256sum "$generated_dir/README.md" | cut -d ' ' -f 1)" = "$(git -C "$upstream_dir" show "$expected_commit:README.md" | sha256sum | cut -d ' ' -f 1)"

# The verifier must reject a tampered checksummed input.
printf 'checksum tampering\n' >> "$upstream_dir/apps/api/Dockerfile"
require_failure env UPSTREAM_URL="$remote_dir" scripts/verify-upstream.sh
git -C "$upstream_dir" checkout -- apps/api/Dockerfile

# Exact tag-ref and detached-HEAD enforcement must remain fail-closed. Create a
# local alternate commit so this hermetic test does not require parent objects
# from the partial upstream clone.
git -C "$upstream_dir" -c user.name=test -c user.email=test@example.invalid commit --allow-empty -m test-alternate >/dev/null
alternate_commit="$(git -C "$upstream_dir" rev-parse HEAD)"
git -C "$upstream_dir" tag -f "$expected_version" "$alternate_commit"
require_failure env UPSTREAM_URL="$remote_dir" scripts/verify-upstream.sh
UPSTREAM_URL="$remote_dir" scripts/fetch-upstream.sh

git -C "$upstream_dir" checkout --detach "$alternate_commit" >/dev/null
require_failure env UPSTREAM_URL="$remote_dir" scripts/verify-upstream.sh
UPSTREAM_URL="$remote_dir" scripts/fetch-upstream.sh

# The accepted tag must remain a lightweight commit ref, not an annotated tag.
git -C "$upstream_dir" tag -d "$expected_version"
git -C "$upstream_dir" -c user.name=test -c user.email=test@example.invalid tag -a "$expected_version" -m test "$expected_commit"
require_failure env UPSTREAM_URL="$remote_dir" scripts/verify-upstream.sh
UPSTREAM_URL="$remote_dir" scripts/fetch-upstream.sh
UPSTREAM_URL="$remote_dir" scripts/verify-upstream.sh
scripts/materialize-upstream.sh

test ! -e "$generated_dir/.git"
test "$(git -C "$upstream_dir" rev-parse HEAD)" = "$expected_commit"

# Documented builds must source both Dockerfiles and contexts from the pristine
# materialization, never from the mutable vendor checkout.
if grep -F -- '--file vendor/firecrawl/' README.md; then
  printf 'README documents an unsafe vendor Dockerfile path\n' >&2
  exit 1
fi
grep -F -- '--file .generated/firecrawl/apps/api/Dockerfile .generated/firecrawl' README.md >/dev/null
grep -F -- '--file .generated/firecrawl/apps/playwright-service-ts/Dockerfile' README.md >/dev/null
