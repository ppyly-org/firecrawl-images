#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly upstream_url="https://github.com/firecrawl/firecrawl.git"
readonly upstream_dir="$repo_root/vendor/firecrawl"
readonly version="$(tr -d '\n' < "$repo_root/UPSTREAM_VERSION")"
readonly expected_commit="$(tr -d '\n' < "$repo_root/UPSTREAM_COMMIT")"

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]]

if [[ -e "$upstream_dir" && ! -d "$upstream_dir/.git" ]]; then
  printf 'Refusing to replace non-Git path: %s\n' "$upstream_dir" >&2
  exit 1
fi

if [[ ! -d "$upstream_dir/.git" ]]; then
  mkdir -p "$(dirname "$upstream_dir")"
  git clone --no-checkout --filter=blob:none "$upstream_url" "$upstream_dir"
fi

actual_remote_url="$(git -C "$upstream_dir" remote get-url origin)"
test "$actual_remote_url" = "$upstream_url"

git -C "$upstream_dir" fetch --force origin "refs/tags/$version:refs/tags/$version"
actual_tag="$(git -C "$upstream_dir" rev-parse "refs/tags/${version}^{commit}")"
test "$actual_tag" = "$expected_commit"

# v2.11.0 is an unsigned lightweight tag. A full SHA pin prevents tag movement
# from changing the checkout, but does not provide cryptographic release proof.
tag_type="$(git -C "$upstream_dir" cat-file -t "refs/tags/$version")"
test "$tag_type" = "commit"

git -C "$upstream_dir" fetch --force origin "$expected_commit"
git -C "$upstream_dir" checkout --detach --force "$expected_commit"
actual_head="$(git -C "$upstream_dir" rev-parse HEAD)"
test "$actual_head" = "$expected_commit"

printf 'Fetched Firecrawl %s at detached %s (unsigned lightweight tag).\n' "$version" "$actual_head"
