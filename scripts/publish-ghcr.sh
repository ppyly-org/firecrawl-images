#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s ARCHIVE REPOSITORY VERSION_TAG SHA_TAG SUBJECT_DIGEST\n' "$0" >&2
  exit 2
}

[[ $# -eq 5 ]] || usage
readonly archive="$1"
readonly repository="$2"
readonly version_tag="$3"
readonly sha_tag="$4"
readonly subject_digest="$5"
readonly retries="${GHCR_VISIBILITY_RETRIES:-12}"
readonly retry_delay="${GHCR_VISIBILITY_RETRY_DELAY:-5}"

[[ -f "$archive" ]] || { printf 'Image archive not found.\n' >&2; exit 1; }
[[ "$repository" =~ ^ghcr\.io/ppyly-org/(firecrawl-api|firecrawl-playwright|firecrawl-nuq-migration|pg-cron)$ ]] || usage
[[ "$version_tag" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+\.[0-9]+-[0-9]+)$ ]] || usage
[[ "$sha_tag" =~ ^sha-[0-9a-f]{7,64}$ ]] || usage
[[ "$subject_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || usage
[[ "$retries" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$retry_delay" =~ ^[0-9]+$ ]] || usage
: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"

readonly package_name="${repository##*/}"
readonly metadata_url="https://api.github.com/orgs/ppyly-org/packages/container/${package_name}"
response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT
metadata_status=''

query_visibility() {
  metadata_status="$(curl --silent --show-error \
    --output "$response_file" \
    --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "Authorization: Bearer ${GITHUB_TOKEN}" \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    "$metadata_url")"
}

# Images are deliberately public: the source is AGPL upstream plus this
# public builder repo, and nothing secret is baked in. A package that is
# not public is treated as config drift and fails the run — GitHub creates
# packages private-by-default and offers no API to change that, so the
# first-ever publish requires a one-time UI flip (Package settings ->
# Change visibility -> Public), then a rerun.
require_public_visibility() {
  local allow_authenticated_404="$1"
  query_visibility
  case "$metadata_status" in
    200)
      if ! jq -e '.visibility == "public"' "$response_file" >/dev/null; then
        printf 'Refusing publication: GHCR package is not public. One-time fix:\n' >&2
        printf 'Package settings -> Change visibility -> Public, then rerun.\n' >&2
        return 1
      fi
      ;;
    404)
      if [[ "$allow_authenticated_404" != true ]]; then
        printf 'Refusing publication: GHCR package metadata is missing after first creation.\n' >&2
        return 1
      fi
      printf 'Authenticated package lookup returned 404; allowing first creation (private-by-default).\n'
      ;;
    *)
      printf 'Refusing publication: GHCR package metadata returned HTTP %s.\n' "$metadata_status" >&2
      return 1
      ;;
  esac
}

wait_until_public() {
  local attempt
  for ((attempt = 1; attempt <= retries; attempt++)); do
    query_visibility
    case "$metadata_status" in
      200)
        if jq -e '.visibility == "public"' "$response_file" >/dev/null; then
          return 0
        fi
        printf 'Publication failed: GHCR package is not public (first creation is\n' >&2
        printf 'always private). One-time fix: Package settings -> Change visibility\n' >&2
        printf '-> Public, then rerun. The digest is pushed; only tagging is blocked.\n' >&2
        return 1
        ;;
      404)
        if (( attempt < retries )); then
          sleep "$retry_delay"
          continue
        fi
        ;;
      *)
        printf 'Publication failed: GHCR package metadata returned HTTP %s.\n' "$metadata_status" >&2
        return 1
        ;;
    esac
  done
  printf 'Publication failed: GHCR package metadata never became accessible.\n' >&2
  return 1
}

# A 404 is accepted only here, before the one operation that may create a package.
require_public_visibility true
pushed_reference="$(crane push "$archive" "${repository}:${sha_tag}")"
[[ "$pushed_reference" == "${repository}@sha256:"* ]]
pushed_digest="${pushed_reference#*@}"
[[ "$pushed_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
if [[ "$pushed_digest" != "$subject_digest" ]]; then
  printf 'Publication failed: pushed digest does not match verified local OCI subject.\n' >&2
  exit 1
fi

# Creation must resolve to public before adding any second tag.
wait_until_public
require_public_visibility false
crane tag "${repository}@${subject_digest}" "$version_tag"

# Publication is successful only after an authenticated public-visibility check.
require_public_visibility false
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'digest=%s\n' "$subject_digest" >> "$GITHUB_OUTPUT"
fi
printf 'Published verified public image %s@%s\n' "$repository" "$subject_digest"
