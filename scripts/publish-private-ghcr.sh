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
[[ "$repository" =~ ^ghcr\.io/ppyly-org/(firecrawl-api|firecrawl-playwright)$ ]] || usage
[[ "$version_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
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

require_private_visibility() {
  local allow_authenticated_404="$1"
  query_visibility
  case "$metadata_status" in
    200)
      if ! jq -e '.visibility == "private"' "$response_file" >/dev/null; then
        printf 'Refusing publication: existing GHCR package is not private.\n' >&2
        return 1
      fi
      ;;
    404)
      if [[ "$allow_authenticated_404" != true ]]; then
        printf 'Refusing publication: GHCR package metadata is missing after first creation.\n' >&2
        return 1
      fi
      printf 'Authenticated package lookup returned 404; allowing private-by-default first creation.\n'
      ;;
    *)
      printf 'Refusing publication: GHCR package metadata returned HTTP %s.\n' "$metadata_status" >&2
      return 1
      ;;
  esac
}

wait_until_private() {
  local attempt
  for ((attempt = 1; attempt <= retries; attempt++)); do
    query_visibility
    case "$metadata_status" in
      200)
        if jq -e '.visibility == "private"' "$response_file" >/dev/null; then
          return 0
        fi
        printf 'Publication failed: created GHCR package is not private.\n' >&2
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
  printf 'Publication failed: private GHCR metadata never became accessible.\n' >&2
  return 1
}

# A 404 is accepted only here, before the one operation that may create a package.
require_private_visibility true
pushed_reference="$(crane push "$archive" "${repository}:${sha_tag}")"
[[ "$pushed_reference" == "${repository}@sha256:"* ]]
pushed_digest="${pushed_reference#*@}"
[[ "$pushed_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
if [[ "$pushed_digest" != "$subject_digest" ]]; then
  printf 'Publication failed: pushed digest does not match verified local OCI subject.\n' >&2
  exit 1
fi

# Creation must resolve to private before adding any second tag.
wait_until_private
require_private_visibility false
crane tag "${repository}@${subject_digest}" "$version_tag"

# Publication is successful only after an authenticated private-visibility check.
require_private_visibility false
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'digest=%s\n' "$subject_digest" >> "$GITHUB_OUTPUT"
fi
printf 'Published verified private image %s@%s\n' "$repository" "$subject_digest"
