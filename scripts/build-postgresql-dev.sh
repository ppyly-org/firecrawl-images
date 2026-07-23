#!/usr/bin/env bash
# Build the PostgreSQL 18.4 development toolchain without networked RUN steps.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
logical_cache="$repo_root/.cache/builder-debs"
tag="${1:-local/firecrawl-postgresql-18.4-dev:verify}"
builder="firecrawl-postgresql-dev-$(openssl rand -hex 12)"
buildkit_image="moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
cleanup_done=false
ownership_dir=
ownership_marker=

case "$tag" in
  -*|*[$'\t\r\n ']*|'') printf 'invalid image tag: %q\n' "$tag" >&2; exit 2 ;;
esac

export DOCKER_CONFIG="${DOCKER_CONFIG:-$repo_root/.cache/docker-config}"
mkdir -p "$DOCKER_CONFIG"

# The verifier parent holds a shared cache lock (flock -s semantics) for this
# entire invocation, including verification and BuildKit context snapshot/use.
if [[ "${BUILDER_CACHE_LOCK_HELD:-}" != 1 ]]; then
  exec python3 "$repo_root/scripts/verify_builder_lock.py" with-cache-lock \
    --lock "$repo_root/sources/postgresql-18.4-dev.lock" --cache "$logical_cache" -- "$0" "$@"
fi
cache="${BUILDER_CACHE_GENERATION:?shared cache bridge did not provide a physical generation}"
ownership_dir="$(mktemp -d "$DOCKER_CONFIG/.builder-ownership.XXXXXXXX")"
chmod 700 "$ownership_dir"
ownership_marker="$ownership_dir/owned"

cleanup() {
  if "$cleanup_done"; then return; fi
  cleanup_done=true
  if [[ -f "$ownership_marker" && ! -L "$ownership_marker" && "$(<"$ownership_marker")" == "$builder" ]]; then
    docker buildx rm -f "$builder" >/dev/null 2>&1 || true
  fi
  [[ -n "$ownership_dir" ]] && rm -rf -- "$ownership_dir"
}
on_signal() {
  trap - EXIT HUP INT TERM
  cleanup
  case "$1" in
    129) exit 129 ;;
    130) exit 130 ;;
    143) exit 143 ;;
    *) exit 1 ;;
  esac
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

"$repo_root/scripts/fetch-builder-debs.sh" --cache "$logical_cache" --offline

# Keep create and ownership-marker publication in one foreground compound
# command. Bash defers parent signal traps until this finishes. Ignore terminal
# cancellation in this short-lived subshell so process-group delivery cannot
# terminate either it or create/mv before the durable marker is published.
(
  trap '' HUP INT TERM
  set -e
  docker buildx create \
    --name "$builder" \
    --driver docker-container \
    --driver-opt "image=$buildkit_image" \
    --use >/dev/null
  umask 077
  printf '%s\n' "$builder" > "$ownership_marker.partial"
  mv -T -- "$ownership_marker.partial" "$ownership_marker"
)
docker buildx inspect --bootstrap "$builder" >/dev/null

no_cache=()
if [[ "${NO_CACHE:-false}" == true ]]; then
  no_cache+=(--no-cache)
elif [[ "${NO_CACHE:-false}" != false ]]; then
  printf 'NO_CACHE must be true or false\n' >&2
  exit 2
fi

docker buildx build \
  --builder "$builder" \
  "${no_cache[@]}" \
  --network=none \
  --pull=false \
  --platform linux/amd64 \
  --build-context builder-debs="$cache" \
  --file "$repo_root/Dockerfile.postgresql-18.4-dev" \
  --tag "$tag" \
  --load \
  "$repo_root"

docker image inspect "$tag" --format 'id={{.Id}} os={{.Os}} arch={{.Architecture}} size={{.Size}}'
