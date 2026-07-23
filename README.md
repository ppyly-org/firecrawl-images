# Firecrawl image sources

This repository pins the source used to build private Firecrawl images. The pin is deliberately split into `UPSTREAM_VERSION` (`v2.11.0`) and `UPSTREAM_COMMIT` (`ef12eb36b2f3382838dfe0a0c1a5add3d5df7fe5`). `vendor/firecrawl` is a detached, ignored checkout used only to fetch and verify the pinned object; it is never a Docker build context or committed source.

## Provenance verification

Run the following from this repository:

```bash
scripts/fetch-upstream.sh
scripts/verify-upstream.sh
scripts/materialize-upstream.sh
bash tests/test_upstream_pin.sh
```

The fetch script verifies that `refs/tags/v2.11.0^{commit}` and the detached checkout both equal the recorded 40-character commit. The verification script checks the required source files and their SHA-256 checksums:

- `apps/api/Dockerfile`
- `apps/playwright-service-ts/Dockerfile`
- `apps/nuq-postgres/Dockerfile`
- `apps/nuq-postgres/nuq.sql`

### Lightweight-tag caveat

Upstream `v2.11.0` is an unsigned lightweight tag: its GitHub tag ref is a `commit`, rather than a signed annotated tag. The exact SHA pin makes the local checkout reproducible and prevents a moved tag from changing it, but it is not cryptographic release verification. Fetch and verification explicitly require the local tag object to be a commit and require its peeled commit and `HEAD` to equal `UPSTREAM_COMMIT`.

## Build contexts for future image work

First materialize the verified exact commit into the repository-scoped generated directory. `git archive` is the sole source of this context, so it contains neither `.git` nor tracked, ignored, or untracked checkout contamination. Do not build from `vendor/firecrawl`.

```bash
scripts/materialize-upstream.sh
```

The API/harness Dockerfile must use the generated Firecrawl repository root as its context because it copies root workspace files and `sharedLibs/go-html-to-md`:

```bash
docker build --file .generated/firecrawl/apps/api/Dockerfile .generated/firecrawl
```

The Playwright service Dockerfile is self-contained and must use its service directory as its context:

```bash
docker build --file .generated/firecrawl/apps/playwright-service-ts/Dockerfile \
  .generated/firecrawl/apps/playwright-service-ts
```

## Migration-image decision: gated

No `Dockerfile.migration` or derived migration SQL is intentionally present. Raw upstream `apps/nuq-postgres/nuq.sql` is initdb/bootstrap SQL for upstream PostgreSQL 17, not a repeatable migration for shared CNPG PostgreSQL 18. It contains cluster-wide `ALTER SYSTEM` settings and unguarded `cron.schedule(...)` calls that duplicate jobs on reapply. A reviewed amendment must first define and test: accepted cluster-wide settings, privileged extension setup after `pg_cron` preload verification, and an idempotent separately named derived migration payload with an auditable diff/checksum. Until then, preserve and checksum the raw upstream SQL only; do not execute it as a shared-CNPG migration.
