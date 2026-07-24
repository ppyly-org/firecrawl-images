#!/usr/bin/env python3
"""Static security contract for the Firecrawl image workflows."""

from pathlib import Path
import json
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
BUILD_WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
RENOVATE_WORKFLOW = ROOT / ".github" / "workflows" / "renovate.yml"
RENOVATE_CONFIG = ROOT / "renovate.json"
PIN = (ROOT / "UPSTREAM_COMMIT").read_text(encoding="utf-8").strip()


class GitHubLoader(yaml.SafeLoader):
    """Read GitHub's YAML 1.2-like syntax without treating ``on`` as bool."""


for first, resolvers in list(GitHubLoader.yaml_implicit_resolvers.items()):
    GitHubLoader.yaml_implicit_resolvers[first] = [
        resolver
        for resolver in resolvers
        if resolver[0] != "tag:yaml.org,2002:bool"
    ]
GitHubLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as stream:
        return yaml.load(stream, Loader=GitHubLoader)


def step_text(job):
    return "\n".join(
        "\n".join(str(step.get(key, "")) for key in ("name", "uses", "run", "with", "if"))
        for step in job.get("steps", [])
    )


def step_index(job, name_fragment):
    names = [str(step.get("name", "")).lower() for step in job.get("steps", [])]
    matches = [index for index, name in enumerate(names) if name_fragment.lower() in name]
    if not matches:
        raise AssertionError(f"missing step containing {name_fragment!r}; got {names!r}")
    return matches[0]


class BuildWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = load_yaml(BUILD_WORKFLOW)
        cls.jobs = cls.workflow["jobs"]

    def test_top_level_and_publish_permissions_are_least_privilege(self):
        self.assertEqual(self.workflow.get("permissions"), {"contents": "read"})
        expected = {
            "contents": "read",
            "packages": "write",
            "id-token": "write",
            "attestations": "write",
        }
        for job_name in ("api", "playwright"):
            self.assertEqual(self.jobs[job_name].get("permissions"), expected)
        self.assertEqual(
            self.jobs["migration-certification"].get("permissions"),
            {"contents": "read"},
        )

    def test_actions_use_approved_pinned_major_versions(self):
        text = BUILD_WORKFLOW.read_text(encoding="utf-8")
        for action in (
            "actions/checkout@v4",
            "docker/setup-buildx-action@v3",
            "docker/login-action@v3",
            "docker/build-push-action@v6",
        ):
            self.assertIn(action, text)
        self.assertNotRegex(text, r"uses:\s+[^\s]+@(main|master|latest)\b")

    def test_api_and_playwright_use_only_exact_commit_archives(self):
        expected = {
            "api": (
                ".generated/firecrawl",
                ".generated/firecrawl/apps/api/Dockerfile",
            ),
            "playwright": (
                ".generated/firecrawl/apps/playwright-service-ts",
                ".generated/firecrawl/apps/playwright-service-ts/Dockerfile",
            ),
        }
        for job_name, (context, dockerfile) in expected.items():
            job = self.jobs[job_name]
            text = step_text(job)
            self.assertIn("scripts/materialize-upstream.sh", text)
            self.assertIn("git archive", text)
            self.assertIn("UPSTREAM_COMMIT", text)
            self.assertIn("cat-file -e", text)
            self.assertIn("test ! -e .generated/firecrawl/.git", text)
            builds = [
                step
                for step in job["steps"]
                if str(step.get("uses", "")).startswith("docker/build-push-action@")
            ]
            self.assertEqual(len(builds), 1)
            self.assertEqual(builds[0]["with"]["context"], context)
            self.assertEqual(builds[0]["with"]["file"], dockerfile)
            self.assertNotIn("vendor/firecrawl", str(builds[0]["with"]))
            self.assertNotIn("context: vendor/firecrawl", text)
            self.assertNotIn("file: vendor/firecrawl", text)

    def test_security_artifacts_and_smoke_all_precede_push(self):
        for job_name in ("api", "playwright"):
            job = self.jobs[job_name]
            push = step_index(job, "push immutable")
            for prerequisite in (
                "repository tests",
                "trivy",
                "sbom",
                "provenance",
                "smoke",
            ):
                self.assertLess(step_index(job, prerequisite), push)
            push_step = job["steps"][push]
            self.assertIn("github.ref_protected", push_step["if"])
            self.assertIn("github.ref_type == 'tag'", push_step["if"])

    def test_private_repositories_tags_and_digest_outputs_are_explicit(self):
        expected_repositories = {
            "api": "ghcr.io/ppyly-org/firecrawl-api",
            "playwright": "ghcr.io/ppyly-org/firecrawl-playwright",
        }
        for job_name, repository in expected_repositories.items():
            job = self.jobs[job_name]
            self.assertEqual(job["outputs"]["digest"], "${{ steps.push.outputs.digest }}")
            text = step_text(job)
            self.assertIn(repository, text)
            self.assertIn(":${version}", text)
            self.assertIn(":sha-${GITHUB_SHA}", text)
            self.assertIn("sha256:", text)
            self.assertIn("private GHCR", text)

    def test_migration_certification_is_separate_blocked_and_non_blocking(self):
        migration = self.jobs["migration-certification"]
        condition = migration["if"]
        self.assertIn("false", condition)
        self.assertIn("task8_evidence", condition)
        self.assertIn("pg_cron_digest", condition)
        self.assertNotIn("api", migration.get("needs", []))
        self.assertNotIn("playwright", migration.get("needs", []))
        for job_name in ("api", "playwright"):
            self.assertNotIn("migration-certification", self.jobs[job_name].get("needs", []))
        self.assertNotIn("Dockerfile.migration", step_text(migration))
        self.assertNotIn("docker push", step_text(migration))


class RenovateContractTests(unittest.TestCase):
    def test_renovate_updates_only_upstream_version_by_pr(self):
        config = json.loads(RENOVATE_CONFIG.read_text(encoding="utf-8"))
        managers = config.get("customManagers", [])
        self.assertEqual(len(managers), 1)
        manager = managers[0]
        self.assertEqual(manager["managerFilePatterns"], ["/^UPSTREAM_VERSION$/"])
        self.assertIn("firecrawl/firecrawl", " ".join(manager["matchStrings"]))
        self.assertEqual(manager["datasourceTemplate"], "github-releases")
        self.assertFalse(config.get("automerge", True))
        self.assertIn("deployment/**", config.get("ignorePaths", []))

    def test_renovate_workflow_is_read_only_except_external_pat(self):
        workflow = load_yaml(RENOVATE_WORKFLOW)
        self.assertEqual(workflow.get("permissions"), {"contents": "read"})
        text = RENOVATE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("renovatebot/github-action@", text)
        self.assertIn("secrets.RENOVATE_TOKEN", text)
        self.assertNotRegex(text, r"@(main|master|latest)\b")


if __name__ == "__main__":
    unittest.main()
