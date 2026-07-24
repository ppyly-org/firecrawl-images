#!/usr/bin/env python3
"""Parsed security contract for the Firecrawl image workflows."""

from pathlib import Path
import json
import os
import re
import shlex
import subprocess
import tempfile
import textwrap
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
BUILD_WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
RENOVATE_WORKFLOW = ROOT / ".github" / "workflows" / "renovate.yml"
RENOVATE_CONFIG = ROOT / "renovate.json"
PRIVATE_PUBLISHER = ROOT / "scripts" / "publish-private-ghcr.sh"


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


def action_steps(job, action):
    return [step for step in job.get("steps", []) if step.get("uses", "").split("@")[0] == action]


def step_by_id(job, step_id):
    matches = [step for step in job.get("steps", []) if step.get("id") == step_id]
    if len(matches) != 1:
        raise AssertionError(f"expected one step id {step_id!r}, got {len(matches)}")
    return matches[0]


def step_index(job, step_id):
    ids = [step.get("id") for step in job.get("steps", [])]
    if step_id not in ids:
        raise AssertionError(f"missing step id {step_id!r}; got {ids!r}")
    return ids.index(step_id)


def assert_protected_only(testcase, step):
    condition = re.sub(r"\s+", " ", str(step.get("if", "")).strip())
    testcase.assertIn("github.ref_protected == true", condition)
    testcase.assertNotIn("||", condition)
    testcase.assertNotIn("github.ref_type", condition)


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

    def test_required_actions_use_exact_approved_major_refs(self):
        expected = {
            "actions/checkout": "actions/checkout@v4",
            "docker/setup-buildx-action": "docker/setup-buildx-action@v3",
            "docker/login-action": "docker/login-action@v3",
            "docker/build-push-action": "docker/build-push-action@v6",
            "actions/attest-build-provenance": "actions/attest-build-provenance@v2",
        }
        for job_name in ("api", "playwright"):
            job = self.jobs[job_name]
            for action, exact_ref in expected.items():
                steps = action_steps(job, action)
                self.assertGreaterEqual(len(steps), 1, f"{job_name}: missing {action}")
                self.assertTrue(
                    all(step["uses"] == exact_ref for step in steps),
                    f"{job_name}: {action} must use exactly {exact_ref}",
                )
        all_uses = [
            step["uses"]
            for job in self.jobs.values()
            for step in job.get("steps", [])
            if "uses" in step
        ]
        self.assertFalse(any(re.search(r"@(main|master|latest)(?:$|\b)", use) for use in all_uses))

    def test_api_and_playwright_use_only_exact_commit_archives(self):
        expected = {
            "api": (".generated/firecrawl", ".generated/firecrawl/apps/api/Dockerfile"),
            "playwright": (
                ".generated/firecrawl/apps/playwright-service-ts",
                ".generated/firecrawl/apps/playwright-service-ts/Dockerfile",
            ),
        }
        for job_name, (context, dockerfile) in expected.items():
            job = self.jobs[job_name]
            materialize = step_by_id(job, "materialize")
            run = materialize["run"]
            self.assertIn("scripts/materialize-upstream.sh", run)
            self.assertIn("cat-file -e", run)
            self.assertIn("test ! -e .generated/firecrawl/.git", run)
            builds = action_steps(job, "docker/build-push-action")
            self.assertEqual(len(builds), 1)
            self.assertEqual(builds[0]["with"]["context"], context)
            self.assertEqual(builds[0]["with"]["file"], dockerfile)
            self.assertNotIn("vendor/firecrawl", str(builds[0]["with"]))

    def test_real_pre_push_attestation_is_bound_to_local_publishable_digest(self):
        for job_name in ("api", "playwright"):
            job = self.jobs[job_name]
            subject = step_by_id(job, "subject")
            subject_run = subject["run"]
            self.assertRegex(subject_run, r"docker save .* --output \S+\.tar")
            self.assertRegex(subject_run, r"crane digest --tarball \S+\.tar")
            self.assertRegex(subject_run, r"\^sha256:\[0-9a-f\]\{64\}\$")
            self.assertIn('echo "digest=$digest"', subject_run)
            self.assertIn('>> "$GITHUB_OUTPUT"', subject_run)

            attest = step_by_id(job, "prepush_attestation")
            self.assertEqual(attest["uses"], "actions/attest-build-provenance@v2")
            self.assertEqual(attest["with"]["subject-digest"], "${{ steps.subject.outputs.digest }}")
            self.assertFalse(attest["with"]["push-to-registry"])
            assert_protected_only(self, attest)

            verify = step_by_id(job, "verify_prepush_attestation")
            verify_run = verify["run"]
            self.assertIn("gh attestation verify", verify_run)
            self.assertIn("${{ steps.prepush_attestation.outputs.bundle-path }}", verify_run)
            self.assertIn("${{ steps.subject.outputs.digest }}", verify_run)
            assert_protected_only(self, verify)

    def test_exact_security_and_publication_order(self):
        required_order = [
            "build",
            "trivy",
            "sbom",
            "subject",
            "prepush_attestation",
            "verify_prepush_attestation",
            "smoke",
            "login",
            "push",
            "postpush_attestation",
        ]
        for job_name in ("api", "playwright"):
            job = self.jobs[job_name]
            indices = [step_index(job, step_id) for step_id in required_order]
            self.assertEqual(indices, sorted(indices), f"{job_name}: unsafe step order")
            for step_id in ("prepush_attestation", "verify_prepush_attestation", "login", "push", "postpush_attestation"):
                assert_protected_only(self, step_by_id(job, step_id))

    def test_every_existing_registry_publication_path_is_protected_only(self):
        for job_name in ("api", "playwright"):
            job = self.jobs[job_name]
            login_steps = action_steps(job, "docker/login-action")
            self.assertEqual(len(login_steps), 1)
            assert_protected_only(self, login_steps[0])
            assert_protected_only(self, step_by_id(job, "push"))
            for attest in action_steps(job, "actions/attest-build-provenance"):
                assert_protected_only(self, attest)

    def test_push_uses_verified_local_archive_and_checks_digest(self):
        for job_name in ("api", "playwright"):
            push = step_by_id(self.jobs[job_name], "push")
            self.assertEqual(shlex.split(push["run"]), [
                "scripts/publish-private-ghcr.sh",
                "${{ steps.subject.outputs.archive }}",
                "${{ env.API_REPOSITORY }}" if job_name == "api" else "${{ env.PLAYWRIGHT_REPOSITORY }}",
                "${{ steps.meta.outputs.version }}",
                "sha-${GITHUB_SHA}",
                "${{ steps.subject.outputs.digest }}",
            ])

    def test_migration_certification_is_blocked_and_has_no_build_publish_semantics(self):
        migration = self.jobs["migration-certification"]
        condition = migration["if"]
        self.assertIn("false", condition)
        self.assertIn("task8_evidence", condition)
        self.assertIn("pg_cron_digest", condition)
        self.assertEqual(migration.get("needs", []), [])
        self.assertNotIn("container", migration)
        self.assertNotIn("services", migration)
        for job_name in ("api", "playwright"):
            self.assertNotIn("migration-certification", self.jobs[job_name].get("needs", []))
        migration_steps = migration.get("steps", [])
        self.assertFalse(any("docker/" in step.get("uses", "") for step in migration_steps))
        command_pattern = re.compile(
            r"(?:docker|podman|buildah|crane|oras)\s+(?:build|push|tag|copy)|"
            r"(?:build|push|publish).*(?:pg[_-]?cron|migration)|"
            r"(?:pg[_-]?cron|migration).*(?:build|push|publish)",
            re.IGNORECASE | re.DOTALL,
        )
        for step in migration_steps:
            self.assertNotRegex(str(step.get("run", "")), command_pattern)
            self.assertNotRegex(str(step.get("with", "")), command_pattern)


class PrivateGhcrPublisherContractTests(unittest.TestCase):
    def test_visibility_gate_commands_fail_closed_and_never_echo_token(self):
        self.assertTrue(PRIVATE_PUBLISHER.is_file(), "private GHCR publisher script is missing")
        script = PRIVATE_PUBLISHER.read_text(encoding="utf-8")
        self.assertIn("api.github.com/orgs/ppyly-org/packages/container/", script)
        self.assertIn("Authorization: Bearer ${GITHUB_TOKEN}", script)
        self.assertIn("X-GitHub-Api-Version: 2022-11-28", script)
        self.assertRegex(script, r"jq\s+-e\s+['\"]\.visibility == ['\"]private['\"]")
        self.assertRegex(script, r"case\s+.*status.*\s+in")
        self.assertRegex(script, r"200\)")
        self.assertRegex(script, r"404\)")
        self.assertRegex(script, r"\*\)")
        self.assertIn("crane push", script)
        self.assertIn("crane tag", script)
        self.assertNotRegex(script, r"set\s+-[^\n]*x")
        self.assertNotRegex(script, r"echo[^\n]*(?:GITHUB_TOKEN|github_token)")

    def test_visibility_behavior_rejects_public_and_non_404_errors_before_push(self):
        for response in ("200:public", "403:private", "500:private"):
            with self.subTest(response=response):
                result, crane_log = self._run_publisher([response])
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("push", crane_log)
                self.assertNotIn("test-secret-value", result.stdout + result.stderr)

    def test_authenticated_404_allows_first_push_then_requires_private(self):
        result, crane_log = self._run_publisher(
            ["404:missing", "200:private", "200:private", "200:private"]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = crane_log.splitlines()
        self.assertEqual(lines[0].split()[0], "push")
        self.assertEqual(Path(lines[0].split()[1]).name, "image.tar")
        self.assertEqual(lines[1].split()[0], "tag")
        self.assertNotIn("test-secret-value", result.stdout + result.stderr)

    def test_after_push_public_visibility_fails_before_version_tag(self):
        result, crane_log = self._run_publisher(["404:missing", "200:public"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([line.split()[0] for line in crane_log.splitlines()], ["push"])

    def _run_publisher(self, responses):
        if not PRIVATE_PUBLISHER.is_file():
            raise AssertionError("private GHCR publisher script is missing")
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            state = temp / "curl-state"
            state.write_text("0", encoding="utf-8")
            response_file = temp / "responses"
            response_file.write_text("\n".join(responses), encoding="utf-8")
            crane_log = temp / "crane.log"
            self._write_executable(
                fake_bin / "curl",
                """#!/usr/bin/env bash
set -euo pipefail
output=''
while (( $# )); do
  if [[ $1 == --output ]]; then output=$2; shift 2; else shift; fi
done
index=$(<"$MOCK_STATE")
response=$(sed -n "$((index + 1))p" "$MOCK_RESPONSES")
echo $((index + 1)) > "$MOCK_STATE"
status=${response%%:*}; visibility=${response#*:}
printf '{"visibility":"%s"}\n' "$visibility" > "$output"
printf '%s' "$status"
""",
            )
            self._write_executable(
                fake_bin / "crane",
                """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_CRANE_LOG"
case $1 in
  push) printf 'ghcr.io/ppyly-org/firecrawl-api@sha256:%064d\n' 0 ;;
  tag) ;;
  *) exit 2 ;;
esac
""",
            )
            archive = temp / "image.tar"
            archive.touch()
            env = os.environ | {
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "GITHUB_TOKEN": "test-secret-value",
                "MOCK_STATE": str(state),
                "MOCK_RESPONSES": str(response_file),
                "MOCK_CRANE_LOG": str(crane_log),
                "GHCR_VISIBILITY_RETRIES": "1",
                "GHCR_VISIBILITY_RETRY_DELAY": "0",
            }
            result = subprocess.run(
                [
                    str(PRIVATE_PUBLISHER),
                    str(archive),
                    "ghcr.io/ppyly-org/firecrawl-api",
                    "v1.2.3",
                    "sha-deadbeef",
                    "sha256:" + "0" * 64,
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            return result, crane_log.read_text(encoding="utf-8") if crane_log.exists() else ""

    @staticmethod
    def _write_executable(path, content):
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        path.chmod(0o755)


class RenovateContractTests(unittest.TestCase):
    def test_only_custom_regex_manager_can_touch_exact_upstream_version_file(self):
        config = json.loads(RENOVATE_CONFIG.read_text(encoding="utf-8"))
        self.assertNotIn("extends", config)
        self.assertEqual(config.get("enabledManagers"), ["custom.regex"])
        self.assertEqual(config.get("includePaths"), ["UPSTREAM_VERSION"])
        self.assertFalse(config.get("automerge", True))
        self.assertTrue(config.get("dependencyDashboard"))
        managers = config.get("customManagers", [])
        self.assertEqual(len(managers), 1)
        manager = managers[0]
        self.assertEqual(manager.get("customType"), "regex")
        self.assertEqual(manager.get("managerFilePatterns"), ["/^UPSTREAM_VERSION$/"])
        self.assertEqual(manager.get("depNameTemplate"), "firecrawl/firecrawl")
        self.assertEqual(manager.get("datasourceTemplate"), "github-releases")
        rules = config.get("packageRules", [])
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].get("matchManagers"), ["custom.regex"])
        self.assertEqual(rules[0].get("matchFileNames"), ["UPSTREAM_VERSION"])
        self.assertEqual(rules[0].get("matchDepNames"), ["firecrawl/firecrawl"])
        self.assertFalse(rules[0].get("automerge", True))

    def test_renovate_workflow_keeps_pr_capable_external_token(self):
        workflow = load_yaml(RENOVATE_WORKFLOW)
        self.assertEqual(workflow.get("permissions"), {"contents": "read"})
        steps = workflow["jobs"]["renovate"]["steps"]
        renovate = [step for step in steps if step.get("uses", "").split("@")[0] == "renovatebot/github-action"]
        self.assertEqual(len(renovate), 1)
        self.assertEqual(renovate[0]["uses"], "renovatebot/github-action@v43.0.10")
        self.assertEqual(renovate[0]["with"]["token"], "${{ secrets.RENOVATE_TOKEN }}")


if __name__ == "__main__":
    unittest.main()
