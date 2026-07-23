#!/usr/bin/env python3
"""Hermetic PostgreSQL 18.4 development-toolchain contract tests."""
import bz2
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "sources" / "postgresql-18.4-dev.lock"
FETCH = ROOT / "scripts" / "fetch-builder-debs.sh"
VERIFY = ROOT / "scripts" / "verify_builder_lock.py"
BUILD = ROOT / "scripts" / "build-postgresql-dev.sh"
DOCKERFILE = ROOT / "Dockerfile.postgresql-18.4-dev"
OPERAND = "ghcr.io/cloudnative-pg/postgresql@sha256:8ff3abd13383e619797f974b4fcdda6de0c2cfdad90eb47e1cd95d41fe26bf80"
PG_VERSION = "18.4-1.pgdg11+1"


def verifier_module():
    spec = importlib.util.spec_from_file_location("verify_builder_lock", VERIFY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load_lock(path=LOCK):
    return json.loads(path.read_text(encoding="utf-8"))


def write_lock(path, lock):
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class LockContractTests(unittest.TestCase):
    def test_lock_has_v2_exact_production_identity_and_71_package_projection(self):
        lock = load_lock()
        self.assertEqual(lock["schema_version"], 2)
        self.assertEqual(lock["platform"], "linux/amd64")
        self.assertEqual(lock["operand"], {
            "reference": OPERAND, "postgresql_version": "18.4",
            "debian_package_version": PG_VERSION, "distribution": "debian",
            "suite": "bullseye", "libc6_version": "2.31-13+deb11u13",
        })
        self.assertEqual(lock["repositories"]["pgdg_archive"]["suite"], "bullseye-pgdg-archive")
        self.assertEqual(lock["repositories"]["pgdg_archive"]["signing_fingerprints"], ["B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"])
        self.assertEqual(lock["repositories"]["pgdg_archive"]["index_policy"], "mutable-signed-index-exact-selected-records-v1")
        self.assertNotIn("inrelease_sha256", lock["repositories"]["pgdg_archive"])
        self.assertEqual(set(lock["repositories"]["pgdg_archive"]["index"]), {"path", "file", "selected_stanzas_sha256"})
        self.assertEqual(set(lock["repositories"]["pgdg_archive"]["sources"]), {"path", "file", "selected_stanzas_sha256"})
        for name in ("dsc", "orig_tar_bz2", "debian_tar_xz"):
            self.assertIs(type(lock["postgresql_source"][name]["size"]), int)
        self.assertEqual(len(lock["packages"]), 71)
        expected = sorted(f"{p['name']}\t{p['version']}\t{p['architecture']}" for p in lock["packages"])
        self.assertEqual(lock["newly_installed_manifest"], expected)

    def test_verifier_rejects_each_immutable_lock_drift_and_manifest_weakening(self):
        cases = []
        for path, value in [
            (("repositories", "debian_snapshot", "timestamp"), "20200101T000000Z"),
            (("repositories", "debian_snapshot", "url"), "https://example.invalid/archive"),
            (("postgresql_source", "orig_tar_bz2", "sha256"), "0" * 64),
            (("packages", 0, "source_package"), "wrong-source"),
            (("packages", 0, "source_version"), "0"),
        ]:
            mutated = copy.deepcopy(load_lock())
            target = mutated
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            cases.append(mutated)
        removed = load_lock(); removed["packages"].pop(); cases.append(removed)
        added = load_lock(); added["packages"].append(copy.deepcopy(added["packages"][0])); cases.append(added)
        reordered = load_lock(); reordered["packages"].reverse(); cases.append(reordered)
        weak = load_lock(); weak["newly_installed_manifest"] = weak["newly_installed_manifest"][:-1]; cases.append(weak)
        with tempfile.TemporaryDirectory() as temporary:
            for number, mutated in enumerate(cases):
                path = Path(temporary) / f"mutated-{number}.json"
                write_lock(path, mutated)
                result = subprocess.run(["python3", str(VERIFY), "validate-lock", "--lock", str(path)], text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


class VerifierCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._signing_root = tempfile.TemporaryDirectory()
        cls.gnupg = Path(cls._signing_root.name) / "gnupg"
        cls.gnupg.mkdir(mode=0o700)
        cls.signers = []
        for identity in ("Allowed Fixture Signer", "Wrong Fixture Signer"):
            subprocess.run([
                "gpg", "--batch", "--homedir", str(cls.gnupg), "--passphrase", "",
                "--quick-gen-key", identity, "rsa2048", "sign", "0",
            ], check=True, capture_output=True, text=True)
            listing = subprocess.run([
                "gpg", "--batch", "--homedir", str(cls.gnupg), "--with-colons", "--list-keys", identity,
            ], check=True, capture_output=True, text=True).stdout
            cls.signers.append(next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")))

    @classmethod
    def tearDownClass(cls):
        cls._signing_root.cleanup()

    def _signed_pgdg_fixture(self, root, package_records, source_records, signer=0):
        metadata = root / "pgdg"; metadata.mkdir(parents=True)
        packages = "\n\n".join(package_records) + "\n"
        sources = "\n\n".join(source_records) + "\n"
        (metadata / "Packages.bz2").write_bytes(bz2.compress(packages.encode()))
        (metadata / "Sources.bz2").write_bytes(bz2.compress(sources.encode()))
        release = ["Origin: signed fixture", "SHA256:"]
        for path, filename in (("main/binary-amd64/Packages.bz2", "Packages.bz2"), ("main/source/Sources.bz2", "Sources.bz2")):
            artifact = metadata / filename
            release.append(f" {hashlib.sha256(artifact.read_bytes()).hexdigest()} {artifact.stat().st_size} {path}")
        unsigned = root / "Release"
        unsigned.write_text("\n".join(release) + "\n", encoding="utf-8")
        subprocess.run([
            "gpg", "--batch", "--yes", "--homedir", str(self.gnupg), "--local-user", self.signers[signer],
            "--digest-algo", "SHA256", "--clearsign", "--output", str(metadata / "InRelease"), str(unsigned),
        ], check=True, capture_output=True, text=True)
        keyring = root / "allowed.gpg"
        with keyring.open("wb") as output:
            subprocess.run(["gpg", "--batch", "--homedir", str(self.gnupg), "--export", self.signers[0]], check=True, stdout=output)
        return metadata, keyring

    def _fixture_contract(self, module):
        package = {
            "name": "selected", "version": "1", "architecture": "amd64",
            "url": "https://apt-archive.postgresql.org/pub/repos/apt/pool/main/s/selected/selected_1_amd64.deb",
            "size": 7, "sha256": "1" * 64, "source_package": "selected-source", "source_version": "1",
        }
        package_record = "\n".join([
            "Package: selected", "Version: 1", "Architecture: amd64", "Source: selected-source (1)",
            "Filename: pool/main/s/selected/selected_1_amd64.deb", "Size: 7", "SHA256: " + "1" * 64,
            "Description: exact selected package",
        ])
        source_record = "\n".join([
            "Package: selected-source", "Version: 1", "Directory: pool/main/s/selected", "Checksums-Sha256:",
            " " + "2" * 64 + " 11 selected_1.dsc", "Timestamp: exact selected source",
        ])
        repo = {
            "metadata_directory": "pgdg",
            "index": {"path": "main/binary-amd64/Packages.bz2", "file": "Packages.bz2", "selected_stanzas_sha256": module.canonical_stanzas_sha256([module.paragraph_fields(package_record)[0]])},
            "sources": {"path": "main/source/Sources.bz2", "file": "Sources.bz2", "selected_stanzas_sha256": module.canonical_stanzas_sha256([module.paragraph_fields(source_record)[0]])},
        }
        source = {"source_package": "selected-source", "version": "1", "dsc": {"file": "selected_1.dsc", "sha256": "2" * 64, "size": 11}}
        return repo, [package], source, package_record, source_record

    def _copy_metadata(self, destination):
        logical = ROOT / ".cache/builder-debs"
        source = verifier_module().resolve_cache(logical) / "repository-metadata"
        if not source.exists():
            self.skipTest("official ignored repository metadata cache is absent")
        shutil.copytree(source, destination)

    def test_real_offline_signed_chain_verifies_with_the_shared_implementation(self):
        cache = ROOT / ".cache/builder-debs"
        result = subprocess.run(["python3", str(VERIFY), "verify-cache", "--lock", str(LOCK), "--cache", str(cache)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("verified 71", result.stdout)
        module = verifier_module()
        repo, packages, source, package_record, source_record = self._fixture_contract(module)
        unrelated_versions = (
            "Package: unrelated\nVersion: 1\nArchitecture: amd64\nFilename: pool/u.deb\nSize: 1\nSHA256: " + "3" * 64,
            "Package: another\nVersion: 2\nArchitecture: all\nFilename: pool/a.deb\nSize: 2\nSHA256: " + "4" * 64,
        )
        for unrelated in unrelated_versions:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, keyring = self._signed_pgdg_fixture(root, [unrelated, package_record], ["Package: unrelated-source\nVersion: 9", source_record])
                selected_packages, selected_source = module.verify_mutable_pgdg_indexes(
                    repo, root, keyring, {self.signers[0]}, packages, source,
                )
                self.assertEqual([record["Package"] for record in selected_packages], ["selected"])
                self.assertEqual(selected_source["Package"], "selected-source")

    def test_metadata_cache_rejects_symlinks_unexpected_and_stale_files_without_touching_victim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"; cache.mkdir()
            self._copy_metadata(cache / "repository-metadata")
            victim = root / "victim"; victim.write_text("unchanged", encoding="utf-8")
            (cache / "SHA256SUMS").symlink_to(victim)
            result = subprocess.run(["python3", str(VERIFY), "verify-cache", "--lock", str(LOCK), "--cache", str(cache)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
            (cache / "SHA256SUMS").unlink()
            (cache / ".download.stale").write_text("x", encoding="utf-8")
            result = subprocess.run(["python3", str(VERIFY), "verify-cache", "--lock", str(LOCK), "--cache", str(cache)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        module = verifier_module()
        repo, packages, source, package_record, source_record = self._fixture_contract(module)
        cases = {
            "package selected stanza drift": ([package_record + "\nHomepage: https://drift.invalid"], [source_record], 0, None),
            "package removal": ([], [source_record], 0, None),
            "package duplicate": ([package_record, package_record], [source_record], 0, None),
            "source selected stanza drift": ([package_record], [source_record + "\nHomepage: https://drift.invalid"], 0, None),
            "source removal": ([package_record], [], 0, None),
            "source duplicate": ([package_record], [source_record, source_record], 0, None),
            "signer mismatch": ([package_record], [source_record], 1, None),
            "malformed package index": (["not-deb822"], [source_record], 0, None),
            "package hash drift": ([package_record.replace("1" * 64, "9" * 64)], [source_record], 0, None),
            "package size drift": ([package_record.replace("Size: 7", "Size: 8")], [source_record], 0, None),
            "package source drift": ([package_record.replace("selected-source (1)", "wrong-source (1)")], [source_record], 0, None),
            "source checksum drift": ([package_record], [source_record.replace("2" * 64, "8" * 64)], 0, None),
            "release to current index mismatch": ([package_record], [source_record], 0, "replace-after-signing"),
        }
        for name, (package_records, source_records, signer, action) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                metadata, keyring = self._signed_pgdg_fixture(root, package_records, source_records, signer)
                if action:
                    (metadata / "Packages.bz2").write_bytes(bz2.compress((package_record + "\n\nPackage: post-signing\n").encode()))
                with self.assertRaises(module.Failure):
                    module.verify_mutable_pgdg_indexes(repo, root, keyring, {self.signers[0]}, packages, source)


class DockerfileContractTests(unittest.TestCase):
    def test_dockerfile_is_offline_checks_deb_metadata_and_exact_full_database_transition(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(f"FROM {OPERAND}", text)
        for forbidden in ("apt-get", "curl", "wget", "--security=insecure", "comm -13"):
            self.assertNotIn(forbidden, text)
        self.assertIn("--network=none", BUILD.read_text(encoding="utf-8"))
        self.assertIn("dpkg-deb -f", text)
        self.assertIn("packages-before.tsv", text)
        self.assertIn("packages-expected.tsv", text)
        self.assertIn("diff -u /tmp/packages-expected.tsv /tmp/packages-after.tsv", text)
        self.assertIn("locked package already installed", text)

    def test_wrapper_tracks_builder_ownership_and_explicit_signal_exit(self):
        text = BUILD.read_text(encoding="utf-8")
        self.assertIn("ownership_marker", text)
        self.assertIn(".builder-ownership.", text)
        self.assertIn("openssl rand", text)
        self.assertIn("on_signal", text)
        self.assertIn("exit 129", text)
        self.assertIn("exit 130", text)
        self.assertIn("exit 143", text)


class FinalBlockerRegressionTests(unittest.TestCase):
    def test_bool_package_size_is_rejected_by_exact_scalar_typing(self):
        module = verifier_module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            lock = load_lock(); lock["packages"][0]["size"] = True
            write_lock(path, lock)
            module.LOCK_SHA256 = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(module.Failure):
                module.validate_lock(module.load(path), path)

    def test_rejects_symlink_in_any_existing_cache_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"; fixture.mkdir()
            outside = Path(temporary) / "outside"; outside.mkdir()
            (fixture / "linked").symlink_to(outside, target_is_directory=True)
            result = subprocess.run([
                "python3", str(VERIFY), "verify-cache", "--lock", str(LOCK),
                "--cache", str(fixture / "linked" / "cache"),
                "--fixture-root", str(fixture),
            ], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr.lower())

    def test_rejects_symlinked_lockfile_and_fixture_escape_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"; fixture.mkdir()
            cache = fixture / "cache"; cache.mkdir()
            victim = Path(temporary) / "victim"; victim.write_text("unchanged", encoding="utf-8")
            (fixture / ".builder-debs.lock").symlink_to(victim)
            result = subprocess.run([
                "python3", str(VERIFY), "verify-cache", "--lock", str(LOCK),
                "--cache", str(cache), "--fixture-root", str(fixture),
            ], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr.lower())
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
            escaped = subprocess.run([
                "python3", str(VERIFY), "verify-cache", "--lock", str(LOCK),
                "--cache", str(Path(temporary) / "outside"), "--fixture-root", str(fixture),
            ], text=True, capture_output=True)
            self.assertNotEqual(escaped.returncode, 0)
            self.assertIn("escapes", escaped.stderr)

    def test_download_rejects_cross_origin_and_cross_path_redirects(self):
        module = verifier_module()
        class Response:
            def __init__(self, final): self.final = final
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def geturl(self): return self.final
            def read(self, _size=-1): return b"payload"
        initial = "https://snapshot.debian.org/archive/debian/20260525T000000Z/dists/bullseye/InRelease"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "artifact"
            for final in (
                "https://evil.invalid/archive/debian/20260525T000000Z/dists/bullseye/InRelease",
                "https://snapshot.debian.org/archive/debian-security/20260525T000000Z/dists/bullseye/InRelease",
            ):
                with mock.patch.object(module.urllib.request, "urlopen", return_value=Response(final)):
                    with self.assertRaises(module.Failure):
                        module.download(initial, destination, "debian_snapshot")
                self.assertFalse(destination.exists())

    def test_atomic_publication_keeps_current_on_failure_and_rotates_two_bounded_slots(self):
        module = verifier_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            cache = parent / "cache"; cache.mkdir(); (cache / "value").write_text("old")
            stage = parent / ".stage"; stage.mkdir(); (stage / "value").write_text("new")
            module.atomic_publish(stage, cache)
            self.assertEqual((module.resolve_cache(cache) / "value").read_text(), "new")
            stage = parent / ".stage2"; stage.mkdir(); (stage / "value").write_text("newer")
            with mock.patch.object(module, "_publish_pointer", side_effect=OSError("injected pointer failure")):
                with self.assertRaises(OSError): module.atomic_publish(stage, cache)
            self.assertEqual((module.resolve_cache(cache) / "value").read_text(), "new")
            stage = parent / ".stage3"; stage.mkdir(); (stage / "value").write_text("newest")
            module.atomic_publish(stage, cache)
            self.assertEqual((module.resolve_cache(cache) / "value").read_text(), "newest")
            self.assertEqual({p.name for p in cache.iterdir()}, {"current", "generation-a", "generation-b"})

    def test_controlled_pointer_rejects_escape_symlink_and_resolution_race(self):
        module = verifier_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); cache = root / "cache"; cache.mkdir()
            outside = root / "outside"; outside.mkdir()
            for name in module.GENERATION_NAMES: (cache / name).mkdir()
            pointer = cache / module.CURRENT_POINTER
            pointer.write_text("../outside\n", encoding="ascii")
            with self.assertRaises(module.Failure): module.resolve_cache(cache)
            pointer.unlink(); pointer.symlink_to("generation-a")
            with self.assertRaises(module.Failure): module.resolve_cache(cache)
            pointer.unlink(); pointer.write_text("generation-a\n", encoding="ascii")
            shutil.rmtree(cache / "generation-a"); (cache / "generation-a").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(module.Failure): module.resolve_cache(cache)
            (cache / "generation-a").unlink(); (cache / "generation-a").mkdir()
            original_open = module.os.open
            raced = False
            def racing_open(path, flags, *args):
                nonlocal raced
                if Path(path) == pointer and not raced:
                    raced = True
                    replacement = cache / ".racing-current"
                    replacement.write_text("generation-b\n", encoding="ascii")
                    os.replace(replacement, pointer)
                return original_open(path, flags, *args)
            with mock.patch.object(module.os, "open", side_effect=racing_open):
                with self.assertRaises(module.Failure): module.resolve_cache(cache)

    def test_existing_cache_refresh_publication_works_on_repository_filesystem_without_exchange(self):
        module = verifier_module()
        # Keep this on the production filesystem: its overlay rejects
        # renameat2(RENAME_EXCHANGE), unlike the old tmpfs-only fixture.
        parent = ROOT / ".cache"
        parent.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix="builder-publication-test.", dir=parent))
        try:
            cache = temporary / "cache"
            cache.mkdir()
            (cache / "legacy-marker").write_text("old", encoding="utf-8")
            stage = temporary / "stage"
            stage.mkdir()
            (stage / "generation-marker").write_text("new", encoding="utf-8")
            module.atomic_publish(stage, cache)
            resolved = module.resolve_cache(cache)
            self.assertEqual((resolved / "generation-marker").read_text(), "new")
            relative = Path(os.path.relpath(cache, ROOT))
            self.assertEqual(module.resolve_cache(relative), resolved)
            self.assertEqual(
                {p.name for p in cache.iterdir() if p.name.startswith("generation-")},
                {"generation-a", "generation-b"},
            )
            self.assertTrue((cache / "generation-a" / "legacy-marker").is_file())
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def test_refresh_and_build_readers_use_compatible_cache_locking(self):
        module = verifier_module()
        with tempfile.TemporaryDirectory() as temporary:
            lockfile = Path(temporary) / "cache.lock"
            with module.cache_lock(lockfile, exclusive=False):
                descriptor = os.open(lockfile, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally: os.close(descriptor)
        wrapper = BUILD.read_text(encoding="utf-8")
        self.assertIn("flock -s", wrapper)
        self.assertLess(wrapper.index("flock -s"), wrapper.index("--offline"))
        self.assertLess(wrapper.index("flock -s"), wrapper.index("docker buildx build"))

    def test_build_binds_exact_lock_derived_closure_after_verification(self):
        lock = load_lock()
        generated = {
            "SHA256SUMS": "".join(f"{p['sha256']}  {p['sha256']}.deb\n" for p in lock["packages"]),
            "package-manifest.tsv": "\n".join(lock["newly_installed_manifest"]) + "\n",
            "package-metadata.tsv": "\n".join("\t".join(str(p[k]) for k in ("sha256","name","version","architecture","source_package","source_version")) for p in lock["packages"]) + "\n",
        }
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        for name, content in generated.items():
            digest = hashlib.sha256(content.encode()).hexdigest()
            self.assertIn(f"{digest}  /builder-debs/{name}", dockerfile)
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            for name, content in generated.items(): (cache / name).write_text(content, encoding="utf-8")
            expected = "".join(f"{hashlib.sha256(content.encode()).hexdigest()}  {cache / name}\n" for name, content in generated.items())
            verified = subprocess.run(["sha256sum", "-c", "-"], input=expected, text=True, capture_output=True)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            # Adversary substitutes the ignored context after wrapper verification.
            with (cache / "package-manifest.tsv").open("a", encoding="utf-8") as output:
                output.write("attacker\t1\tamd64\n")
            in_build_gate = subprocess.run(["sha256sum", "-c", "-"], input=expected, text=True, capture_output=True)
            self.assertNotEqual(in_build_gate.returncode, 0)

    def _fake_docker_run(self, mode, signal_at=None, sent_signal=signal.SIGTERM, process_group=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); bindir = root / "bin"; bindir.mkdir()
            log = root / "docker.log"; event = root / "event"
            docker = bindir / "docker"
            docker.write_text("""#!/usr/bin/env bash
set -eu
printf '%s\\n' \"$*\" >> \"$FAKE_DOCKER_LOG\"
if [[ \"$1 $2\" == 'buildx create' ]]; then
  [[ \"${FAKE_DOCKER_MODE:-success}\" != failure ]] || exit 1
  [[ \"${FAKE_DOCKER_MODE:-success}\" != collision ]] || exit 1
  printf 'created %s\\n' \"$*\" >> \"$FAKE_DOCKER_LOG\"
  touch \"$FAKE_DOCKER_EVENT.create\"
  [[ \"${FAKE_DOCKER_MODE:-success}\" != create-wait ]] || sleep 0.4
elif [[ \"$1 $2\" == 'buildx inspect' ]]; then
  touch \"$FAKE_DOCKER_EVENT.inspect\"
  [[ \"${FAKE_DOCKER_MODE:-success}\" != inspect-wait ]] || sleep 0.4
fi
exit 0
""", encoding="utf-8")
            docker.chmod(0o755)
            fake_mv = bindir / "mv"
            fake_mv.write_text("""#!/usr/bin/env bash
set -eu
case \"$*\" in
  *builder-ownership*partial*)
    touch \"$FAKE_DOCKER_EVENT.marker\"
    [[ \"${FAKE_DOCKER_MODE:-success}\" != marker-wait ]] || sleep 0.4
    ;;
esac
/bin/mv \"$@\"
printf 'published ownership marker\\n' >> \"$FAKE_DOCKER_LOG\"
""", encoding="utf-8")
            fake_mv.chmod(0o755)
            fake_python = bindir / "python3"
            fake_python.write_text("""#!/bin/sh
case "${1:-}" in
  */verify_builder_lock.py) [ "${2:-}" != verify-cache ] || exit 0 ;;
esac
exec /usr/bin/python3 "$@"
""", encoding="utf-8")
            fake_python.chmod(0o755)

            environment = os.environ.copy()
            environment.update(
                PATH=str(bindir) + os.pathsep + environment["PATH"],
                FAKE_DOCKER_LOG=str(log), FAKE_DOCKER_EVENT=str(event),
                FAKE_DOCKER_MODE=mode, DOCKER_CONFIG=str(root / "docker-config"),
                BUILDER_CACHE_LOCK_HELD="1",
                BUILDER_CACHE_GENERATION=str(verifier_module().resolve_cache(ROOT / ".cache/builder-debs")),
            )
            process = subprocess.Popen(
                [str(BUILD), "local/test:signal"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=environment, start_new_session=process_group,
            )
            communicated = False
            try:
                if signal_at:
                    target = Path(str(event) + f".{signal_at}")
                    deadline = time.monotonic() + 90
                    while not target.exists() and process.poll() is None and time.monotonic() < deadline: time.sleep(0.02)
                    self.assertTrue(target.exists(), "fake docker did not reach signal window")
                    if process_group:
                        os.killpg(process.pid, sent_signal)
                    else:
                        os.kill(process.pid, sent_signal)
                stdout, stderr = process.communicate(timeout=30)
                communicated = True
                return process.returncode, log.read_text(encoding="utf-8") if log.exists() else "", stdout + stderr
            finally:
                if not communicated:
                    if process.poll() is None:
                        if process_group:
                            os.killpg(process.pid, signal.SIGTERM)
                        else:
                            process.terminate()
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        if process_group:
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                        process.communicate()

    def test_builder_signal_windows_and_collisions_only_remove_owned_builder(self):
        for mode in ("failure", "collision"):
            returncode, log, output = self._fake_docker_run(mode)
            self.assertNotEqual(returncode, 0, output)
            self.assertNotIn("created buildx create", log)
            self.assertNotIn("published ownership marker", log)
            self.assertNotIn("buildx rm", log)
        returncode, log, output = self._fake_docker_run("success")
        self.assertEqual(returncode, 0, output)
        self.assertRegex(log, r"--build-context builder-debs=.*/\.cache/builder-debs/generation-[ab]")
        returncode, log, output = self._fake_docker_run("inspect-wait", "inspect")
        self.assertEqual(returncode, 143, output)
        self.assertIn("buildx rm -f", log)

    def test_create_and_marker_publication_survive_pid_and_process_group_cancellation(self):
        expected = {signal.SIGHUP: 129, signal.SIGINT: 130, signal.SIGTERM: 143}
        for repetition in range(2):
            for process_group in (False, True):
                for window in ("create", "marker"):
                    for sent_signal, returncode in expected.items():
                        with self.subTest(repetition=repetition, process_group=process_group, window=window, signal=sent_signal):
                            mode = "create-wait" if window == "create" else "marker-wait"
                            actual, log, output = self._fake_docker_run(
                                mode, window, sent_signal=sent_signal, process_group=process_group,
                            )
                            self.assertEqual(actual, returncode, output)
                            create = next(line for line in log.splitlines() if line.startswith("buildx create "))
                            builder = create.split("--name ", 1)[1].split()[0]
                            self.assertIn(f"created {create}", log)
                            self.assertIn("published ownership marker", log)
                            self.assertIn(f"buildx rm -f {builder}", log)


if __name__ == "__main__":
    unittest.main(verbosity=2)
