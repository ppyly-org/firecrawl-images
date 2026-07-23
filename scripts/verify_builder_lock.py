#!/usr/bin/env python3
"""Fail-closed verifier and cache refresher for the PostgreSQL 18.4 builder."""
from __future__ import annotations

import argparse
import bz2
import contextlib
import fcntl
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# This digest makes every lock field immutable independently of metadata supplied by
# the lock itself.  Update it only as part of a reviewed lock rotation.
LOCK_SHA256 = "c9c74f17b17ed4dc02f6dec242d6d73fc7d82325938e695c34257ac669fca2b6"
PRODUCTION = {
    "operand": {"reference": "ghcr.io/cloudnative-pg/postgresql@sha256:8ff3abd13383e619797f974b4fcdda6de0c2cfdad90eb47e1cd95d41fe26bf80", "postgresql_version": "18.4", "debian_package_version": "18.4-1.pgdg11+1", "distribution": "debian", "suite": "bullseye", "libc6_version": "2.31-13+deb11u13"},
    "repositories": {
        "debian_snapshot": ("20260525T000000Z", "https://snapshot.debian.org/archive/debian/20260525T000000Z", "bullseye", "debian", "7917d4598768bfc4a25776eb0f6bf2f7d1f13301c2dc1e16467ef170dd752d40", "main/binary-amd64/Packages.xz", "Packages.xz", "1c3405444297ead864711c18e64bce4810db63b48340a2f9d81182d9f235ad71", 8065948),
        "debian_security_snapshot": ("20260525T000000Z", "https://snapshot.debian.org/archive/debian-security/20260525T000000Z", "bullseye-security", "debian-security", "55e0586ced0265471b8aef4d4f7727a68e0cf3fb15489959c0b25b7013de06e5", "main/binary-amd64/Packages.xz", "Packages.xz", "18e9aa0ef2f9692055c681a72eb36340a0f1aa4117418f252e240eb77d0c40ae", 457172),
        "debian_updates_snapshot": ("20260525T000000Z", "https://snapshot.debian.org/archive/debian/20260525T000000Z", "bullseye-updates", "debian-updates", "e7c2ada1e773d679722b9ca1be52c8286213593273c6abaa718f608b9502a089", "main/binary-amd64/Packages.xz", "Packages.xz", "eebb6103cc6f76baa2fee74e7dd915be4c888033bf438756df0774890bdf9806", 18832),
        "pgdg_archive": ("https://apt-archive.postgresql.org/pub/repos/apt", "bullseye-pgdg-archive", "pgdg", "mutable-signed-index-exact-selected-records-v1", "main/binary-amd64/Packages.bz2", "Packages.bz2", "ebc684f77dd83447d2348a0d5166d60e821c429ccd9af0bf0a076fec5b77664c", "main/source/Sources.bz2", "Sources.bz2", "42ce52249fa03aac8bce2b2b77bcc7d141b5bc5e8b0a3d15f6efc44590f74021"),
    },
    "repository_signers": {
        "debian_snapshot": {"A7236886F3CCCAAD148A27F80E98404D386FA1D9", "4CB50190207B4758A3F73A796ED0E7B82643E131", "A4285295FC7B1A81600062A9605C66F00D6C9793"},
        "debian_security_snapshot": {"B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8", "ED541312A33F1128F10B1C6C54404762BBB6E853"},
        "debian_updates_snapshot": {"A7236886F3CCCAAD148A27F80E98404D386FA1D9", "4CB50190207B4758A3F73A796ED0E7B82643E131", "A4285295FC7B1A81600062A9605C66F00D6C9793"},
        "pgdg_archive": {"B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"},
    },
    "keyrings": {
        "debian": ("sources/repository-trust/debian-archive-keyring.pgp", "506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017", {"A7236886F3CCCAAD148A27F80E98404D386FA1D9", "4CB50190207B4758A3F73A796ED0E7B82643E131", "A4285295FC7B1A81600062A9605C66F00D6C9793", "B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8", "ED541312A33F1128F10B1C6C54404762BBB6E853"}),
        "pgdg": ("sources/repository-trust/pgdg-ACCC4CF8.gpg", "8ca1b2fb3a2533cc44b87ee146a03858f6e8ea31c1f165dfd38dc270c04ada0f", {"B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"}),
    },
    "source": {
        "source_package": "postgresql-18", "version": "18.4-1.pgdg11+1",
        "dsc": ("https://apt-archive.postgresql.org/pub/repos/apt/pool/main/p/postgresql-18/postgresql-18_18.4-1.pgdg11+1.dsc", "postgresql-18_18.4-1.pgdg11+1.dsc", "fc4bf05815e939e8ace18bd0a490f09c2716903231dba3a22a33b5f6bb11e7e3", 3528),
        "orig_tar_bz2": ("https://apt-archive.postgresql.org/pub/repos/apt/pool/main/p/postgresql-18/postgresql-18_18.4.orig.tar.bz2", "postgresql-18_18.4.orig.tar.bz2", "81a81ec695fb0c7901407defaa1d2f7973617154cf27ba74e3a7ab8e64436094", 22567173),
        "debian_tar_xz": ("https://apt-archive.postgresql.org/pub/repos/apt/pool/main/p/postgresql-18/postgresql-18_18.4-1.pgdg11+1.debian.tar.xz", "postgresql-18_18.4-1.pgdg11+1.debian.tar.xz", "cb9674e5453c2fcff9621750f3c59e42bc039c962ac80ae157a3939482857ff8", 27804),
    },
}
HEX = re.compile(r"^[0-9a-f]{64}$")
GENERATION_NAMES = ("generation-a", "generation-b")
CURRENT_POINTER = "current"
URL_POLICIES = {
    "debian_snapshot": ("snapshot.debian.org", "/archive/debian/20260525T000000Z/"),
    "debian_security_snapshot": ("snapshot.debian.org", "/archive/debian-security/20260525T000000Z/"),
    "debian_updates_snapshot": ("snapshot.debian.org", "/archive/debian/20260525T000000Z/"),
    "pgdg_archive": ("apt-archive.postgresql.org", "/pub/repos/apt/"),
}

class Failure(Exception): pass

def fail(message: str) -> None: raise Failure(message)
def sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def lexical_absolute(path: Path) -> Path:
    # Collapse '.' and '..' without resolving symlinks.
    return Path(os.path.abspath(os.fspath(path)))
def reject_symlink_components(path: Path) -> None:
    path=lexical_absolute(path)
    current=Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try: info=current.lstat()
        except FileNotFoundError: continue
        if stat.S_ISLNK(info.st_mode): fail(f"symlink path component is forbidden: {current}")
def confined(path: Path, root: Path) -> bool:
    try: lexical_absolute(path).relative_to(lexical_absolute(root)); return True
    except ValueError: return False
def regular(path: Path) -> None:
    reject_symlink_components(path)
    try: info = path.lstat()
    except FileNotFoundError: fail(f"missing required file: {path}")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1: fail(f"not a singly-linked regular file: {path}")
def real_dir(path: Path) -> None:
    reject_symlink_components(path)
    try: info = path.lstat()
    except FileNotFoundError: fail(f"missing required directory: {path}")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode): fail(f"not a real directory: {path}")
def load(path: Path) -> dict[str, Any]:
    regular(path)
    try: value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error: fail(f"invalid JSON lock: {error}")
    if type(value) is not dict: fail("lock root is not an object")
    return value
def require_keys(value: dict[str, Any], keys: set[str], where: str) -> None:
    if set(value) != keys: fail(f"unexpected or missing keys in {where}: {sorted(value)}")
def paragraph_fields(text: str) -> list[dict[str, str]]:
    records=[]
    for paragraph in text.strip().split("\n\n"):
        fields={}; current=None
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")) and current: fields[current] += "\n" + line[1:]
            elif ":" in line:
                current, value=line.split(":", 1)
                if not current or (value and not value.startswith(" ")): fail("malformed deb822 field")
                if current in fields: fail("duplicate deb822 field")
                fields[current]=value.lstrip(" ")
            else: fail("malformed deb822 metadata")
        records.append(fields)
    return records
def source_value(raw: str | None, fallback: str) -> tuple[str, str]:
    if raw is None: return fallback, ""
    match=re.fullmatch(r"([^ ]+)(?: \(([^)]+)\))?", raw)
    if not match: fail(f"invalid Source field: {raw}")
    return match.group(1), match.group(2) or ""
def fingerprints(keyring: Path) -> set[str]:
    regular(keyring)
    with tempfile.TemporaryDirectory(prefix="builder-lock-gpg-") as home:
        os.chmod(home, 0o700)
        result=subprocess.run(["gpg", "--no-options", "--homedir", home, "--show-keys", "--with-colons", str(keyring)], text=True, capture_output=True)
    if result.returncode: fail(f"cannot inspect trust root: {keyring}")
    return {line.split(":")[9] for line in result.stdout.splitlines() if line.startswith("fpr:")}
def gpgv(inrelease: Path, keyring: Path, allowed: set[str]) -> None:
    regular(inrelease); regular(keyring)
    result=subprocess.run(["gpgv", "--status-fd", "1", "--keyring", str(keyring), str(inrelease)], text=True, capture_output=True)
    valid={line.split()[2] for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) >= 3}
    if result.returncode or not valid.intersection(allowed): fail(f"signature verification failed for {inrelease.name}; allowed signer absent")
def signed_release(inrelease: Path, keyring: Path, allowed: set[str]) -> str:
    gpgv(inrelease, keyring, allowed)
    result=subprocess.run(["gpgv", "--keyring", str(keyring), "--output", "-", str(inrelease)], text=True, capture_output=True)
    if result.returncode: fail(f"cannot extract verified release: {inrelease}")
    return result.stdout
def release_hash(release: str, index_path: str) -> tuple[str, int]:
    found=[]; start=False
    for line in release.splitlines():
        if line == "SHA256:": start=True; continue
        if start:
            if not line.startswith(" "): break
            fields=line.split()
            if len(fields) == 3 and fields[2] == index_path: found.append((fields[0], int(fields[1])))
    if len(found) != 1: fail(f"Release must contain exactly one SHA256 record for {index_path}")
    return found[0]
def decompressed(path: Path) -> str:
    regular(path); data=path.read_bytes()
    try:
        if path.suffix == ".xz": return lzma.decompress(data).decode("utf-8")
        if path.suffix == ".bz2": return bz2.decompress(data).decode("utf-8")
    except (OSError, UnicodeDecodeError) as error: fail(f"invalid compressed index {path}: {error}")
    fail(f"unsupported index compression: {path}")
def checked_index(repo: dict[str, Any], metadata: Path, keyring: Path, allowed: set[str], name: str) -> list[dict[str,str]]:
    inrelease=metadata / repo["metadata_directory"] / "InRelease"; index=metadata / repo["metadata_directory"] / repo["index"]["file"]
    release=signed_release(inrelease, keyring, allowed); expected_hash, expected_size=release_hash(release, repo["index"]["path"])
    if expected_hash != repo["index"]["sha256"] or expected_size != repo["index"]["size"]: fail(f"Release-to-index lock mismatch for {name}")
    regular(index)
    if sha(index) != expected_hash or index.stat().st_size != expected_size: fail(f"Release-to-index cache mismatch for {name}")
    return paragraph_fields(decompressed(index))
def current_signed_index(release: str, repo: dict[str, Any], metadata: Path, name: str) -> list[dict[str,str]]:
    index=metadata/repo["metadata_directory"]/repo["index"]["file"]
    expected_hash,expected_size=release_hash(release,repo["index"]["path"])
    regular(index)
    if sha(index) != expected_hash or index.stat().st_size != expected_size: fail(f"Release-to-current-index mismatch for {name}")
    return paragraph_fields(decompressed(index))
def canonical_stanzas_sha256(records: list[dict[str,str]]) -> str:
    canonical=json.dumps(records,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()
def package_path(url: str) -> str:
    if "/pool/" not in url: fail(f"package URL has no pool path: {url}")
    return "pool/" + url.split("/pool/", 1)[1]
def validate_lock(lock: dict[str, Any], lock_path: Path) -> None:
    if sha(lock_path) != LOCK_SHA256: fail("immutable production lock digest drift")
    require_keys(lock, {"schema_version","platform","operand","repositories","postgresql_source","packages","newly_installed_manifest"}, "lock")
    if type(lock["schema_version"]) is not int or lock["schema_version"] != 2 or type(lock["platform"]) is not str or lock["platform"] != "linux/amd64" or type(lock["operand"]) is not dict or lock["operand"] != PRODUCTION["operand"]: fail("production operand identity drift")
    if type(lock["repositories"]) is not dict or set(lock["repositories"]) != set(PRODUCTION["repositories"]): fail("repository identities drift")
    for name, expected in PRODUCTION["repositories"].items():
        repo=lock["repositories"][name]; pgdg=name == "pgdg_archive"
        if type(repo) is not dict: fail(f"repository {name} is not object")
        keys={"url","suite","signing_fingerprints","metadata_directory","keyring","keyring_sha256","index"}
        if not pgdg: keys.update({"timestamp","inrelease_sha256"})
        else: keys.update({"index_policy","sources"})
        require_keys(repo, keys, name)
        if type(repo["index"]) is not dict: fail(f"repository index is not object: {name}")
        if pgdg and type(repo["sources"]) is not dict: fail("PGDG sources is not object")
        values=(repo.get("url"),repo.get("suite"),repo.get("metadata_directory"),repo.get("inrelease_sha256"),repo["index"].get("path"),repo["index"].get("file"),repo["index"].get("sha256"),repo["index"].get("size"))
        expected_values=expected[1:]
        if pgdg:
            require_keys(repo["index"],{"path","file","selected_stanzas_sha256"},"pgdg index")
            values=(repo.get("url"),repo.get("suite"),repo.get("metadata_directory"),repo.get("index_policy"),repo["index"].get("path"),repo["index"].get("file"),repo["index"].get("selected_stanzas_sha256"))
            expected_values=expected[:7]
        if values != expected_values: fail(f"hardcoded repository evidence drift: {name}")
        if not pgdg and repo.get("timestamp") != expected[0]: fail(f"repository timestamp drift: {name}")
        if pgdg:
            source=repo["sources"]
            require_keys(source,{"path","file","selected_stanzas_sha256"},"pgdg sources")
            if tuple(source.get(k) for k in ("path","file","selected_stanzas_sha256")) != expected[7:]: fail("hardcoded PGDG Sources selected-record drift")
        key_name="pgdg" if pgdg else "debian"; key_path,key_sha,_keyring_fprs=PRODUCTION["keyrings"][key_name]
        if repo["keyring_sha256"] != key_sha or repo["signing_fingerprints"] != sorted(PRODUCTION["repository_signers"][name]): fail(f"trust root lock drift: {name}")
        if not pgdg and (type(repo["index"].get("size")) is not int or repo["index"]["size"] <= 0): fail("invalid index size")
    source=lock["postgresql_source"]
    if type(source) is not dict: fail("postgresql_source is not object")
    require_keys(source,{"source_package","version","dsc","orig_tar_bz2","debian_tar_xz"},"postgresql_source")
    if source["source_package"] != PRODUCTION["source"]["source_package"] or source["version"] != PRODUCTION["source"]["version"]: fail("PostgreSQL source identity drift")
    for item_name in ("dsc","orig_tar_bz2","debian_tar_xz"):
        item=source[item_name]
        if type(item) is not dict: fail(f"source.{item_name} is not object")
        require_keys(item,{"url","sha256","file","size"},f"source.{item_name}")
        if tuple(item[k] for k in ("url","file","sha256","size")) != PRODUCTION["source"][item_name]: fail(f"hardcoded PostgreSQL source drift: {item_name}")
    packages=lock["packages"]
    if type(packages) is not list or len(packages) != 71: fail("package closure must have exactly 71 records")
    identities=[]
    for package in packages:
        if type(package) is not dict: fail("package record is not object")
        require_keys(package,{"name","version","architecture","url","size","sha256","source_package","source_version"},"package")
        if not all(type(package[k]) is str and package[k] for k in ("name","version","architecture","url","sha256","source_package","source_version")) or package["architecture"] not in {"amd64","all"} or type(package["size"]) is not int or package["size"] <= 0 or not HEX.fullmatch(package["sha256"]): fail("invalid package fields")
        identities.append((package["name"],package["version"],package["architecture"]))
    if identities != sorted(identities) or len(set(identities)) != 71: fail("package identities must be unique and sorted")
    if type(lock["newly_installed_manifest"]) is not list or not all(type(row) is str for row in lock["newly_installed_manifest"]) or lock["newly_installed_manifest"] != ["\t".join(row) for row in identities]: fail("newly_installed_manifest is not exact")
def cache_entries(cache: Path, lock: dict[str, Any]) -> None:
    real_dir(cache); expected={"repository-metadata","SHA256SUMS","package-manifest.tsv","package-metadata.tsv"} | {p["sha256"]+".deb" for p in lock["packages"]}
    actual={child.name for child in cache.iterdir()}
    if actual != expected: fail(f"unexpected, stale, or missing cache entries: {sorted(actual ^ expected)}")
    for child in cache.iterdir():
        if child.name == "repository-metadata": real_dir(child)
        else: regular(child)
def source_checks(stanza: dict[str,str]) -> dict[str, tuple[str,int]]:
    checks={}
    for line in stanza.get("Checksums-Sha256", "").splitlines():
        if not line: continue
        fields=line.split()
        if len(fields) != 3 or not HEX.fullmatch(fields[0]) or not fields[1].isdigit() or not fields[2] or "/" in fields[2]: fail("malformed Sources Checksums-Sha256")
        digest,size,filename=fields[0],int(fields[1]),fields[2]
        if filename in checks: fail(f"duplicate source filename: {filename}")
        checks[filename]=(digest,size)
    return checks
def verify_mutable_pgdg_indexes(repo: dict[str,Any], metadata: Path, keyring: Path, allowed: set[str], packages: list[dict[str,Any]], source: dict[str,Any]) -> tuple[list[dict[str,str]],dict[str,str]]:
    """Authenticate the current mutable envelope, then require the exact selected records."""
    inrelease=metadata/repo["metadata_directory"]/"InRelease"
    release=signed_release(inrelease,keyring,allowed)
    package_records=current_signed_index(release,repo,metadata,"pgdg packages")
    source_records=current_signed_index(release,{**repo,"index":repo["sources"]},metadata,"pgdg sources")
    expected_by_filename={package_path(package["url"]):package for package in packages}
    expected_identities={(package["name"],package["version"],package["architecture"]) for package in packages}
    selected=[]
    for stanza in package_records:
        identity=tuple(stanza.get(key) for key in ("Package","Version","Architecture"))
        if stanza.get("Filename") in expected_by_filename or identity in expected_identities: selected.append(stanza)
    if len(selected) != len(packages): fail("PGDG selected package stanza removal or duplicate")
    selected.sort(key=lambda stanza:(stanza.get("Filename",""),stanza.get("Package",""),stanza.get("Version",""),stanza.get("Architecture","")))
    for stanza in selected:
        package=expected_by_filename.get(stanza.get("Filename",""))
        if package is None: fail("PGDG selected package Filename drift")
        if tuple(stanza.get(k) for k in ("Package","Version","Architecture","Size","SHA256")) != (package["name"],package["version"],package["architecture"],str(package["size"]),package["sha256"]): fail(f"package index stanza mismatch: {package['name']}")
        source_name,source_version=source_value(stanza.get("Source"),package["name"])
        if source_name != package["source_package"] or (source_version and source_version != package["source_version"]): fail(f"package source stanza mismatch: {package['name']}")
    if canonical_stanzas_sha256(selected) != repo["index"]["selected_stanzas_sha256"]: fail("PGDG exact selected package stanzas drift")
    matching_sources=[stanza for stanza in source_records if stanza.get("Package")==source["source_package"] and stanza.get("Version")==source["version"]]
    if len(matching_sources) != 1: fail("PostgreSQL source stanza must occur exactly once")
    selected_source=matching_sources[0]
    expected_checks={item["file"]:(item["sha256"],item["size"]) for name,item in source.items() if name not in {"source_package","version"}}
    if source_checks(selected_source) != expected_checks: fail("exact PostgreSQL source artifact checksums drift")
    if canonical_stanzas_sha256([selected_source]) != repo["sources"]["selected_stanzas_sha256"]: fail("PGDG exact selected source stanza drift")
    return selected,selected_source
def verify_cache(lock: dict[str, Any], cache: Path) -> None:
    cache_entries(cache,lock); metadata=cache/"repository-metadata"
    expected_dirs={"debian","debian-security","debian-updates","pgdg","debian/keys","pgdg/keys"}
    source=lock["postgresql_source"]
    expected_files={"debian/InRelease","debian/Packages.xz","debian/keys/debian-archive-keyring.pgp","debian-security/InRelease","debian-security/Packages.xz","debian-updates/InRelease","debian-updates/Packages.xz","pgdg/InRelease","pgdg/Packages.bz2","pgdg/Sources.bz2","pgdg/keys/ACCC4CF8.gpg"} | {"pgdg/" + source[n]["file"] for n in ("dsc","orig_tar_bz2","debian_tar_xz")}
    dirs=set(); files=set()
    for path in metadata.rglob("*"):
        rel=path.relative_to(metadata).as_posix(); info=path.lstat()
        if stat.S_ISLNK(info.st_mode): fail(f"symlink in metadata: {rel}")
        if stat.S_ISDIR(info.st_mode): dirs.add(rel)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1: files.add(rel)
        else: fail(f"unsafe metadata entry: {rel}")
    if dirs != expected_dirs or files != expected_files: fail("unexpected or missing repository metadata entries")
    debian_key=metadata/lock["repositories"]["debian_snapshot"]["keyring"]; pgdg=lock["repositories"]["pgdg_archive"]; pgdg_key=metadata/pgdg["keyring"]
    for kind,key in (("debian",debian_key),("pgdg",pgdg_key)):
        checked=ROOT/PRODUCTION["keyrings"][kind][0]; expected_sha=PRODUCTION["keyrings"][kind][1]; expected_fprs=PRODUCTION["keyrings"][kind][2]
        regular(checked); regular(key)
        if sha(checked) != expected_sha or sha(key) != expected_sha or sha(checked) != sha(key) or not expected_fprs.issubset(fingerprints(checked)) or not expected_fprs.issubset(fingerprints(key)): fail(f"trust-root substitution: {kind}")
    indexes=[]
    for name in ("debian_snapshot","debian_security_snapshot","debian_updates_snapshot"):
        repo=lock["repositories"][name]
        if sha(metadata/repo["metadata_directory"] / "InRelease") != PRODUCTION["repositories"][name][4]: fail("hardcoded Debian InRelease drift")
        indexes += checked_index(repo,metadata,debian_key,PRODUCTION["repository_signers"][name],name)
    pgdg_packages=[package for package in lock["packages"] if package["url"].startswith(pgdg["url"]+"/pool/")]
    packages,selected_source=verify_mutable_pgdg_indexes(pgdg,metadata,pgdg_key,PRODUCTION["repository_signers"]["pgdg_archive"],pgdg_packages,source)
    by_filename={}; wanted_filenames={package_path(package["url"]) for package in lock["packages"]}
    for stanza in indexes + packages:
        filename=stanza.get("Filename")
        if filename in wanted_filenames:
            if filename in by_filename: fail(f"duplicate locked package Filename: {filename}")
            by_filename[filename]=stanza
    for package in lock["packages"]:
        path=package_path(package["url"]); stanza=by_filename.get(path)
        if not stanza or tuple(stanza.get(k) for k in ("Package","Version","Architecture","Size","SHA256")) != (package["name"],package["version"],package["architecture"],str(package["size"]),package["sha256"]): fail(f"package index stanza mismatch: {package['name']}")
        src,version=source_value(stanza.get("Source"),package["name"])
        if src != package["source_package"] or (version and version != package["source_version"]): fail(f"package source stanza mismatch: {package['name']}")
        blob=cache/(package["sha256"]+".deb"); regular(blob)
        if blob.stat().st_size != package["size"] or sha(blob) != package["sha256"]: fail(f"package blob mismatch: {package['name']}")
        fields=[]
        for field in ("Package","Version","Architecture"):
            result=subprocess.run(["dpkg-deb","-f",str(blob),field],text=True,capture_output=True)
            if result.returncode: fail(f"invalid Debian control metadata: {package['name']}")
            fields.append(result.stdout.strip())
        source_result=subprocess.run(["dpkg-deb","-f",str(blob),"Source"],text=True,capture_output=True)
        if source_result.returncode or not all(fields): fail(f"invalid Debian control metadata: {package['name']}")
        src,version=source_value(source_result.stdout.strip() or None,fields[0])
        if (fields[0],fields[1],fields[2],src,version or fields[1]) != (package["name"],package["version"],package["architecture"],package["source_package"],package["source_version"]): fail(f"dpkg-deb metadata mismatch: {package['name']}")
    checks=source_checks(selected_source)
    for name in ("dsc","orig_tar_bz2","debian_tar_xz"):
        item=source[name]; expected=checks.get(item["file"])
        if not expected or expected != (item["sha256"],item["size"]): fail(f"Sources-to-source checksum mismatch: {name}")
        artifact=metadata/pgdg["metadata_directory"]/item["file"]; regular(artifact)
        if sha(artifact) != expected[0] or artifact.stat().st_size != expected[1]: fail(f"source artifact mismatch: {name}")
    # The authenticated Sources stanza, not a detached .dsc signature, authenticates
    # the descriptor.  The descriptor then binds its listed source artifacts.
    dsc=metadata/pgdg["metadata_directory"]/source["dsc"]["file"]
    dsc_records=paragraph_fields(dsc.read_text(encoding="utf-8",errors="strict"))
    if len(dsc_records) != 1: fail("dsc must contain exactly one stanza")
    dsc_checks=source_checks(dsc_records[0])
    for name in ("orig_tar_bz2","debian_tar_xz"):
        item=source[name]
        if dsc_checks.get(item["file"], (None,None))[0] != item["sha256"]: fail(f"dsc-to-source checksum mismatch: {name}")
    metadata_rows=["\t".join([p[k] for k in ("sha256","name","version","architecture","source_package","source_version")]) for p in lock["packages"]]
    expected_sums="".join(f"{p['sha256']}  {p['sha256']}.deb\n" for p in lock["packages"])
    if (cache/"SHA256SUMS").read_text() != expected_sums or (cache/"package-manifest.tsv").read_text() != "\n".join(lock["newly_installed_manifest"])+"\n" or (cache/"package-metadata.tsv").read_text() != "\n".join(metadata_rows)+"\n": fail("generated manifests are not exact")
def policy_for_url(url: str) -> str:
    parsed=urllib.parse.urlsplit(url)
    for name,(host,prefix) in URL_POLICIES.items():
        if parsed.scheme == "https" and parsed.netloc == host and parsed.path.startswith(prefix): return name
    fail(f"URL is outside production repository policies: {url}")
def effective_url_allowed(initial: str, effective: str, policy: str) -> bool:
    expected_host,prefix=URL_POLICIES[policy]
    first=urllib.parse.urlsplit(initial); final=urllib.parse.urlsplit(effective)
    if first.scheme != "https" or first.netloc != expected_host or first.username is not None or first.password is not None or first.fragment or not first.path.startswith(prefix): return False
    if final.scheme != "https" or final.netloc != expected_host or final.username is not None or final.password is not None or final.fragment: return False
    if final.path == first.path and final.query == first.query: return True
    # snapshot.debian.org canonically redirects immutable archive paths to its
    # same-origin content-addressed /file/<sha1>/<basename-or-object-hash>
    # endpoint; all downloaded bytes remain independently lock-hash checked.
    if expected_host == "snapshot.debian.org":
        match=re.fullmatch(r"/file/[0-9a-f]{40}/([^/]+)",final.path)
        if not match or final.query: return False
        leaf=urllib.parse.unquote(match.group(1))
        return leaf == Path(first.path).name or bool(re.fullmatch(r"[0-9a-f]{64}",leaf))
    return False
def download(url: str, destination: Path, policy: str | None = None) -> None:
    temporary=destination.with_name(destination.name + ".partial")
    policy=policy or policy_for_url(url)
    reject_symlink_components(temporary)
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            effective=response.geturl()
            if not effective_url_allowed(url,effective,policy): fail(f"redirect escaped {policy} HTTPS origin/path policy: {effective}")
            with open(temporary, "xb") as output: shutil.copyfileobj(response, output)
        os.replace(temporary,destination)
    except Failure:
        temporary.unlink(missing_ok=True); raise
    except Exception as error:
        temporary.unlink(missing_ok=True); fail(f"download failed for {url}: {error}")
def resolve_cache(cache: Path) -> Path:
    """Resolve the controlled pointer, or accept the pre-generation legacy cache."""
    real_dir(cache)
    cache=lexical_absolute(cache)
    pointer=cache/CURRENT_POINTER
    try: info=pointer.lstat()
    except FileNotFoundError:
        # A legacy cache has payload at its root.  Reserved generation entries may
        # exist only as recoverable debris from an interrupted first migration.
        payload=[p for p in cache.iterdir() if p.name not in GENERATION_NAMES]
        if not payload: fail("cache has no current generation")
        return cache
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: fail("cache current pointer is not a singly-linked regular file")
    descriptor=os.open(pointer,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        opened=os.fstat(descriptor)
        if (opened.st_dev,opened.st_ino) != (info.st_dev,info.st_ino): fail("cache current pointer raced during resolution")
        contents=os.read(descriptor,65)
        if len(contents) > 64 or os.read(descriptor,1): fail("cache current pointer is oversized")
    finally: os.close(descriptor)
    allowed={f"{name}\n".encode("ascii"): name for name in GENERATION_NAMES}
    target=allowed.get(contents)
    if target is None: fail("cache current pointer has invalid encoding")
    generation=cache/target
    try: generation_info=generation.lstat()
    except FileNotFoundError: fail("cache current generation is missing")
    if not stat.S_ISDIR(generation_info.st_mode) or stat.S_ISLNK(generation_info.st_mode):
        fail("cache current generation is not a real directory")
    # Do not resolve through the pointer: the physical path is returned and all
    # of its own ancestors have independently passed the no-symlink walk.
    reject_symlink_components(generation)
    if generation.parent != cache: fail("cache generation escaped cache root")
    return generation
def _sync_directory(directory: Path) -> None:
    descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
def _publish_pointer(cache: Path, target: str) -> None:
    if target not in GENERATION_NAMES: fail("invalid generation pointer target")
    temporary=cache/(f".current.{os.getpid()}.{os.urandom(8).hex()}")
    try:
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
        try:
            os.write(descriptor,(target+"\n").encode("ascii"))
            os.fsync(descriptor)
        finally: os.close(descriptor)
        os.replace(temporary,cache/CURRENT_POINTER)
        _sync_directory(cache)
    finally:
        temporary.unlink(missing_ok=True)
def _copy_legacy_payload(cache: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    try:
        for source in list(cache.iterdir()):
            if source.name in GENERATION_NAMES or source.name == CURRENT_POINTER: continue
            info=source.lstat()
            if stat.S_ISLNK(info.st_mode): fail(f"symlink in legacy cache: {source.name}")
            target=destination/source.name
            if stat.S_ISDIR(info.st_mode): shutil.copytree(source,target,symlinks=True)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1: shutil.copy2(source,target)
            else: fail(f"unsafe legacy cache entry: {source.name}")
    except Exception:
        shutil.rmtree(destination,ignore_errors=True); raise
def _retire_root_extras(cache: Path) -> None:
    for child in list(cache.iterdir()):
        if child.name in {*GENERATION_NAMES,CURRENT_POINTER}: continue
        info=child.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode): shutil.rmtree(child)
        else: child.unlink()
    _sync_directory(cache)
def atomic_publish(stage: Path, cache: Path, verify_generation=None) -> None:
    """Publish stage with two bounded generations and one atomic pointer rename."""
    reject_symlink_components(stage); real_dir(stage)
    reject_symlink_components(cache)
    if not cache.exists(): cache.mkdir(mode=0o700)
    real_dir(cache)
    pointer=cache/CURRENT_POINTER
    if pointer.exists() or pointer.is_symlink():
        active=resolve_cache(cache).name
        inactive=GENERATION_NAMES[1] if active == GENERATION_NAMES[0] else GENERATION_NAMES[0]
        destination=cache/inactive
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_dir(): fail("inactive generation is unsafe")
            shutil.rmtree(destination)
        os.rename(stage,destination)
        _sync_directory(cache)
        _publish_pointer(cache,inactive)
        _retire_root_extras(cache)
        return
    # Explicit migration: copy the only legacy cache into the rollback slot.
    # The original remains untouched until both slots and current are durable.
    for name in GENERATION_NAMES:
        candidate=cache/name
        if candidate.exists() or candidate.is_symlink():
            if candidate.is_symlink() or not candidate.is_dir(): fail("unsafe interrupted migration generation")
            shutil.rmtree(candidate)
    rollback=cache/GENERATION_NAMES[0]
    _copy_legacy_payload(cache,rollback)
    if verify_generation is not None: verify_generation(rollback)
    destination=cache/GENERATION_NAMES[1]
    os.rename(stage,destination)
    _sync_directory(cache)
    _publish_pointer(cache,GENERATION_NAMES[1])
    # Retirement is deterministic and bounded.  The copied verified legacy
    # generation is the deliberate rollback slot; no ad-hoc old directory remains.
    _retire_root_extras(cache)
@contextlib.contextmanager
def cache_lock(lockfile: Path, exclusive: bool):
    reject_symlink_components(lockfile)
    descriptor=os.open(lockfile,os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: fail(f"unsafe cache lock file: {lockfile}")
        fcntl.flock(descriptor,fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally: os.close(descriptor)
def refresh_cache(lock: dict[str, Any], cache: Path) -> None:
    parent=cache.parent; real_dir(parent)
    if cache.exists() or cache.is_symlink():
        if cache.is_symlink() or not cache.is_dir(): fail("cache is not a real directory")
        # Migration and rotation never discard the only valid generation.  A
        # malformed existing cache is not silently replaced by downloaded bytes.
        verify_cache(lock,resolve_cache(cache))
    stage=Path(tempfile.mkdtemp(prefix=".builder-debs.stage.",dir=parent)); metadata=stage/"repository-metadata"
    try:
        for kind, target in (("debian", "debian/keys/debian-archive-keyring.pgp"),("pgdg", "pgdg/keys/ACCC4CF8.gpg")):
            source=ROOT/PRODUCTION["keyrings"][kind][0]; regular(source); destination=metadata/target; destination.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(source,destination)
        for name,repo in lock["repositories"].items():
            directory=metadata/repo["metadata_directory"]; directory.mkdir(parents=True,exist_ok=True)
            base=repo["url"] + "/dists/" + repo["suite"]
            download(base+"/InRelease",directory/"InRelease",name)
            for item_name in (["index","sources"] if name == "pgdg_archive" else ["index"]):
                item=repo[item_name]; download(base+"/"+item["path"],directory/item["file"],name)
        pgdg_dir=metadata/lock["repositories"]["pgdg_archive"]["metadata_directory"]
        for name in ("dsc","orig_tar_bz2","debian_tar_xz"):
            item=lock["postgresql_source"][name]; download(item["url"],pgdg_dir/item["file"],"pgdg_archive")
        for package in lock["packages"]: download(package["url"],stage/(package["sha256"]+".deb"),policy_for_url(package["url"]))
        (stage/"SHA256SUMS").write_text("".join(f"{p['sha256']}  {p['sha256']}.deb\n" for p in lock["packages"]),encoding="utf-8")
        (stage/"package-manifest.tsv").write_text("\n".join(lock["newly_installed_manifest"])+"\n",encoding="utf-8")
        (stage/"package-metadata.tsv").write_text("\n".join("\t".join(p[k] for k in ("sha256","name","version","architecture","source_package","source_version")) for p in lock["packages"])+"\n",encoding="utf-8")
        verify_cache(lock,stage)
        atomic_publish(stage,cache,lambda generation: verify_cache(lock,generation))
    except Exception:
        shutil.rmtree(stage,ignore_errors=True); raise
def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "with-cache-lock":
        bridge=argparse.ArgumentParser(); bridge.add_argument("--lock",type=Path,required=True); bridge.add_argument("--cache",type=Path,required=True); bridge.add_argument("command",nargs=argparse.REMAINDER)
        args=bridge.parse_args(sys.argv[2:]); args.command=args.command[1:] if args.command[:1] == ["--"] else args.command
        try:
            if lexical_absolute(args.lock) != ROOT/"sources/postgresql-18.4-dev.lock" or lexical_absolute(args.cache) != ROOT/".cache/builder-debs": fail("shared build lock is restricted to production repository paths")
            if not args.command: fail("with-cache-lock requires a command")
            reject_symlink_components(args.lock); reject_symlink_components(args.cache)
            lock=load(args.lock); validate_lock(lock,args.lock)
            lockfile=args.cache.parent/".builder-debs.lock"; reject_symlink_components(lockfile)
            descriptor=os.open(lockfile,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
            info=os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: fail(f"unsafe cache lock file: {lockfile}")
            fcntl.flock(descriptor,fcntl.LOCK_SH); os.set_inheritable(descriptor,True)
            generation=resolve_cache(args.cache); verify_cache(lock,generation)
            environment=os.environ.copy()
            environment["BUILDER_CACHE_LOCK_HELD"]="1"
            environment["BUILDER_CACHE_GENERATION"]=str(generation)
            os.execvpe(args.command[0],args.command,environment)
        except (Failure,OSError) as error: print(f"verify-builder-lock: {error}",file=sys.stderr); return 1
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
    for name in ("validate-lock","verify-cache","refresh-cache"):
        item=sub.add_parser(name); item.add_argument("--lock",type=Path,default=ROOT/"sources/postgresql-18.4-dev.lock"); item.add_argument("--cache",type=Path,default=ROOT/".cache/builder-debs"); item.add_argument("--fixture-root",type=Path)
    args=parser.parse_args()
    try:
        production_lock=ROOT/"sources/postgresql-18.4-dev.lock"; production_cache=ROOT/".cache/builder-debs"
        if args.fixture_root is not None:
            real_dir(args.fixture_root)
            if lexical_absolute(args.lock) != production_lock and not confined(args.lock,args.fixture_root): fail("fixture lock escapes explicit fixture root")
            if lexical_absolute(args.cache) != production_cache and not confined(args.cache,args.fixture_root): fail("fixture cache escapes explicit fixture root")
        elif lexical_absolute(args.lock) != production_lock or lexical_absolute(args.cache) != production_cache:
            fail("production lock/cache paths must remain inside the repository; use --fixture-root only in tests")
        reject_symlink_components(args.lock); reject_symlink_components(args.cache)
        lock=load(args.lock); validate_lock(lock,args.lock)
        if args.command == "validate-lock": print("lock schema v2 is valid")
        else:
            lockfile=args.cache.parent/".builder-debs.lock"
            reject_symlink_components(lockfile)
            with cache_lock(lockfile,exclusive=args.command == "refresh-cache"):
                if args.command == "verify-cache":
                    generation=resolve_cache(args.cache)
                    verify_cache(lock,generation)
                    print(f"verified 71 locked Debian packages and authenticated repository chain at {generation}")
                else: refresh_cache(lock,args.cache); print("refreshed and verified 71 locked Debian packages and authenticated repository chain")
        return 0
    except (Failure,OSError) as error: print(f"verify-builder-lock: {error}",file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())
