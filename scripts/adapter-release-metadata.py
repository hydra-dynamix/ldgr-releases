#!/usr/bin/env python3
"""Generate and gate compatibility-v2 adapter catalog metadata.

Release workflows emit one fragment per native archive from the generated
adapter-compatibility.json sidecar. Publication merges a complete platform
matrix, verifies every archive carries that sidecar, and evaluates stable
variants against every signed stable Core compatibility profile before writing
schema-v2 index.json.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

ADAPTER_FORMAT = "ldgr.adapter-compatibility.v2"
CORE_FORMAT = "ldgr.core-compatibility.v2"
FRAGMENT_FORMAT = "ldgr.adapter-release-fragment.v2"
PLATFORMS = (
    "linux-aarch64",
    "linux-x86_64",
    "macos-aarch64",
    "macos-x86_64",
    "windows-x86_64",
)
IDENTIFIER = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
CAPABILITY = re.compile(
    r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)*\.v[1-9][0-9]*"
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


class GateError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"{path} is not valid UTF-8 JSON: {error}") from error


def exact(value: Any, fields: set[str], subject: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{subject} must be an object")
    require(set(value) == fields, f"{subject} fields differ: expected {sorted(fields)}, got {sorted(value)}")
    return value


def text(value: Any, subject: str) -> str:
    require(isinstance(value, str) and value and value.strip() == value, f"{subject} must be non-empty text")
    return value


def identifier(value: Any, subject: str) -> str:
    value = text(value, subject)
    require(IDENTIFIER.fullmatch(value) is not None and not value.startswith("ldgr-"), f"{subject} is not a canonical adapter identifier")
    return value


def positive(value: Any, subject: str) -> int:
    require(not isinstance(value, bool) and isinstance(value, int) and 1 <= value <= 2_147_483_647, f"{subject} must be a positive 32-bit integer")
    return value


def sorted_unique(values: Any, subject: str, key=lambda value: value) -> list[Any]:
    require(isinstance(values, list), f"{subject} must be an array")
    require(values == sorted(values, key=key), f"{subject} must be sorted")
    keys = [key(value) for value in values]
    require(len(keys) == len(set(keys)), f"{subject} must be unique")
    return values


def canonical_json(value: Any) -> bytes:
    # The compatibility schemas exclude floats and constrain strings to ASCII.
    # For that domain this is RFC 8785 JCS serialization.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fingerprint(compatibility: dict[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(compatibility)).hexdigest()}"


def validate_requirements(value: Any, subject: str) -> dict[str, Any]:
    value = exact(value, {"adapter_protocol_epoch", "central_components", "minimum_core_schema", "required_core_capabilities"}, subject)
    positive(value["adapter_protocol_epoch"], f"{subject}.adapter_protocol_epoch")
    positive(value["minimum_core_schema"], f"{subject}.minimum_core_schema")
    capabilities = sorted_unique(value["required_core_capabilities"], f"{subject}.required_core_capabilities")
    for offset, capability in enumerate(capabilities):
        require(isinstance(capability, str) and CAPABILITY.fullmatch(capability) is not None, f"{subject}.required_core_capabilities[{offset}] is invalid")
    components = sorted_unique(value["central_components"], f"{subject}.central_components", lambda item: item.get("namespace", "") if isinstance(item, dict) else "")
    for offset, component in enumerate(components):
        field = f"{subject}.central_components[{offset}]"
        component = exact(component, {"accepted_lineage_digests", "minimum_schema_version", "namespace", "schema_epoch"}, field)
        identifier(component["namespace"], f"{field}.namespace")
        positive(component["schema_epoch"], f"{field}.schema_epoch")
        positive(component["minimum_schema_version"], f"{field}.minimum_schema_version")
        digests = sorted_unique(component["accepted_lineage_digests"], f"{field}.accepted_lineage_digests")
        require(bool(digests), f"{field}.accepted_lineage_digests must not be empty")
        require(all(isinstance(item, str) and DIGEST.fullmatch(item) for item in digests), f"{field}.accepted_lineage_digests contains an invalid digest")
    return value


def validate_sidecar(value: Any, subject: str) -> dict[str, Any]:
    value = exact(value, {"adapter", "compatibility", "format", "local_stores"}, subject)
    require(value["format"] == ADAPTER_FORMAT, f"{subject}.format must be {ADAPTER_FORMAT}")
    identifier(value["adapter"], f"{subject}.adapter")
    validate_requirements(value["compatibility"], f"{subject}.compatibility")
    stores = sorted_unique(value["local_stores"], f"{subject}.local_stores", lambda item: item.get("store_id", "") if isinstance(item, dict) else "")
    for offset, store in enumerate(stores):
        field = f"{subject}.local_stores[{offset}]"
        store = exact(store, {"engine", "migration_digest", "schema_version", "store_id"}, field)
        identifier(store["engine"], f"{field}.engine")
        identifier(store["store_id"], f"{field}.store_id")
        positive(store["schema_version"], f"{field}.schema_version")
        require(isinstance(store["migration_digest"], str) and DIGEST.fullmatch(store["migration_digest"]) is not None, f"{field}.migration_digest is invalid")
    return value


def semver(value: Any, subject: str) -> tuple[Any, ...]:
    value = text(value, subject)
    match = SEMVER.fullmatch(value)
    require(match is not None, f"{subject} must be semantic version syntax")
    prerelease = match.group(4)
    pre: tuple[Any, ...] = (1,) if prerelease is None else (0, *tuple((0, int(part)) if part.isdigit() else (1, part) for part in prerelease.split(".")))
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), pre


def validate_platform(value: Any, subject: str) -> dict[str, Any]:
    value = exact(value, {"archive_root", "asset_url", "binary", "platform", "resource_manifest", "sha256", "signature_url", "signing_key_id"}, subject)
    require(value["platform"] in PLATFORMS, f"{subject}.platform is unsupported")
    for field in ("archive_root", "asset_url", "binary", "resource_manifest", "signature_url", "signing_key_id"):
        text(value[field], f"{subject}.{field}")
    require(PurePosixPath(value["archive_root"]).name == value["archive_root"] and value["archive_root"] not in {".", ".."}, f"{subject}.archive_root must be one path component")
    require(SHA256.fullmatch(value["sha256"]) is not None, f"{subject}.sha256 must be lowercase SHA-256")
    return value


def validate_product(value: Any, subject: str, fragment: bool = False) -> dict[str, Any]:
    required = {"aliases", "classification", "domain", "primary_namespace", "releases", "title"}
    allowed = required | {"source_url"}
    require(isinstance(value, dict) and required <= set(value) <= allowed, f"{subject} fields are invalid")
    domain = identifier(value["domain"], f"{subject}.domain")
    require(value["primary_namespace"] == domain, f"{subject}.primary_namespace must equal domain")
    text(value["title"], f"{subject}.title")
    require(value["classification"] in {"open_source", "commercial"}, f"{subject}.classification is invalid")
    aliases = sorted_unique(value["aliases"], f"{subject}.aliases")
    for offset, alias in enumerate(aliases):
        identifier(alias, f"{subject}.aliases[{offset}]")
    require(isinstance(value["releases"], list) and value["releases"], f"{subject}.releases must not be empty")
    for offset, release in enumerate(value["releases"]):
        field = f"{subject}.releases[{offset}]"
        release = exact(release, {"channel", "compatibility", "compatibility_sha256", "platforms", "version"}, field)
        semver(release["version"], f"{field}.version")
        require(release["channel"] in {"stable", "prerelease"}, f"{field}.channel is invalid")
        requirements = validate_requirements(release["compatibility"], f"{field}.compatibility")
        require(release["compatibility_sha256"] == fingerprint(requirements), f"{field}.compatibility_sha256 is stale")
        require(isinstance(release["platforms"], list) and release["platforms"], f"{field}.platforms must not be empty")
        if fragment:
            require(len(release["platforms"]) == 1, f"{field} fragment must contain one platform")
        seen: set[str] = set()
        for platform_index, platform in enumerate(release["platforms"]):
            platform = validate_platform(platform, f"{field}.platforms[{platform_index}]")
            require(platform["platform"] not in seen, f"{field} duplicates platform {platform['platform']}")
            seen.add(platform["platform"])
    return value


def core_profiles(catalog: Any) -> list[tuple[str, dict[str, Any], list[dict[str, Any]]]]:
    require(isinstance(catalog, dict) and catalog.get("schema_version") == 1 and isinstance(catalog.get("releases"), list), "Core catalog is invalid")
    profiles = []
    for offset, release in enumerate(catalog["releases"]):
        if release.get("channel") != "stable":
            continue
        subject = f"Core releases[{offset}]"
        semver(release.get("version"), f"{subject}.version")
        adapter = release.get("compatibility", {}).get("adapter_compatibility")
        require(isinstance(adapter, dict), f"{subject} lacks released adapter compatibility inventory")
        profile = exact(adapter.get("profile"), {"central_components", "core_capabilities", "core_schema_version", "format", "supported_adapter_protocol_epochs"}, f"{subject}.profile")
        require(profile["format"] == CORE_FORMAT, f"{subject}.profile format is unsupported")
        positive(profile["core_schema_version"], f"{subject}.profile.core_schema_version")
        sorted_unique(profile["supported_adapter_protocol_epochs"], f"{subject}.profile.supported_adapter_protocol_epochs")
        sorted_unique(profile["core_capabilities"], f"{subject}.profile.core_capabilities")
        components = sorted_unique(profile["central_components"], f"{subject}.profile.central_components", lambda item: item.get("namespace", ""))
        database = adapter.get("projected_database_components")
        require(isinstance(database, list), f"{subject}.projected_database_components must be an array")
        require([item.get("namespace") for item in components] == [item.get("namespace") for item in database], f"{subject} projected central component set is stale")
        profiles.append((release["version"], profile, database))
    require(bool(profiles), "Core catalog contains no stable compatibility-v2 profiles")
    return profiles


def compatible(requirements: dict[str, Any], adapter: str, profile: dict[str, Any], database: list[dict[str, Any]]) -> bool:
    if requirements["adapter_protocol_epoch"] not in profile["supported_adapter_protocol_epochs"]:
        return False
    if requirements["minimum_core_schema"] > profile["core_schema_version"]:
        return False
    if not set(requirements["required_core_capabilities"]) <= set(profile["core_capabilities"]):
        return False
    compiled = {item["namespace"]: item for item in profile["central_components"]}
    projected = {item["namespace"]: item for item in database}
    for requirement in requirements["central_components"]:
        component = compiled.get(requirement["namespace"])
        state = projected.get(requirement["namespace"])
        if component is None or state is None or component.get("owner_adapter") != adapter:
            return False
        if component.get("schema_epoch") != requirement["schema_epoch"] or state.get("schema_epoch") != requirement["schema_epoch"]:
            return False
        minimum = requirement["minimum_schema_version"]
        if component.get("schema_version", 0) < minimum or state.get("schema_version", 0) < minimum:
            return False
        lineage = {item.get("schema_version"): item.get("migration_digest") for item in component.get("lineage", [])}
        state_lineage = {item.get("schema_version"): item.get("migration_digest") for item in state.get("lineage", [])}
        digest = lineage.get(minimum)
        if digest not in requirement["accepted_lineage_digests"] or state_lineage.get(minimum) != digest:
            return False
    return True


def validate_index(index: Any, catalog: Any, require_platforms: bool = True) -> dict[str, Any]:
    index = exact(index, {"adapters", "schema_version"}, "adapter index")
    require(index["schema_version"] == 2, "publication only writes adapter index schema_version 2")
    require(isinstance(index["adapters"], list) and index["adapters"], "adapter index must contain products")
    profiles = core_profiles(catalog)
    latest = max(profiles, key=lambda item: semver(item[0], "Core version"))
    identities: set[str] = set()
    for adapter_index, product in enumerate(index["adapters"]):
        subject = f"adapters[{adapter_index}]"
        validate_product(product, subject)
        domain = product["domain"]
        for identity in [domain, *product["aliases"]]:
            require(identity not in identities, f"duplicate adapter identity {identity}")
            identities.add(identity)
        stable = [release for release in product["releases"] if release["channel"] == "stable"]
        require(bool(stable), f"{subject} has no stable compatibility-v2 release")
        current_matches = 0
        by_version: dict[str, list[dict[str, Any]]] = {}
        for release_index, release in enumerate(stable):
            field = f"{subject}.releases[{release_index}]"
            if require_platforms:
                actual = sorted(item["platform"] for item in release["platforms"])
                require(actual == list(PLATFORMS), f"{field} platform matrix differs: expected {list(PLATFORMS)}, got {actual}")
            matches = [version for version, profile, database in profiles if compatible(release["compatibility"], domain, profile, database)]
            require(bool(matches), f"{field} is incompatible with every released stable Core profile")
            if compatible(release["compatibility"], domain, latest[1], latest[2]):
                current_matches += 1
            by_version.setdefault(release["version"], []).append(release)
        require(current_matches > 0, f"{subject} has no release compatible with current stable Core {latest[0]}")
        for version, variants in by_version.items():
            if len(variants) < 2:
                continue
            for core_version, profile, database in profiles:
                matches = [item for item in variants if compatible(item["compatibility"], domain, profile, database)]
                require(len(matches) <= 1, f"{subject} version {version} has overlapping variants on Core {core_version}")
    return index


def release_keys(path: Path) -> dict[str, bytes]:
    value = exact(read_json(path), {"keys"}, str(path))
    require(isinstance(value["keys"], list) and value["keys"], f"{path}.keys must not be empty")
    keys: dict[str, bytes] = {}
    for offset, raw in enumerate(value["keys"]):
        item = exact(raw, {"key_id", "public_key"}, f"{path}.keys[{offset}]")
        key_id = text(item["key_id"], f"{path}.keys[{offset}].key_id")
        require(key_id not in keys, f"{path} duplicates key {key_id}")
        try:
            public_key = base64.b64decode(text(item["public_key"], f"{path}.keys[{offset}].public_key"), validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise GateError(f"{path} key {key_id} is not canonical base64") from error
        require(len(public_key) == 32, f"{path} key {key_id} must be an Ed25519 public key")
        keys[key_id] = public_key
    return keys


def verify_archive_signature(archive: Path, envelope: dict[str, Any], keys: dict[str, bytes]) -> None:
    key_id = envelope["key_id"]
    require(key_id in keys, f"{archive} signature names unknown key {key_id}")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise GateError(f"{archive} signature is not canonical base64") from error
    require(len(signature) == 64, f"{archive} Ed25519 signature must be 64 bytes")
    # SubjectPublicKeyInfo prefix for an RFC 8410 Ed25519 raw public key.
    der = bytes.fromhex("302a300506032b6570032100") + keys[key_id]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        der_path, pem_path, signature_path = root / "key.der", root / "key.pem", root / "signature.raw"
        der_path.write_bytes(der)
        signature_path.write_bytes(signature)
        try:
            subprocess.run(
                ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(der_path), "-out", str(pem_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(pem_path), "-in", str(archive), "-sigfile", str(signature_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise GateError(f"{archive} detached Ed25519 signature did not verify") from error


def archive_sidecar(archive: Path, root: str) -> tuple[dict[str, Any], str]:
    with tarfile.open(archive, "r:gz") as bundle:
        expected = f"{root}/adapter-compatibility.json"
        try:
            member = bundle.getmember(expected)
        except KeyError as error:
            raise GateError(f"{archive} is missing {expected}") from error
        require(member.isfile() and member.size <= 256 * 1024, f"{archive} compatibility sidecar is invalid")
        source = bundle.extractfile(member)
        require(source is not None, f"{archive} compatibility sidecar is unreadable")
        raw = source.read()
    try:
        sidecar = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"{archive} compatibility sidecar is invalid: {error}") from error
    validate_sidecar(sidecar, f"{archive} sidecar")
    return sidecar, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def emit(args: argparse.Namespace) -> None:
    sidecar = validate_sidecar(read_json(args.sidecar), str(args.sidecar))
    require(sidecar["adapter"] == args.domain, "sidecar adapter does not match release domain")
    aliases = sorted(filter(None, args.alias.split(",")))
    product: dict[str, Any] = {
        "aliases": aliases,
        "classification": args.classification,
        "domain": args.domain,
        "primary_namespace": args.domain,
        "releases": [{
            "channel": args.channel,
            "compatibility": sidecar["compatibility"],
            "compatibility_sha256": fingerprint(sidecar["compatibility"]),
            "platforms": [{
                "archive_root": args.archive_root,
                "asset_url": args.asset_url,
                "binary": args.binary,
                "platform": args.platform,
                "resource_manifest": args.resource_manifest,
                "sha256": args.sha256,
                "signature_url": args.signature_url,
                "signing_key_id": args.signing_key_id,
            }],
            "version": args.version,
        }],
        "title": args.title,
    }
    if args.source_url:
        product["source_url"] = args.source_url
    validate_product(product, "generated product", fragment=True)
    fragment = {
        "format": FRAGMENT_FORMAT,
        "product": product,
        "sidecar_sha256": f"sha256:{hashlib.sha256(args.sidecar.read_bytes()).hexdigest()}",
    }
    args.output.write_text(json.dumps(fragment, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def merge(args: argparse.Namespace) -> None:
    fragments = []
    for path in args.fragment:
        value = exact(read_json(path), {"format", "product", "sidecar_sha256"}, str(path))
        require(value["format"] == FRAGMENT_FORMAT, f"{path} has unsupported fragment format")
        require(DIGEST.fullmatch(value["sidecar_sha256"]) is not None, f"{path} sidecar digest is invalid")
        validate_product(value["product"], f"{path}.product", fragment=True)
        fragments.append(value)
    require(bool(fragments), "no adapter release fragments supplied")
    products: dict[tuple[Any, ...], dict[str, Any]] = {}
    digests: dict[tuple[Any, ...], str] = {}
    for fragment in fragments:
        product = fragment["product"]
        release = product["releases"][0]
        product_identity = canonical_json({key: value for key, value in product.items() if key != "releases"})
        key = (product["domain"], release["version"], release["channel"], release["compatibility_sha256"])
        if key not in products:
            products[key] = json.loads(json.dumps(product))
            digests[key] = fragment["sidecar_sha256"]
        else:
            existing = products[key]
            existing_identity = canonical_json({name: value for name, value in existing.items() if name != "releases"})
            require(existing_identity == product_identity, f"fragment product metadata differs for {key}")
            require(digests[key] == fragment["sidecar_sha256"], f"fragment sidecars differ for {key}")
            existing["releases"][0]["platforms"].extend(release["platforms"])
    grouped: dict[str, dict[str, Any]] = {}
    for key in sorted(products):
        product = products[key]
        release = product["releases"][0]
        release["platforms"].sort(key=lambda item: item["platform"])
        domain = product["domain"]
        if domain not in grouped:
            grouped[domain] = product
        else:
            grouped[domain]["releases"].append(release)
    if args.existing_index:
        existing = validate_index(
            read_json(args.existing_index), read_json(args.core_catalog), require_platforms=True
        )
        for existing_product in existing["adapters"]:
            domain = existing_product["domain"]
            if domain not in grouped:
                grouped[domain] = existing_product
                continue
            candidate_product = grouped[domain]
            existing_identity = canonical_json(
                {name: value for name, value in existing_product.items() if name != "releases"}
            )
            candidate_identity = canonical_json(
                {name: value for name, value in candidate_product.items() if name != "releases"}
            )
            require(existing_identity == candidate_identity, f"published product metadata differs for {domain}")
            candidate_keys = {
                (item["version"], item["channel"], item["compatibility_sha256"])
                for item in candidate_product["releases"]
            }
            retained = [
                item
                for item in existing_product["releases"]
                if (item["version"], item["channel"], item["compatibility_sha256"])
                not in candidate_keys
            ]
            candidate_product["releases"].extend(retained)
    for product in grouped.values():
        product["releases"].sort(key=lambda item: (semver(item["version"], "version"), item["compatibility_sha256"]), reverse=True)
    index = {"adapters": [grouped[key] for key in sorted(grouped)], "schema_version": 2}
    validate_index(index, read_json(args.core_catalog), require_platforms=True)
    if args.archives:
        require(args.keyring is not None, "--archives requires --keyring for detached signature verification")
        keys = release_keys(args.keyring)
        for product in index["adapters"]:
            for release in product["releases"]:
                key = (product["domain"], release["version"], release["channel"], release["compatibility_sha256"])
                if key not in digests:
                    continue
                for platform in release["platforms"]:
                    archive = args.archives / PurePosixPath(platform["asset_url"]).name
                    signature_path = Path(f"{archive}.sig")
                    require(archive.is_file(), f"missing staged archive {archive}")
                    require(signature_path.is_file(), f"missing staged archive signature {signature_path}")
                    envelope = exact(read_json(signature_path), {"algorithm", "key_id", "signature"}, str(signature_path))
                    require(envelope["algorithm"] == "Ed25519", f"{signature_path} does not use Ed25519")
                    require(envelope["key_id"] == platform["signing_key_id"], f"{signature_path} signing key differs from fragment")
                    text(envelope["signature"], f"{signature_path}.signature")
                    verify_archive_signature(archive, envelope, keys)
                    raw_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                    require(raw_digest == platform["sha256"], f"{archive} checksum differs from fragment")
                    sidecar, sidecar_digest = archive_sidecar(archive, platform["archive_root"])
                    require(sidecar_digest == digests[key], f"{archive} packages a stale sidecar")
                    require(sidecar["adapter"] == product["domain"] and sidecar["compatibility"] == release["compatibility"], f"{archive} sidecar differs from indexed compatibility")
    args.output.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate(args: argparse.Namespace) -> None:
    validate_index(read_json(args.index), read_json(args.core_catalog), require_platforms=not args.allow_partial_platforms)
    print(f"adapter catalog compatibility gate passed: {args.index}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    command = commands.add_parser("emit")
    command.add_argument("--sidecar", type=Path, required=True)
    for name in ("domain", "title", "classification", "version", "channel", "platform", "asset-url", "archive-root", "binary", "sha256", "signature-url", "signing-key-id"):
        command.add_argument(f"--{name}", required=True)
    command.add_argument("--alias", default="")
    command.add_argument("--source-url")
    command.add_argument("--resource-manifest", default="adapter-resources.json")
    command.add_argument("--output", type=Path, required=True)
    command.set_defaults(run=emit)
    command = commands.add_parser("merge")
    command.add_argument("--fragment", type=Path, action="append", required=True)
    command.add_argument("--core-catalog", type=Path, required=True)
    command.add_argument("--existing-index", type=Path)
    command.add_argument("--archives", type=Path)
    command.add_argument("--keyring", type=Path)
    command.add_argument("--output", type=Path, required=True)
    command.set_defaults(run=merge)
    command = commands.add_parser("validate")
    command.add_argument("--index", type=Path, required=True)
    command.add_argument("--core-catalog", type=Path, required=True)
    command.add_argument("--allow-partial-platforms", action="store_true")
    command.set_defaults(run=validate)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.run(args)
        return 0
    except (GateError, OSError, tarfile.TarError) as error:
        print(f"adapter release metadata error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
