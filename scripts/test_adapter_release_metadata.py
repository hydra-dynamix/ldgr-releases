#!/usr/bin/env python3
"""Isolation tests for compatibility-v2 catalog publication tooling."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("adapter-release-metadata.py")
SPEC = importlib.util.spec_from_file_location("adapter_release_metadata", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class CatalogGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compatibility = {
            "adapter_protocol_epoch": 1,
            "central_components": [],
            "minimum_core_schema": 5,
            "required_core_capabilities": ["work.v1"],
        }
        self.platforms = [
            {
                "archive_root": "research-0.1.6",
                "asset_url": f"https://example.invalid/research-0.1.6-{platform}.tar.gz",
                "binary": "ldgr-research.exe" if platform.startswith("windows") else "ldgr-research",
                "platform": platform,
                "resource_manifest": "adapter-resources.json",
                "sha256": "a" * 64,
                "signature_url": f"https://example.invalid/research-0.1.6-{platform}.tar.gz.sig",
                "signing_key_id": "fixture-key",
            }
            for platform in TOOL.PLATFORMS
        ]
        self.index = {
            "adapters": [
                {
                    "aliases": [],
                    "classification": "open_source",
                    "domain": "research",
                    "primary_namespace": "research",
                    "releases": [
                        {
                            "channel": "stable",
                            "compatibility": self.compatibility,
                            "compatibility_sha256": TOOL.fingerprint(self.compatibility),
                            "platforms": self.platforms,
                            "version": "0.1.6",
                        }
                    ],
                    "title": "Research adapter",
                }
            ],
            "schema_version": 2,
        }
        self.catalog = {
            "schema_version": 1,
            "release_keys": [],
            "releases": [self.core_release("0.1.14", 5), self.core_release("0.1.15", 6)],
        }

    @staticmethod
    def core_release(version: str, schema: int) -> dict:
        return {
            "version": version,
            "channel": "stable",
            "compatibility": {
                "adapter_compatibility": {
                    "profile": {
                        "central_components": [],
                        "core_capabilities": ["prompt.v1", "telemetry.v1", "work.v1"],
                        "core_schema_version": schema,
                        "format": "ldgr.core-compatibility.v2",
                        "supported_adapter_protocol_epochs": [1],
                    },
                    "projected_database_components": [],
                    "legacy_profile": {},
                }
            },
        }

    def test_core_patch_and_additive_schema_need_no_adapter_edit(self) -> None:
        TOOL.validate_index(self.index, self.catalog)
        self.assertEqual(self.index["adapters"][0]["releases"][0]["compatibility"]["minimum_core_schema"], 5)

    def test_missing_platform_is_rejected(self) -> None:
        self.index["adapters"][0]["releases"][0]["platforms"].pop()
        with self.assertRaisesRegex(TOOL.GateError, "platform matrix differs"):
            TOOL.validate_index(self.index, self.catalog)

    def test_incompatible_capability_is_rejected(self) -> None:
        release = self.index["adapters"][0]["releases"][0]
        release["compatibility"]["required_core_capabilities"] = ["work.v2"]
        release["compatibility_sha256"] = TOOL.fingerprint(release["compatibility"])
        with self.assertRaisesRegex(TOOL.GateError, "every released stable Core"):
            TOOL.validate_index(self.index, self.catalog)

    def test_handwritten_patch_range_is_rejected(self) -> None:
        release = self.index["adapters"][0]["releases"][0]
        release["core_compatibility"] = ">=0.1.14, <0.1.15"
        with self.assertRaisesRegex(TOOL.GateError, "fields differ"):
            TOOL.validate_index(self.index, self.catalog)

    def test_stale_fingerprint_is_rejected(self) -> None:
        self.index["adapters"][0]["releases"][0]["compatibility_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(TOOL.GateError, "is stale"):
            TOOL.validate_index(self.index, self.catalog)


if __name__ == "__main__":
    unittest.main()
