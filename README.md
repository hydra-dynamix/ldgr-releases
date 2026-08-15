# LDGR Releases

Public binary release distribution repository for LDGR Core and its open-source
and commercial adapters.

## Current coherent database release

The current stable adapter set is built against Core schema v2 and database
contract `sha256:7e177ee30c2eff7801d30d2f787e59daa24cbfe0eceff4e98bb442058e288aa3` and published under
[`database-contract-7e177ee30c2-r2`](https://github.com/hydra-dynamix/ldgr-releases/releases/tag/database-contract-7e177ee30c2-r2).

The release contains native binaries for Linux x86_64, Linux ARM64, and Windows
x86_64. Every archive has a SHA-256 checksum and an Ed25519 detached signature.
All adapters in `index.json` identify the same database contract and require
LDGR Core 0.1.11 or newer within the 0.1 release family. Revision 2 includes
the backed-up schema-v1 migration fix in Core and in adapters linked to Core.

`release-keyring.json` contains the offline public keys trusted by LDGR Core
when verifying detached signatures. `index.json` is the canonical adapter
catalog consumed by `ldgr adapter install <adapter>`.

## Compatibility-v2 publication

The schema-v1 catalog above is read-only legacy state. New adapter releases are
published only as a complete schema-v2 candidate:

1. each platform workflow emits an `ldgr.adapter-release-fragment.v2` envelope
   from its generated `adapter-compatibility.json` sidecar;
2. `.github/workflows/publish-adapter-catalog.yml` verifies all five archives,
   signatures, checksums, embedded sidecars, and platform entries;
3. every stable variant is evaluated against every stable compatibility profile
   in the signed Core catalog, including overlap checks for same-version
   variants; and
4. the draft release is made available before one commit atomically replaces
   `index.json` and `index.json.sig`. The catalog commit is the client activation
   point, so clients never observe metadata for unavailable assets.

`core_compatibility` package-version ranges are forbidden in schema v2. Core
patches and additive schemas require no adapter metadata edit; selection uses
protocol epochs, minimum Core schema, capabilities, and registered central
components generated from reviewed descriptors.

This repository must contain release metadata and binary assets only. Commercial adapter source code must not be published here.
