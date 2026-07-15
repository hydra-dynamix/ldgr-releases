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

This repository must contain release metadata and binary assets only. Commercial adapter source code must not be published here.
