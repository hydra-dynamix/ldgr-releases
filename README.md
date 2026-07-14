# LDGR Releases

Public binary release distribution repository for LDGR Core and its open-source
and commercial adapters.

## Current coherent database release

The current stable adapter set is built against database contract
`sha256:2d59299bf0738de94997d0f58e104b0de321800064f99d6391f2bdadabf2fc6c`
and published under
[`database-contract-2d59299bf073`](https://github.com/hydra-dynamix/ldgr-releases/releases/tag/database-contract-2d59299bf073).

The release contains native binaries for Linux x86_64, Linux ARM64, and Windows
x86_64. Every archive has a SHA-256 checksum and an Ed25519 detached signature.
All adapters in `index.json` identify the same database contract and require
LDGR Core 0.1.9 or newer within the 0.1 release family.

`release-keyring.json` contains the offline public keys trusted by LDGR Core
when verifying detached signatures. `index.json` is the canonical adapter
catalog consumed by `ldgr adapter install <adapter>`.

This repository must contain release metadata and binary assets only. Commercial adapter source code must not be published here.
