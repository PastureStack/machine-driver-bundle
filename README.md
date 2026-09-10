# Machine Driver Bundle

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

This repository builds the Linux AMD64 machine-management bundle consumed by
the PastureStack compatibility server. The current public GitHub Release is
[`v0.16.4`](https://github.com/PastureStack/machine-driver-bundle/releases/tag/v0.16.4),
and the generated archive and both rebuilt executables use numeric version
`0.16.4` without a product or maintenance suffix.

## Reviewed inputs

- Docker Machine is rebuilt from GitLab's maintained fork at upstream source tag `v0.16.2-gitlab.52`, commit `95d190cbe55757b4212b69d0a278151d1faaaf66`. That external tag is recorded only as an immutable source coordinate.
- The compatibility provider is rebuilt from Equinix's final release `0.6.0`, commit `1579a8271d52e00760e38dd153d3935abc302915`, with the protocol-compatible binary name `docker-machine-driver-packet`.
- Both binaries are built with Go `1.27.0`. The zero-fuzz source patch migrates the linked cloud clients to maintained SDKs, including AWS SDK v2 and Azure Track 2 with managed disks; resulting `go.mod` and `go.sum` hashes are locked.

The official GitLab checksum manifest is verified with its release signature and the exact GitLab signing-key fingerprint before any source is built. Source archives, licenses, patched module files, and output binaries are independently SHA-256 pinned.

## Retired provider boundary

Equinix Metal ended service on June 30, 2026 and removed resource creation on July 1, 2026. The `packet` provider remains in this bundle only so an existing configuration can be inspected or rolled back without losing its expected plugin binary.

New installation is disabled by policy. The bundle records that policy in `provider-lifecycle.json`; the web console excludes Packet from new-host choices and host-provisioner rejects direct create requests. The binary remains only for inspecting or rolling back an existing configuration.

## Security and licensing

The build rejects unexpected archive paths, links, signatures, checksums, source-patch drift, module-lock drift, local path leakage, binary-format drift, and version drift. Dependency-license collection can read only from the two reviewed source trees or the active Go module cache, rejects path and symlink escapes, and renders only to standard output so it cannot overwrite a caller-selected path. Tests cover the complete upstream non-command package set, core race-detector coverage, provider race-detector coverage, CLI behavior, provider protocol discovery, malicious license-path fixtures, and byte-identical packaging.

The OpenVEX document is restricted to the sole module-level scanner warning: the unmaintained `x/crypto/openpgp` package is not imported by either command and has no reachable package or function trace in source-mode `govulncheck`.

The archive includes the Go standard-library license, both upstream project licenses, and every license or notice file belonging to a Go module actually linked into either binary. PastureStack's MIT license applies only to this repository's independently written packaging code and documentation.

## Build

```sh
make validate
make package
make test
```

Output:

```text
dist/artifacts/machine-driver-bundle-0.16.4-linux-amd64.tar.xz
```

Artifacts built directly from a checkout are review candidates. A GitHub Release, when present, is the reviewed distribution and its package is covered by GitHub Artifact Attestation generated from the protected default branch. Catalog changes, container-registry changes, and deployment remain intentionally excluded from this workflow.
