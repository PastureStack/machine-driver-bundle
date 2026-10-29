# Reviewed source patches

All patches are applied with zero fuzz to immutable, SHA-256-pinned upstream source archives.

- `docker-machine-go-security.patch` replaces EOL cloud and Docker clients with their maintained APIs. Its reviewed runtime changes are limited to the CLI compatibility layer (including normalized string-slice RPC values), AWS EC2, Azure, Exoscale, vSphere, Docker client wiring, and the corresponding module locks and tests.
- `packet-driver-go-security.patch` updates the retired provider's dependencies and replaces its machine library with the sibling, reviewed source tree used for the primary executable.

The build verifies the resulting `go.mod` and `go.sum` files against fixed hashes before downloading modules. `scripts/validate` enforces an exact path boundary for the primary patch and keeps the retired provider patch limited to `go.mod` and `go.sum`.

The external source tags retain their upstream spelling for provenance. The PastureStack bundle and both rebuilt executables expose only the numeric candidate version `0.16.6`.

The `docker-machine-xnet062.patch` and `packet-driver-xnet062.patch` follow the existing security patches and only change `go.mod`/`go.sum`. They select official x/net 0.62.0 and the minimum Go module dependency closure for CVE-2026-78661 and CVE-2026-97045; provider and transport implementation code is unchanged.
