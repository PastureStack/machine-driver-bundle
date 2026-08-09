# Reviewed source patches

Both patches are applied with zero fuzz to immutable, SHA-256-pinned upstream source archives.

- `docker-machine-go-security.patch` updates the Go toolchain declaration and security-sensitive dependencies without changing runtime business logic.
- `packet-driver-go-security.patch` updates the retired provider's dependencies and replaces its machine library with the sibling, reviewed source tree used for the primary executable.

The build verifies the resulting `go.mod` and `go.sum` files against fixed hashes before downloading modules. A patch may touch only those two files; `scripts/validate` enforces that boundary.

The external source tags retain their upstream spelling for provenance. The PastureStack bundle and both rebuilt executables expose only the numeric candidate version `0.16.4`.
