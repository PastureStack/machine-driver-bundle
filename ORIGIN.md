# Origin and maintenance boundary

## Independent packaging implementation

The historical functional predecessor is `rancher/machine-package` tag `v0.14.0`, commit `8e2495c95a11c610f9c791fb8be65b981fb7e657`. That source tree has no root or nested license file. PastureStack therefore does not fork, copy, or modify its source or build scripts.

This repository starts with an independent root commit and implements only the observable package contract required by the compatibility server: a deterministic Linux AMD64 archive containing `docker-machine` and the provider plugin name expected by existing configurations.

## Licensed source inputs

The primary executable is rebuilt from the Apache-2.0-licensed GitLab Docker Machine fork. The compatibility provider is rebuilt from the BSD-3-Clause-licensed Equinix source. Exact URLs, commits, external source tags, archive hashes, signing evidence, patched module hashes, and binary hashes are fixed in `sources.lock.env`.

The upstream tag `v0.16.2-gitlab.51` is retained verbatim only because changing an external source coordinate would destroy provenance. It is not a PastureStack version. The bundle's version is `0.16.4`.

The preserved executable names are protocol identifiers required by the server and plugin discovery. They are not branding or a claim that PastureStack authored the upstream projects.

## Patch boundary

PastureStack patches only `go.mod` and `go.sum` in the downloaded source trees. The build enforces this file boundary, applies patches with zero fuzz, verifies the resulting hashes, and records the complete linked-module license set in each archive.
