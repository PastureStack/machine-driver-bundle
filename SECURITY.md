# Security policy

Please report suspected vulnerabilities through GitHub private vulnerability reporting for this repository. Do not place credentials, provider tokens, private addresses, or production configuration in a public issue.

Every source and metadata input is fixed by URL and SHA-256. The GitLab release checksum manifest must also pass GPG verification with fingerprint `931DA69CFA3AFEBBC97DAA8C6C57C29C6BA75A4E`.

The manual security gate requires:

- full upstream tests and selected race-detector suites;
- provider protocol and CLI smoke tests;
- byte-identical package reproduction;
- exact govulncheck symbol findings validated against reviewed code paths;
- Trivy secret, dependency, artifact, and SBOM checks;
- exact OpenVEX products and justifications;
- license evidence for every linked Go module.
- dependency-license reads restricted to the reviewed source trees or Go module cache, with stdout-only rendering and no caller-selected output path.
- protected-default-branch build provenance recorded with GitHub Artifact Attestation before release publication.

Any new reachable finding, unexpected module-only finding, missing license, checksum mismatch, signature mismatch, dependency-graph expansion into Docker server code, or non-numeric candidate version fails the gate.

The `packet` provider is retired and cannot be security-tested against the discontinued external service. Its local protocol and unit behavior remain tested; real provider operation is not claimed.
