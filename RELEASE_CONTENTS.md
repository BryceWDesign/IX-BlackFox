# IX-BlackFox 0.5.0 release contents

This source release implements Wave 17 Enterprise Integration Mesh and retains the existing authority, identity, evidence, runtime and verification layers. It includes source, tests, examples, public schemas, protocol/operator documentation, GitHub workflows and captured local validation evidence. License, notice and commercial terms retain their original bytes.

`FILE_MANIFEST.json` hashes every packaged file except itself. The source archive excludes Git metadata, private signing keys, credentials, runtime databases, virtual environments, caches and build directories. A clean wheel build and installed-package smoke checks are recorded in `VALIDATION_REPORT.md`.

- Integration contract: `docs/wave17-enterprise-integration-mesh.md`
- Claim-to-test mapping: `docs/wave17-claims-ledger.json`
- Operator template: `examples/wave17/blackfox.gateway.toml`
- Reproducible network proof: `scripts/run_wave17_integration_mesh_ci.py`
- Validation results: `VALIDATION_REPORT.md` and `validation/wave17`
- Windows application and verification: `WINDOWS_SETUP.md`
- Roadmap through Wave 20: `docs/ROADMAP.md`

Historical Wave 16/16.1 measurements remain under their versioned validation directories and are not presented as new release measurements. Hosted services, production capacity, high availability and remote GitHub Actions outcomes are not established by the local release results.
