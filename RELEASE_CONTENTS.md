# IX-BlackFox 0.7.0 release contents

The source archive includes Wave 19 Closed-Loop Verification, the preceding authority and integration layers, tests, examples, schemas, GitHub workflows and release validation. The evaluation license, notice, commercial terms and original logo retain their supplied bytes.

| Item | Location |
| --- | --- |
| Verification protocol and operator procedures | `docs/wave19-closed-loop-verification.md` |
| Runnable quota service and independent collectors | `examples/wave19` |
| Failure, replay, restart, concurrency and verifier regressions | `tests/autonomy/test_verification.py` |
| Linux and Windows workflow | `.github/workflows/wave19-closed-loop-verification.yml` |
| Local results, public proof and release audit | `VALIDATION_REPORT.md`, `validation/wave19` |
| Windows application instructions | `WINDOWS_SETUP.md` |
| Roadmap | `docs/ROADMAP.md` |

`FILE_MANIFEST.json` hashes every packaged file except itself. The source archive excludes Git metadata, live credentials, private signing keys, operational databases, build directories and caches.
