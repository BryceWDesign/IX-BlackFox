# Apply and verify 0.5.0 on Windows

The source archive contains the full project and no Git metadata. Preserve your existing checkout's `.git` directory and history. Keep a clean backup or commit of your current work before applying a release.

1. Extract the release into a separate directory.
2. In your existing checkout, inspect `git status` and preserve existing changes.
3. Copy the release contents into the checkout, including `.github` and `.gitignore`. Preserve your `.git`, virtual environment, credentials and operational databases. The source package `src/ix_blackfox/runtime` must remain tracked.
4. Remove obsolete release-instruction files and old wheels after reviewing `FILE_MANIFEST.json`, which lists the complete source release. Preserve local operational state.
5. Run the following commands separately in PowerShell. Use an existing compatible virtual environment or create one with the first command.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,aws-kms]"
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/run_wave16_crypto_authority_ci.py --root .
.\.venv\Scripts\python.exe scripts/run_wave17_integration_mesh_ci.py --root .
```

Every command must succeed. The Wave 17 proof must report `passed: true`. Consult `VALIDATION_REPORT.md` for the measured release environment and counts. The AWS extra supplies the SDK for contract tests; these local proofs do not call live AWS, GitHub, Jira or SIEM services.

Use the existing remote and branch after reviewing your diff:

```powershell
git diff --check
git diff --stat
git status
git remote -v
git add -A
git commit -m "Release v0.5.0 Wave 17 enterprise integration mesh"
git push origin main
```

Confirm that `origin` and `main` identify the intended repository and branch. The dedicated **Wave 17 Enterprise Integration Mesh** workflow runs on Ubuntu and Windows across Python 3.11–3.13. Its remote results become available after the push; local Linux validation does not establish Windows execution.

The configuration in `examples/wave17` is an operator template. Generate your own signing keys, provision separate credentials, replace example destinations and supply valid evidence before operating real service routes. The automated proof creates temporary local credentials and removes them afterward. Captured public proof artifacts are validation fixtures, not operational trust roots.
