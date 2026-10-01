# Apply and verify Wave 16.1 on Windows

This ZIP is the complete 0.4.1 source release. It contains no `.git` directory. Keep your existing repository's `.git` directory and Git history.

1. Extract the ZIP into a new directory. Keep the earlier release until this one is verified.
2. In your existing IX-BlackFox Git checkout, run `git status`. Commit or preserve any existing local changes before applying the release.
3. Copy the extracted release's contents into that existing checkout, including `.github`, `.gitignore` and the other project files. Do not replace `.git` or your existing `.venv`. No original project source file is removed by this release. Old 0.4.0 wheels, if present locally, are historical; use the delivered 0.4.1 wheel.
4. Open PowerShell in that checkout and run each command separately. Continue only if it succeeds.

```powershell
# Create this only if the checkout has no .venv yet:
py -3.13 -m venv .venv

.\.venv\Scripts\python.exe -m pip install -e ".[dev,aws-kms]"
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/run_wave16_crypto_authority_ci.py --root .
```

Expected suite: 1,784 passing tests. The AWS extra supplies boto3 for the local API contract test; it does not contact live AWS. Expected live proof: `passed: true`, 17 checks, 9 signed receipts and 2 witnessed writes. Ruff and strict mypy must pass. Timings vary by machine.

Inspect and push only after the local checks pass:

```powershell
git diff --check
git diff --stat
git status
git remote -v
git add -A
git commit -m "Release v0.4.1 Wave 16.1 ledger and verifier hardening"
git push origin main
```

The final command assumes your checked-out branch is `main` and `origin` points to your IX-BlackFox repository; confirm those with `git status` and `git remote -v`. Do not force-push. This handoff does not create a remote commit or overwrite your remote repository.

Wait for GitHub's workflows, particularly **Wave 16 Cryptographic Authority** on Ubuntu/Windows and Python 3.11/3.12/3.13. Local Linux results do not certify Windows execution or remote CI. Preserve `.blackfox-artifacts/wave16` as local proof output; it is ignored by Git. The delivered evidence snapshots are independently reproducible demo artifacts, not production trust fixtures.
