# Wave 16.1 hardening contract

Release 0.4.1 fixes the reviewed signed-append and verifier issues. The source, tests and evidence are linked from the current validation report. Existing finite Wave 14 digest bytes, Wave 16 receipt schema and evaluation-only license terms are preserved.

## Signed append and recovery

The previous implementation loaded and verified every existing receipt twice for each append inside `BEGIN IMMEDIATE`. Growing a stream therefore required quadratic cumulative verification work and kept SQLite's writer lock during signing.

The new implementation keeps a private replay-derived head, sequence, receipt IDs, consumed authorization claims and unresolved authorizations. It reconstructs this state by verifying every persisted signed receipt on startup. No unsigned database head or cache metadata establishes trust. The signed receipt chain is the durable recovery record; the acceleration cache is deliberately process-local rather than an independently trusted database table.

A normal append validates one signed receipt and its sequence/predecessor, checks unique claim consumption or its earlier unresolved authorization, then commits the receipt. State advances only after commit. Signed parsed bodies are detached from caller-owned return data. The same transition validator is used by independent full replay, so append and audit do not have separate semantic rules.

One persistent SQLite connection, protected by an `RLock`, observes `PRAGMA data_version`. SQLite generation values are compared only on that connection. Any commit from another connection invalidates the cache and causes conservative full replay, including database index/payload consistency. A changed public trust policy also triggers replay, preserving current revocation behavior. Observed truncation or replacement of the verified prefix is refused. A new store without an independently retained checkpoint cannot establish latestness of a valid historical snapshot.

Preparation/recovery uses a read snapshot. That transaction ends before calling the signer. A short `BEGIN IMMEDIATE` checks the generation and trust-policy fingerprint before insertion. If another writer or a policy change intervened, the signed candidate is discarded and the operation restarts; after 16 conflicts it refuses the append. Refusal propagates through the existing fail-closed gateway behavior. No unsigned fallback is added. Readiness audit and export remain independent full replays.

**Fast-path scope:** one long-lived store per stream, with concurrent callers serialized in that store. External writers, including evidence-claim changes from other connections, conservatively cause full replay. This protects historical-tamper detection; it does not solve sustained multiprocess throughput. Multiple independent stores are tested for correctness, not production scaling. Replay and verification-state memory still grow with stream length. HA, process failover and power-loss campaigns remain unvalidated. Call `close()` when releasing a signed store, particularly before deleting its database on Windows. Do not reuse SQLite connections across a process fork.

The benchmark compares the uploaded original append and verifier sources with the current sources under the same Python, signer, payload and storage conditions. Preserved original source texts and SHA-256 values are included. It uses real Ed25519 signatures and temporary SQLite WAL databases with `synchronous=FULL`. Each sample is 25 consecutive appends after reaching the stated receipt count. It measures minimal pre-evaluation denials, not full governed-call latency or cloud-signing throughput. Full audit is separately checked. Timings are observations, not CI thresholds; the 1,000-append regression instead fails deterministically if normal append reads full history.

```powershell
.\.venv\Scripts\python.exe scripts/benchmark_wave16_append.py --baseline-source validation/wave16_1/baseline-source/receipts.py.txt --baseline-verifier validation/wave16_1/baseline-source/verification.py.txt --output .blackfox-artifacts/wave16/append-benchmark.json
```

## Checkpoint prefixes

The bundle's own signed checkpoint must match its entire receipt list. An independently retained checkpoint at N must match the bundle's first N receipts, including their attestations, sequence, head digest and list digest. The complete stream is still verified. A shorter bundle, signed fork, malformed count (including booleans) or different trust domain is rejected. An empty retained checkpoint authenticates an empty prefix only. A matching older checkpoint establishes continuity from that prefix; it cannot establish that no newer receipts exist elsewhere.

## Denial semantics

Evaluated denials now use the full subject/decision digest, schema, principal and evidence consistency checks. Their decision must have `allowed=false` and status `block`, `review_required` or `evidence_required`. The decision subject must equal the receipt subject. They cannot claim dispatch, execution, an upstream response or authorization-consumed evidence.

Pre-evaluation failures cannot supply a fully evaluated subject or authenticated principal. Their existing historical shape remains supported with exact minimal subject fields (`agent_id`, `tool_name`) and decision fields (`status`, `reason_codes`), status `block`, nonempty string reason codes, and empty principal/evidence/claims. Adding an allowed decision, digest-bearing partial subject or fabricated authenticated context fails. These records describe failed evaluation, not a completed identity/evidence evaluation.

## Two explicit encoding profiles

Wave 14 subject, decision, principal-context and evidence-claim digests retain the **legacy ASCII-escaped Python JSON profile**: sorted string keys in Unicode code-point order, compact comma/colon separators, `ensure_ascii=True`, UTF-8 encoded output and Python JSON numeric spelling. Non-ASCII characters use lowercase `\u` escapes; astral characters use a surrogate pair. Finite number bytes are unchanged. NaN and positive/negative infinity now fail, including when nested.

Wave 16 receipt/list/statement digests use **BlackFox canonical JSON profile v1**: the same compact ordering, `ensure_ascii=False`, UTF-8, finite numbers, no unpaired surrogates and integer values within ±(2^53−1). Neither profile is RFC 8785. Float spelling follows Python 3.11+ JSON, including `1.0`, `-0.0` and exponent formatting. Legacy code outside Wave 16 may digest larger integers or escaped surrogates; Wave 16's strict envelope validation excludes those values. No Unicode normalization is performed; composed and decomposed strings are distinct.

The DSSE signature authenticates its embedded payload bytes. Digest and canonical-form checks still require the specified profiles. `examples/wave16/canonicalization-vectors.json` fixes exact hexadecimal bytes and SHA-256 digests for Unicode, astral characters, escapes, nested values, numeric bounds and float cases under both profiles. Cross-language implementations must reproduce these vectors and the documented profiles; this release does not claim a separately implemented cross-language verifier.

Human approval is still HMAC-authenticated evidence, with synthetic reviewers in the demo. It is not an independently attributable personal public-key signature. No AWS/HSM/Sigstore live validation, deployment authorization, certification or production readiness is inferred from this hardening release.
