# Wave 19 release audit

The audit used a detached source checkout, a separately installed wheel and the exported public proof. The offline verifier ran in a separate interpreter without gateway access. The artifact audit recomputed the reported outcomes from the raw collector outputs and compared eight outputs with their signed SHA-256 values and targets.

| Release claim | Executable check | Result |
| --- | --- | --- |
| Requirements, change, plan, approval and execution are linked | `authorization` in `verification/proof.py` and the installed-wheel bundle verification | The receipt matched the retained plan, operation, review digest, step, request ID and scope |
| Provider acknowledgement is insufficient | `examples/wave19/run.py` and the quota-20 proof | The provider returned HTTP 200. The read-only collector saw 10 against required quota 20. Verified closure was rejected |
| Test and simulation criteria are mandatory when present | `test_independent_closure_requires_every_source_and_pins_signed_bundle` and `test_offline_verifier_recomputes_requirements_even_with_valid_closure_signature` | The online and offline paths rejected incomplete evidence |
| Wrong-source, forged, replayed, stale and conflicting evidence cannot confer verification | `test_evidence_rejection`, `test_epoch_renewal_rejects_old_proof_and_requires_fresh_read`, `test_expired_valid_proofs_cannot_close_and_are_visible_in_unresolved_queue` and `test_dependencies_and_conflicts_remain_blocked_across_restart` | The operations stayed pending or failed, and dependent dispatch or closure was blocked |
| A transport failure does not cause another write | `test_ambiguous_provider_write_survives_gateway_restart_and_real_read` | Exactly one provider write was retained and verified after restart using a separate HTTP read |
| Recovery has its own authority, tests and final decision | Quota rollback proof, both `test_failure_followup_uses_new_authority_and_inherited_criteria` cases and `test_parallel_followup_approval_selects_one_and_failed_rollback_cannot_close_verified` | Recovery restored quota 8 in the live example. Competing approval and a mismatching rollback were blocked |
| Signed closures can be checked without gateway state | Installed `blackfox verification verify`, followed by `audit_proof.py` against the public bundles | The original operation and the rollback chain were verified, and all retained artifact digests matched |

The release archive was checked against its file manifest and the supplied Wave 18 archive. The license, notice, commercial terms and logo match the supplied bytes. Existing Wave 18 regression cases remain in place. The shared test provider fixture now accepts an explicit operation-ID allowlist with the original ID as its default.

The audit covers the checked source, installed runtime and local evidence. Operational trust still depends on separate collectors and controlled provider access. Hosted CI, Windows execution, vendor deployment qualification and third-party security review are outside the audit scope.
