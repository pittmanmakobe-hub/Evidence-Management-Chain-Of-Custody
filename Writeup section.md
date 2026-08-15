
Writeup section · MD
Lab 4.4: Evidence Management & Chain of Custody
Chain of custody for the evidence pipeline is defined by four properties. Each is backed by a specific artifact in the vault, not by process trust:

Property	What it means	Artifact that proves it
Authenticity	The bundle was produced by this repo's CI, not fabricated or substituted by someone with AWS access	evidence-<run_id>-<sha>.tar.gz.sig.bundle — Cosign signature whose certificate encodes the GitHub OIDC subject (repo:<owner>/<repo>:ref:...), issued by Sigstore Fulcio
Integrity	The bundle's bytes have not been altered since signing	evidence-<run_id>-<sha>.tar.gz.sha256 — SHA-256 recomputed at verify time and compared against the sidecar written at sign time
Timeliness	The signature is anchored to a specific, disprovable moment	The Sigstore Rekor transparency log entry embedded in the .sig.bundle, which timestamps the signing event independently of anything in our AWS account
Completeness / Preservation	The evidence cannot be deleted or overwritten before the retention period expires, even by an account admin	S3 Object Lock retention on the bundle object, checked via get-object-retention and reported as RetainUntilDate in verify-evidence.sh
receipt.json ties these together for a given run: run ID, vault, object key, S3 version ID, SHA-256, and commit SHA.

Running scripts/verify-evidence.sh <run_id> checks all three verifiable properties (integrity, authenticity/timeliness, preservation) in sequence and exits non-zero on the first failure. A tamper test — modifying one byte of a downloaded bundle and recomputing its hash — confirms the integrity check catches tampering, and that Object Lock prevents writing the tampered copy back to the vault under the same key.

Result: CHAIN INTACT for run <run_id> — verified without trusting anyone's word, including mine.


