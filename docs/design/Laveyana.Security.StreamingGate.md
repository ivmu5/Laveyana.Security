# Laveyana.Security — Phase 20 Streaming Security Gate

[Русский](Laveyana.Security.StreamingGate.ru.md) | **English**

## Scope and decision

**Streaming SHA-256/384/512 and full-length HMAC-SHA-256/384/512 are implemented and covered by the passing 16 October 2026 Windows/Ubuntu CI test baseline. Segmented / encrypted streaming AEAD is explicitly UNSUPPORTED / DEFERRED.** No new ciphertext format or unsafe chunked AES-GCM protocol was introduced. This decision follows the optional gate for encrypted streaming in the Roadmap, not a claim of a complete Phase 20 acceptance.

## Implemented non-encrypted streaming boundary

- `StreamProcessingOptions`: 1..65,536-byte chunks, up to 1 TiB of input, optional trusted exact length. The exact-byte limit is enforced by probing EOF; no digest/tag returned if it is exceeded, missing bytes are detected or the stream read/cancellation fails.
- SHA-2 incremental computation uses `IncrementalHash` and reads from the current stream position to EOF; no authenticity claim.
- HMAC incremental computation uses key material only inside `SensitiveMaterialLease.UseMaterial` to initialize an owned `IncrementalHash`. Provider checks Active for MAC creation; verification accepts exact Active/Retired versions when allowed. Historical references remain fixed. Once reading ends, the store's authoritative revision must still match the starting revision. A mismatch throws (not false).
- Stream is borrowed, not closed or rewound. Read buffers are cleared before returning to `ArrayPool`. HMAC internal/native crypto state is disposed; a full tag is copied into `MacResult` and temporary tags are zeroed. No raw key material crosses an external provider interface.
- Whole-buffer HMAC/AEAD size limits are separate from streaming HMAC limits. This API is neither segmented AEAD nor a way around AEAD's 16 MiB payload cap.

## NUnit tests (executed in H01 CI)

Hash known-answer comparisons (three SHA sizes), empty and partial reads, 6 MiB synthetic stream with 1 KiB windows, exact/short/overlong lengths, cancellation, I/O failure, forbidden SHA-1; three HMAC algorithm equivalences with one-shot MAC, mismatch, corrupted tag, rotation, retirement and deletion, missing capability, exact registry routing, typed view, simultaneous revision mutation and stream failure. Independent format or ciphertext acceptance vectors are intentionally absent because encrypted streaming was not implemented.

## Encrypted AEAD gate — blockers

1. Choose a vetted segmented AEAD design or independently reviewed existing implementation, with normative wire format, protocol version, suite and header binding.
2. Define and prove uniqueness rules across key versions, segments, crash/restart and rollback; no nonce reuse or unreviewed derivation.
3. Authenticate stream identity, segment index/ordering, plaintext length where appropriate and an unambiguous **final segment or completion record**; no plaintext made trusted before verified final completion.
4. Define truncated/duplicated/reordered/spliced streams, empty streams, replay and cross-file substitution behavior; reject all invalid cases.
5. Establish conservative message/segment/nonce bounds, cancellation/crash recovery and exception semantics; ensure no partial-authenticated-output consumer is misled into accepting success.
6. Obtain authoritative known-answer and interoperability vectors, negative corpus and fuzzing, independent security review, .NET build and cross-platform execution.

## Remaining release blockers

.NET SDK/NUnit unavailable in this execution environment; neither source compilation nor test run has been confirmed. All previous FileSystem/rollback/Windows TOCTOU/security gates remain open. Do not use current storage implementation for production secrets.
