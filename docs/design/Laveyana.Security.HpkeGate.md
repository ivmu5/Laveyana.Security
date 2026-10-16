# Phase 19 — HPKE security gate (EN)

**English** | [Русский](Laveyana.Security.HpkeGate.ru.md)

**Status: DEFERRED / UNSUPPORTED.** This report prepares a cryptographic design and evidence, but is **not** approval to ship a Seal/Open API. No `Seal`, `Open`, `SealedPayload`, HPKE capability advertisement or custom wire format is published in this phase.

## 1. Normative basis and candidate suite

- RFC 9180, including verified errata, notably §§ 4–9 and Appendix A.
- Exact **interoperability reference**: `mode_base=0x00`, `DHKEM(P-256, HKDF-SHA256)=0x0010`, `HKDF-SHA256=0x0001`, `AES-128-GCM=0x0001` from RFC 9180 Appendix A.3.1. This does **not** change the existing AES-256-GCM symmetric encryption default.
- `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM (0x0002)` is also a candidate for a future API, but demands separate authoritative test vectors for that exact suite; AES-128 vectors do not prove AES-256 interop.
- No suite is enabled for production until an independent provider and exact implemented behavior have passed the gate. No automatic algorithm substitution.

## 2. Required protocol properties

1. Initially consider **single-shot RFC 9180 Base mode only**. Phase 18's custom `DerivationContext` is **not** RFC 9180 HPKE's labeled HKDF; do not repurpose it or hand-roll an `ECDH + HKDF + AES-GCM` scheme.
2. A fresh unpredictable ephemeral key pair per `Seal`; `enc` is a canonical 65-byte P-256 uncompressed point. RFC 9180 controls the nonce; callers do not provide a nonce or reuse contexts.
3. Bind ciphertext to **exact** `ProviderId + KeyId + KeyVersion`; `Open` must not silently select a newer key after rotation. A trusted executor must re-check exact-key authorization, state and revocation at operation time.
4. Pin versioned application/protocol `info` and authenticate all security-relevant envelope header fields (suite, mode, version identity, `enc`) and external AAD. Reject a mismatch without releasing plaintext or falling back to another suite.
5. Any future parser must reject unknown wire versions/modes/KEM/KDF/AEAD, duplicate or trailing fields, inconsistent sizes, malformed EC points, invalid `enc`/ciphertext and untrusted identities.
6. Candidate limits: plaintext <= 16 MiB, external AAD <= 64 KiB, `info` <= 4 KiB. The exact framing, total envelope length and stable wire semantics need a distinct completed review before publication. Keep all private and intermediate key material non-exportable at the high level.
7. Base mode does **not** authenticate the sender or prevent replay; a separate protocol must authenticate the recipient public key and supply peer identity and replay policy.
8. Failed authentication must never release partial plaintext. Key, store, provider, input and cancellation errors must not be disguised as mere tag failures. Durable trusted asymmetric-key storage and cross-process revocation are still unavailable.

## 3. Evidence collected

- `tests/hpke-gate/rfc9180-a3-base.json`: exact published **test-only** RFC 9180 Appendix A.3.1 reference keys, transcript and six ciphertext samples; never use the fixed private keys for actual messages.
- `tools/hpke_gate_verify.py`: independently checks P-256 ECDH from both parties, RFC labeled HKDF, KEM shared secret, key schedule, AEAD key/base nonce/exporter secret and sequences 0/1/2/4/255/256. Includes 14 negative authentication checks covering tampering, wrong AAD, recipient and `info`.
- The Python reference passes under available `cryptography 46.0.4`. This is **not** a .NET implementation, C# conformance test or independent third-party product audit.
- No unsafe public HPKE feature was added to the library.

Run the reference-only check (requires external Python `cryptography` dependency, not a NuGet production dependency):

```bash
python tools/hpke_gate_verify.py
```

## 4. Mandatory outstanding gates

| Criterion | Status |
|---|---|
| Exact reference suite and authoritative RFC Appendix A.3.1 vector | Ready |
| Independent reference + negative cases | PASS (Python test harness only) |
| Approved and maintained .NET HPKE implementation/provider strategy | **OPEN** |
| .NET 10 build, NUnit official vector/interop/negative/key-rotation tests | **OPEN** |
| Exact wire-format / `info` / AAD binding / identity & replay security analysis | **OPEN** |
| Independent RFC 9180 interop, authoritative vectors for final production suite | **OPEN** |
| Focused security review including key custody, zeroization and error taxonomy | **OPEN** |
| Existing FileSystem/platform protection production gates | **OPEN** |

**Decision:** Phase 19 is deferred. The optional feature does not block Phase 20 per the adopted Roadmap. Resume only after each gate can be verified; then introduce public `Seal` / `Open` / `SealedPayload` types and a stable envelope format. A passing Python script must never be misrepresented as C# production readiness.

**Normative sources:** https://www.rfc-editor.org/rfc/rfc9180.html ; https://www.rfc-editor.org/errata/rfc9180 .
