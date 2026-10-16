# Changelog

**English** | [Русский](CHANGELOG.ru.md)

This changelog records **unreleased development checkpoints**, not production releases or successful security acceptance. Version configured in `Directory.Build.props`: `1.2610.0-alpha.1`. No public package, compatibility promise or release tag is asserted by this document.

## Unreleased — H01: compiler diagnostic fixes (2026-10-16)

- Fixed `CS0618` (NUnit), `CS9174` (`ReadOnlyMemory<byte>`) and Windows-only platform analyzer `CA1416` warnings.
- Eliminated test-assembly `CS1591` by disabling XML documentation output **only** for test projects; shipping library API documentation remains mandatory.
- Retained NuGet lock files and excluded `.vs`, `bin`, `obj` from the archive. Real compilation and NUnit remain unverified.

## Unreleased — H01 build corrections (2026-10-12)

- Fixed 52 missing-braces constructs and documented 46 public enum values with XML comments.
- Separated top-level types into independent files without changing public API signatures; original IDE0011/CS1591 causes have been addressed, while cascading CS0006 errors require a fresh compilation.
- Added `tools/verify_api_layout.py` to CI and the [correction report](docs/hardening/H01-CompilationRepair.md).
- **.NET compilation and NUnit remain unverified; Phase 27 production NO-GO remains in effect.**

## Unreleased — Phase 27 (partial review, 2026-10-10)

- Static security review of seven projects and a [prioritized findings report](docs/audit/Laveyana.Security.Phase27.SecurityAudit.md).
- Snapshot mutable AEAD AAD and signing input before asynchronous metadata I/O; wipe private snapshots on completion.
- Added delayed-I/O input mutation regressions and deterministic wire-format mutation tests.
- **Phase 27 and the production release gate remain open:** .NET build/NUnit/platform tests are unrun; Windows TOCTOU, rollback and nonce lifetime invariants remain unverified.

## Unreleased — Phase 26 (2026-10-10)

- Reconciled README, specification, architecture and roadmap against the Phase 25 repository baseline.
- Added a bilingual source-capability/status matrix and explicit **not verified** build/test/security gates.
- Marked HPKE and streaming AEAD deferred, FileSystem experimental and persistent asymmetric/secret backends incomplete.
- Clarified the Decision Log's intentional numbering gaps; no historical decisions were recreated or silently renumbered.
- Added automated documentation verification and CI integration. No cryptographic runtime behavior is changed in Phase 26.

## Unreleased — implementation checkpoints

| Phase | Scope introduced | Acceptance state |
| --- | --- | --- |
| 1–4 | Repository, identities, safe local primitives and sensitive material | Source prepared; .NET/NUnit unverified |
| 5–8 | Typed handles, lifecycle planner, provider and store contracts | Source prepared; .NET/NUnit unverified |
| 9–11 | Software lifecycle, nonce policy, versioned persisted schemas | Source prepared; .NET/NUnit unverified |
| 12–13 | FileSystem store and platform confinement | **Experimental; security gate open** |
| 14–14A | Windows DPAPI and explicit protector re-protection | Source prepared; platform tests unverified |
| 15–18 | Payloads, AES-GCM, HMAC/signatures, agreement and derivation | Source prepared; .NET/NUnit unverified |
| 19 | RFC 9180 reference verification and HPKE gate analysis | **HPKE API deferred / unsupported** |
| 20 | Streaming SHA/HMAC and separate streaming gate | SHA/HMAC source prepared; **AEAD unsupported** |
| 21–22 | Secrets management contracts and DI composition | Source prepared; .NET/NUnit unverified |
| 23–24 | Optional conditional rotation and provider migration primitives | Source prepared; durable coordination is external |
| 25 | Opt-in logging, metrics, tracing, best-effort audit | Source prepared; .NET/NUnit unverified |

See [Roadmap](docs/design/Laveyana.Security.Roadmap.md), [Decision Log](docs/design/Laveyana.Security.DecisionLog.md) and [README](README.md) for detailed capabilities and blockers. Phase 27 has a partial static review, but the **full security acceptance remains open**.
