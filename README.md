# Laveyana.Security

**English** | [Русский](README.ru.md)

Modular .NET 10 library for key lifecycle management, cryptographic operations, secret-provider integration and explicit provider composition. **This repository is a pre-release implementation, not a production-approved security library.** The implemented code has passed repository-level static checks, but a successful .NET 10 build, NUnit run, cross-process tests and platform security review have **not** been demonstrated in this development environment.

> **Current checkpoint:** Phase 27 — partial static security review of the Phase 26 baseline (2026-10-10), including fixes for mutable AEAD AAD and signing input. Build, NUnit and platform security tests are **unrun**. The production release gate remains **open**. See the [Phase 27 report](docs/audit/Laveyana.Security.Phase27.SecurityAudit.md).

**New:** [H01 first-run and CI setup](docs/hardening/H01-Setup.md). Generate and commit genuine NuGet lock files on a .NET SDK 10.0.4xx host before your first Push.

**H01 correction set:** [first-build diagnostics and one-type-per-file rule](docs/hardening/H01-CompilationRepair.md). Extract to a clean directory and preserve genuine NuGet lock files from your existing copy.

## Assemblies

| Project | Responsibility |
| --- | --- |
| `Laveyana.Security.Abstractions` | Stable identities, typed handles, immutable result values, extension contracts, sensitive-memory ownership. |
| `Laveyana.Security` | Core primitives, key lifecycle, software provider, AEAD, MAC, derivation, routing, rotation, migration and observability. |
| `Laveyana.Security.FileSystem` | Experimental protected `IKeyStore`; Linux/Windows safety measures are not yet production-validated. |
| `Laveyana.Security.Windows` | Explicit Windows DPAPI CurrentUser `IKeyStoreProtector` (platform tests pending). |
| `Laveyana.Security.DependencyInjection` | Explicit `AddSecurity`/`AddSecurityDefaults` composition and optional hosted rotation worker. |
| `Laveyana.Security.Tests` | NUnit unit and contract tests. |
| `Laveyana.Security.IntegrationTests` | NUnit DI, FileSystem, Windows and worker integration scenarios. |

The public extension interfaces remain in Abstractions. Applications may construct components directly without dependency injection. No automatic plaintext fallback, protector selection, file-store creation or worker startup is provided.

## Implementation status

| Area / phases | Source status | Important boundary |
| --- | --- | --- |
| Identity, primitive crypto, sensitive memory, metadata handles, lifecycle and provider registry (1–7) | Implemented | Capability preflight is metadata-only; the backend must authorize at execution. |
| Storage/protector contracts, software lifecycle, nonce policy, versioned persistence (8–11) | Implemented | Atomicity and rollback guarantees depend on the concrete store / external authority. |
| FileSystem store and hardening (12–13) | **Experimental** | Explicit experimental write opt-in; Windows TOCTOU and end-to-end durability/rollback gates remain open. |
| Windows DPAPI and protector migration (14, 14A) | Implemented in source | Windows execution and recovery testing are unconfirmed; re-protection does not rotate cryptographic material. |
| Result types, AES-256-GCM, HMAC, ephemeral ECDSA/RSA-PSS and ECDH/HKDF (15–18) | Implemented in source | Persistent asymmetric private-key management and strong executor revocation are not provided. |
| HPKE `Seal`/`Open` (19) | **Deferred / unsupported** | RFC 9180 reference vectors alone do not validate a .NET HPKE implementation. No public HPKE API. |
| Streaming SHA-2 and HMAC (20) | Implemented in source | **Streaming AEAD is deferred / unsupported** pending its own protocol security gate. |
| Secrets, DI, explicit rotation worker, provider migration, observability (21–25) | Implemented in source | Provider authorization, durable work queues, app cutover journals and audit delivery are application/provider responsibilities. |
| Documentation synchronization (26) | Prepared | Does not close earlier build, test or security gates. |
| Full audit (27) | **Partially reviewed — not accepted** | Static findings and source fixes exist; live build, NUnit, rollback and platform gates remain open. |

Other unsupported assumptions: no default rollback-resistant nonce allocator, no built-in persistent general-purpose secret provider, no implicit export of non-exportable keys, and no guaranteed secure erase of external memory or deleted disk blocks.

## Basic local-primitives example

```csharp
using System.Security.Cryptography;
using Laveyana.Security.Primitives;

byte[] key = LocalCryptography.GenerateRandomBytes(32);
byte[] message = "message"u8.ToArray();
try
{
    byte[] tag = LocalCryptography.HmacSha256(key, message);
    bool matches = LocalCryptography.VerifyHmacSha256(key, message, tag);
    // Consume the non-secret result; do not log key bytes.
}
finally
{
    CryptographicOperations.ZeroMemory(key);
}
```

This is a local primitive, **not** a managed-key service or an authorization boundary. Production applications must review key generation, ownership, zeroization, provider policy and storage assumptions for their threat model.

## Verification

Install the .NET SDK selected by [`global.json`](global.json) (10.0.x) and run:

```sh
python tools/verify_repository.py
python tools/verify_repository.py --self-test
python tools/verify_documentation.py
python tools/verify_documentation.py --self-test
dotnet restore Laveyana.Security.sln
dotnet build Laveyana.Security.sln -c Release --no-restore -warnaserror
dotnet test Laveyana.Security.sln -c Release --no-build --no-restore
```

The GitHub Actions workflow runs verification, build and tests on Windows and Ubuntu **when CI executes**. Its presence is not evidence of a successful run. Run platform-hardening, multi-process, power-failure/recovery, permission and rollback scenarios independently before enabling writes with real secrets.

## Documentation

| Resource | Content |
| --- | --- |
| [Technical specification](docs/design/Laveyana.Security.TechnicalSpecification.md) | API requirements, persisted formats, invariants and security constraints. |
| [Architecture](docs/design/Laveyana.Security.Architecture.md) | Assembly boundaries, lifecycle, provider, storage and operational trust boundaries. |
| [Roadmap](docs/design/Laveyana.Security.Roadmap.md) | Phase-by-phase acceptance criteria and release gates. |
| [Decision log](docs/design/Laveyana.Security.DecisionLog.md) | Security-specific decisions D04–D57 with deliberate numbering gaps; see its maintenance note. |
| [HPKE gate](docs/design/Laveyana.Security.HpkeGate.md) | Deferred HPKE evidence and blockers. |
| [Streaming gate](docs/design/Laveyana.Security.StreamingGate.md) | Implemented SHA/HMAC scope and deferred AEAD. |
| [Phase 27 audit](docs/audit/Laveyana.Security.Phase27.SecurityAudit.md) | Static findings, fixes and mandatory release gates. |
| [CHANGELOG](CHANGELOG.md) | Unreleased checkpoint history, not a release announcement. |
| [Master implementation prompt](Laveyana.Security.MasterImplementationPrompt.ru.md) | Generation 1 constraints and staged continuation guidance (Russian). |

All core design documents above have Russian counterparts named `*.ru.md`, and the root [Russian README](README.ru.md) and [Russian CHANGELOG](CHANGELOG.ru.md) are provided.

## Release policy

Phase 27 is mandatory. The repository must pass build and test verification, prove relevant Windows/Linux filesystem and protector properties, address rollback/nonce and concurrency risks, and complete a focused security review before production claims are made. Optional HPKE and streaming AEAD may remain explicitly unsupported. No license is included; choosing and adding one requires an explicit project-owner decision.
