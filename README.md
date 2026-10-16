# Laveyana.Security

**English** | [Русский](README.ru.md)

[![Verify](https://github.com/ivmu5/Laveyana.Security/actions/workflows/verify.yml/badge.svg)](https://github.com/ivmu5/Laveyana.Security/actions/workflows/verify.yml)

`Laveyana.Security` is a set of .NET 10 libraries for cryptographic primitives, versioned key lifecycle, provider capabilities, and explicitly protected persistent key storage. The core and platform integrations are separate assemblies. The repository is **pre-release**; the filesystem backend remains **experimental and not approved for production secrets**.

**Verification (16 October 2026):** the `Verify` GitHub Actions workflow passed its source/documentation checks and Release build/NUnit jobs on **Windows and Ubuntu**. This establishes a CI baseline, **not** completion of the Phase 27 security review. In particular, Windows pathname TOCTOU, independent rollback protection, durable nonce assurances, and adversarial crash/recovery evidence remain outstanding. See [security review](docs/audit/Laveyana.Security.Phase27.SecurityAudit.md).

## Contents

- [Capabilities](#capabilities)
- [Architecture and entry points](#architecture-and-entry-points)
- [Quick start](#quick-start)
- [Verification](#verification)
- [Security and lifecycle boundaries](#security-and-lifecycle-boundaries)
- [Documentation](#documentation)

## Capabilities

- Local RNG, SHA-2, HMAC, HKDF and PBKDF2 utilities; policy-governed software cryptography.
- Opaque provider/key identities, exact key versions, capability-based operations and key lifecycle transitions.
- Managed authenticated encryption, MAC, signing/verification and derivation contracts, with explicit ownership of sensitive memory.
- Versioned persisted metadata, software key-provider implementation, optional rollback-protected nonce allocation contract and explicit provider migration operations.
- Opt-in filesystem `IKeyStore`, Windows DPAPI CurrentUser protector, dependency injection, conditional rotation worker and non-sensitive telemetry.

**Not implemented:** public HPKE `Seal`/`Open`, encrypted streaming AEAD, a general-purpose persistent asymmetric private-key executor, and a built-in durable generic secret backend. These cannot be inferred from related interfaces or design documents.

## Architecture and entry points

| Assembly | Responsibility and relevant entry points |
| --- | --- |
| `Laveyana.Security.Abstractions` | [Key identities](src/Laveyana.Security.Abstractions/Identifiers/KeyReference.cs), [typed capabilities](src/Laveyana.Security.Abstractions/Capabilities/EncryptionKey.cs), [store contract](src/Laveyana.Security.Abstractions/Storage/IKeyStore.cs), [protector contract](src/Laveyana.Security.Abstractions/Protection/IKeyStoreProtector.cs). |
| `Laveyana.Security` | [LocalCryptography](src/Laveyana.Security/Primitives/LocalCryptography.cs), [SoftwareKeyProviderBackend](src/Laveyana.Security/Software/SoftwareKeyProviderBackend.cs), [ProviderRegistry](src/Laveyana.Security/Providers/ProviderRegistry.cs), lifecycle, migration and observability. |
| `Laveyana.Security.FileSystem` | [FileSystemKeyStore](src/Laveyana.Security.FileSystem/Storage/FileSystemKeyStore.cs), [options](src/Laveyana.Security.FileSystem/Storage/FileSystemKeyStoreOptions.cs), Windows ACL and Linux descriptor-based path guards. **Experimental.** |
| `Laveyana.Security.Windows` | [WindowsDpapiUserProtector](src/Laveyana.Security.Windows/Protection/WindowsDpapiUserProtector.cs), explicitly selected, Windows-only. |
| `Laveyana.Security.DependencyInjection` | [AddSecurity / AddSecurityDefaults](src/Laveyana.Security.DependencyInjection/Composition/SecurityServiceCollectionExtensions.cs), [composition builder](src/Laveyana.Security.DependencyInjection/Composition/SecurityCompositionBuilder.cs), optional rotation worker. |

```text
Application
  -> Laveyana.Security.DependencyInjection (optional explicit composition)
  -> Laveyana.Security + Laveyana.Security.Abstractions
                  -> provider / store / protector contracts
                  -> optional FileSystem store + Windows protector
```

The solution also contains `Laveyana.Security.Tests` (unit and contract tests) and `Laveyana.Security.IntegrationTests` (platform, store, DI and worker integration tests). Public contracts are independent of any specific filesystem location or Windows protector.

## Quick start

For standalone, caller-owned primitives, reference `Laveyana.Security` and use an existing public API:

```csharp
using System.Security.Cryptography;
using Laveyana.Security.Primitives;

byte[] key = LocalCryptography.GenerateRandomBytes(32);
try
{
    byte[] message = "example"u8.ToArray();
    byte[] tag = LocalCryptography.HmacSha256(key, message);
    bool verified = LocalCryptography.VerifyHmacSha256(key, message, tag);
    // Use verified for application logic; do not log the key.
}
finally
{
    CryptographicOperations.ZeroMemory(key);
}
```

This example is not a key-management or authentication protocol. For managed keys, the application must explicitly select a backend and its trusted `IKeyStore` / `IKeyStoreProtector` and then use the provider contracts. `AddSecurityDefaults` does **not** generate keys, silently select a plaintext backend, create a filesystem store or enable a worker.

<details>
<summary>Provider composition and filesystem write restrictions</summary>

[`SecurityCompositionBuilder`](src/Laveyana.Security.DependencyInjection/Composition/SecurityCompositionBuilder.cs) supports explicit registration of key providers, secret providers, a protector, store, nonce allocator and observability. A composition is registered once; incompatible registrations fail rather than being silently overwritten. A provider must also authorize capabilities at execution, not just during metadata preflight.

[`FileSystemKeyStoreOptions`](src/Laveyana.Security.FileSystem/Storage/FileSystemKeyStoreOptions.cs) requires a fully qualified root directory. `EnableExperimentalWrites` defaults to `false`; enabling it permits **non-production experiments only**. A correctly functioning DPAPI protector does not make this filesystem backend production-approved. The application owns process identities, filesystem isolation, backups and an independent rollback authority where required.

</details>

## Verification

Install the SDK selected by [`global.json`](global.json) (.NET SDK `10.0.400`, `latestPatch` within the 10.0.4xx feature band). NuGet lock files are committed; normal CI restores them in locked mode.

```sh
python tools/verify_repository.py
python tools/verify_api_layout.py
python tools/verify_documentation.py
python tools/verify_documentation.py --self-test
dotnet restore Laveyana.Security.sln --locked-mode
dotnet build Laveyana.Security.sln -c Release --no-restore -warnaserror
dotnet test Laveyana.Security.sln -c Release --no-build --no-restore
```

GitHub Actions runs `Source & docs`, `Build & NUnit (ubuntu-latest)` and `Build & NUnit (windows-latest)` for every pull request and after pushes to `master` (not for standalone pushes to topic branches), with TRX results. An active `Protect master` ruleset targets the default branch, requires a pull request and all three checks, and blocks force pushes/deletion. The main branch is currently named `master`. A separate [Extended Regression workflow](.github/workflows/nightly.yml) repeats the full NUnit suite five times per OS on the **first day of each month at 02:17 UTC**, or on demand from GitHub Actions. Its first manual run on `master` passed on 16 October 2026 (Windows and Ubuntu). Local success does not substitute for platform or security acceptance. More: [H01 verification workflow](docs/hardening/H01-Setup.md).

## Security and lifecycle boundaries

- The FileSystem store is **experimental**, with opt-in writes and unresolved Windows TOCTOU and crash/durability review; do not use it for production secrets.
- Authenticated persistence alone does **not** prevent replay of a previously valid snapshot. Rollback-sensitive guarantees require independent trustworthy state.
- Randomized AES-GCM nonces require an appropriate usage budget; multi-process, cross-restart and backup/restore assurance is a separate architectural responsibility. Do not assume an automatic durable nonce allocator.
- Protectors have stable identities. Changing or rotating a protector is **not** equivalent to key rotation. DPAPI CurrentUser is tied to a Windows user profile, not portable machine-wide encryption.
- Sensitive material has explicit lease/ownership semantics. Caller-owned arrays are not automatically cleared. Cancellation is not a guaranteed rollback after a durable commit.
- `SecurityObservability` is opt-in and redacts sensitive inputs; audit delivery is best-effort, not a transactional audit log.
- Assemblies currently target `net10.0`, have `IsPackable=false`, and are not published as NuGet packages by this repository configuration.

## Documentation

| Document | Authoritative scope |
| --- | --- |
| [Technical Specification](docs/design/Laveyana.Security.TechnicalSpecification.md) | Required external semantics, invariants and acceptance criteria. |
| [Architecture](docs/design/Laveyana.Security.Architecture.md) | Internal boundaries, ownership and components. |
| [Decision Log](docs/design/Laveyana.Security.DecisionLog.md) | Approved architectural tradeoffs (historical DXX identifiers retained). |
| [Roadmap](docs/design/Laveyana.Security.Roadmap.md) | Phase progression and remaining release gates. |
| [HPKE gate](docs/design/Laveyana.Security.HpkeGate.md) · [Streaming gate](docs/design/Laveyana.Security.StreamingGate.md) | Deferred protocol features and evidence required before exposure. |
| [Phase 27 security review](docs/audit/Laveyana.Security.Phase27.SecurityAudit.md) | Static findings, subsequent H01 verification and outstanding security risks. |
| [H01 verification](docs/hardening/H01-Setup.md) · [Compilation history](docs/hardening/H01-CompilationRepair.md) | Reproducible CI and historical compiler fixes. |
| [Changelog](CHANGELOG.md) | Development changes and release history (currently unreleased). |

Documentation is maintained as matching English `*.md` and Russian `*.ru.md` files. This repository is licensed under [MIT](LICENSE.txt). Third-party dependency licenses must be reviewed independently before redistribution; dependency versions are defined in [`Directory.Packages.props`](Directory.Packages.props).
