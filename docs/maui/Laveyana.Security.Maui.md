# Laveyana.Security.Maui — SecureStorage adapter (candidate)

**English** | [Русский](Laveyana.Security.Maui.ru.md)

**Status (22 October 2026):** common library and portable NUnit tests passed on Windows/Linux; Android and Apple workload projects compiled in GitHub Actions. Native hardware-device tests remain pending. Experimental only, not production approved.

## Purpose and boundaries

`MauiSecureStorageSecretProvider` implements the existing `ISecretManagementProvider` contract using a caller-supplied `Microsoft.Maui.Storage.ISecureStorage` (or MAUI `SecureStorage.Default`). It is intentionally **not** an `IKeyStore` or `IKeyStoreProtector`: platform key-value storage does not guarantee the atomic durable CAS, key-wide nonce discipline, rollback resistance, envelope purpose/authenticated-context binding, cross-process coordination, or crash recovery required by those contracts.

Capabilities:

- Exact stable `ProviderId`/`SecretId` addressing; provider-scoped MAUI storage keys and a versioned record containing its own immutable identity to reject accidental record swaps.
- `FindAsync`, `GetAsync` (owned `SensitiveMaterialLease`), `SetAsync`, `DeleteAsync` via the existing library interfaces.
- Maximum raw material of **2048 bytes**. Values are Base64-encoded into `string` for the underlying MAUI API, with strict format and identity validation on reads.
- Malformed records and errors surfaced by `ISecureStorage` fail closed. An exact immediate readback rejects silent no-op or mismatched writes. The adapter itself never calls `RemoveAll`, retries automatically, or falls back. The Android MAUI backend may internally suppress errors or clear preferences, which the adapter cannot prevent.
- Explicit DI registration; an `ISecureStorage` fake can be injected in unit tests.

**Not guaranteed:** process isolation between app components, user-level authorization, zeroization of managed `string` copies, transactional/multi-process writes, hardware-backed key custody on every device, cross-device portability, durability after power failure, rollback protection, secure deletion or keys usable as safe persistent AES-GCM encryption roots.

## Wiring in a MAUI application

The MAUI app already provides `SecureStorage.Default`. Register the adapter **before** the existing `AddSecurity` composition. The provider ID and each secret ID must be constants or persistently configured IDs, **never generated at each launch**:

```csharp
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.DependencyInjection.Composition;
using Laveyana.Security.Maui.Composition;
using Laveyana.Security.Maui.Storage;

ProviderId providerId = ProviderId.Parse("11111111-1111-4111-8111-111111111111"); // Replace and keep stable.
builder.Services.AddLaveyanaMauiSecureStorage(providerId);
builder.Services.AddSecurity(security =>
    security.UseSecretProvider<MauiSecureStorageSecretProvider>(providerId));
```

To write or read from your application service:

```csharp
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Sensitive;

SecretReference secret = new(providerId, SecretId.Parse("22222222-2222-4222-8222-222222222222"));
using SensitiveMaterialLease value = SensitiveMaterialLease.CreateCopy("test-token"u8);
await provider.SetAsync(secret, value);

using SecretReadResult? result = await provider.GetAsync(secret);
result?.UseMaterial(bytes =>
{
    // Use the borrowed bytes synchronously; do not retain the span or log secrets.
});
```

`provider` above is an injected `MauiSecureStorageSecretProvider` or `ISecretManagementProvider`. `SensitiveMaterialLease`, `SecretReference` and `SecretReadResult` belong to `Laveyana.Security.Abstractions` namespaces `Sensitive`, `Identifiers`, and `Secrets` respectively.

`ISecureStorage` has no `CancellationToken` parameter. Cancellation is honored **before** the platform operation, not during it. After an exception near `SetAsync`, the write outcome may be uncertain; inspect the exact key rather than retrying blindly when that matters. Deletes are not guaranteed to securely erase disk blocks or remote synchronized copies.

## Platform notes

- **Android:** MAUI uses encrypted preferences backed by Android keys. Backup/restore can make ciphertext unavailable. On some recovery failures `SecureStorage.Default` may **clear multiple preferences or return null instead of surfacing an error**, and writes may silently do nothing. Immediate readback detects a missing/mismatched *just-written* record, but cannot prove durability, prevent backend cleanup, or distinguish a later suppressed failure from genuine absence. Exclude these preferences from backup or use recoverable re-authentication. **Never automatically recreate an irreplaceable root secret solely because `GetAsync` returned null.**
- **iOS / Mac Catalyst:** Keychain entries can survive app uninstallation; depending on configuration, iCloud Keychain may synchronize. Define application first-launch/user-switch cleanup explicitly; this adapter intentionally does not call `RemoveAll`.
- **Windows:** MAUI uses DataProtectionProvider. Packaged settings are size-constrained; the 2048-byte raw material bound avoids large-value use. Packaged and unpackaged applications persist differently.

See Microsoft's [SecureStorage platform documentation](https://learn.microsoft.com/en-us/dotnet/maui/platform-integration/storage/secure-storage?view=net-maui-10.0).

## Build and release gate

- The common MAUI project is already in the solution and portable NUnit suite, with `Microsoft.Maui.Essentials` centrally versioned. Android and Apple use separate workload-specific projects and workflows.
- **New NuGet dependency/lock files require regeneration** from a trusted .NET 10 SDK machine before `--locked-mode` CI will pass. Use the project's existing `scripts/Initialize-LockFiles.ps1` procedure and commit the generated locks. Do not edit locks manually.
- Run `verify_repository.py`, `verify_api_layout.py`, `verify_documentation.py`, Release build and NUnit; test MAUI Android/iOS/Mac Catalyst/Windows behavior on real supported targets before claiming a validated public package.
- `IsPackable=false` remains inherited. Public NuGet publishing of this module is deferred until the integration is verified.

## Experimental hardware signing — Windows TPM

An optional `INativeSigningKeyService` low-level adapter supports creating,
finding, and deleting persistent named ECDSA NIST P-256 keys via the **Microsoft
Platform Crypto Provider (TPM)** on compatible Windows devices. It signs with
SHA-256 and returns fixed-width 64-byte IEEE P1363 signatures and an exportable
**public** SubjectPublicKeyInfo. Private key export and software fallback are
not supported.

Explicit registration: `services.AddLaveyanaWindowsTpmSigning(providerId)`.
Application code must persist the provider/key IDs, never reuse deleted IDs,
and handle uncertain create/delete outcomes. Keys may persist after an app
crash. Deletion is not proof of physical erasure. The implementation is NOT
`IKeyProviderBackend` / `IManagedSignatureBackend`: no versioned lifecycle,
attestation, user-presence/biometrics, rollback resistance or cross-process CAS.

Normal NUnit/CI runs exercise public-key validation and portable behavior.
The real Windows TPM create/sign/delete test requires an explicit
`LAVEYANA_RUN_TPM_TESTS=1` opt-in on a supported Windows PC and can leave a
persistent key after process termination. It is intentionally skipped by
default; passing CI **does not prove TPM hardware functionality**.

Android Keystore and Apple Secure Enclave both have separate **experimental implementations**, but neither has passed physical-device acceptance.
This component is experimental and not accepted for production secrets or a
stable NuGet release; SA-03/04/08 remain open.

## Android hardware signing candidate (separate workload)

An **experimental**, separately compiled `platforms/android/Laveyana.Security.Maui.Android`
assembly implements the same `INativeSigningKeyService` contract using
Android Keystore on Android 12+ (API 31+). It rejects keys whose reported
security level is not TEE or StrongBox and provides ECDSA P-256/SHA-256
signing with 64-byte IEEE P1363 results.

This candidate is not in the default solution, does not run on Windows/Linux,
and has no on-device acceptance yet. A platform-specific compile workflow is
separate from core CI. See [Android module](../../platforms/android/README.md).
No key attestation, user-presence policy, CAS, or rollback guarantee is implied.

## Apple Secure Enclave candidate

The optional iOS/Mac Catalyst-only `platforms/apple/Laveyana.Security.Maui.Apple`
assembly implements the same `INativeSigningKeyService`. It explicitly
requests hardware Secure Enclave P-256 keys with a
`WhenUnlockedThisDeviceOnly` policy, transforms public X9.63 keys into
SPKI and DER signatures into IEEE P1363. No software fallback is permitted.

This separate workload project is **not** part of the core solution; device
acceptance, hardware attestation, end-user authorization, cross-process CAS,
and rollback-proof lifecycle are **not provided**. See
[Apple native candidate](../../platforms/apple/README.md).
