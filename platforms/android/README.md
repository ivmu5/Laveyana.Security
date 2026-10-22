# Laveyana.Security.Maui.Android — experimental native signing

This project is **not** part of the default solution or published NuGet packages.
It references the common `INativeSigningKeyService` introduced by the Windows
TPM pull request and is designed for separate Android workload compilation.

The service targets Android API 31+ and creates persistent app-scoped P-256
ECDSA keys with `AndroidKeyStore`. It checks the `KeyInfo.SecurityLevel`
of the actual private key on create, find and sign, accepting only Trusted
Environment or StrongBox, and fails without a software-key fallback. The
service signs SHA-256 and emits 64-byte IEEE P1363 signatures converted from
the platform DER output. Only public SPKI data is exported.

No user-authentication policy, hardware attestation, deletion proof,
cross-process atomic key-name claim, versioned key lifecycle or rollback
protection is implemented. A creation race can replace an alias, and a crash
after generation can leave a persistent key with an uncertain outcome.
Callers must store stable IDs and reconcile after interrupted calls.
Android Keystore keys are app-specific and typically do not survive uninstall;
do not use this for unrecoverable encryption keys.

Build using a .NET 10 Android workload:

```powershell
dotnet workload install android
dotnet restore platforms/android/Laveyana.Security.Maui.Android/Laveyana.Security.Maui.Android.csproj --force-evaluate
dotnet build platforms/android/Laveyana.Security.Maui.Android/Laveyana.Security.Maui.Android.csproj -c Release --no-restore
```

A dedicated GitHub Actions workflow compiles this project; ordinary Windows/
Linux solution CI does **not** compile Android-specific code. The workflow
restore regenerates a candidate lock locally; before adding this project to
the release solution, commit a genuine platform lock file and enable locked
restore. Physical device and emulator tests are still needed.

**Status:** draft candidate, not production or NuGet-ready.

## Optional fail-closed encrypted preferences (storage experiment)

`Storage.AndroidFailClosedSecureStorage` is a **separate opt-in**
`ISecureStorage` implementation. It is not a `IKeyStore`, key custodian
or guaranteed-durable database. Use it only for small, reproducible tokens.

Unlike the default MAUI Android implementation it directly opens isolated
AndroidX `EncryptedSharedPreferences`, never catches/deletes/recreates
corrupt preferences, calls synchronous `Commit()` and treats `false` as a
write failure. The existing `MauiSecureStorageSecretProvider` adds immediate
readback verification. Underlying exceptions are preserved. `RemoveAll()`
is deliberately unsupported. These behaviors are **not** rollback protection,
power-cut durability, cross-process CAS or proof that a missing entry never existed.

AndroidX `EncryptedSharedPreferences` is **deprecated**. This is a
short-term experiment using its existing authenticated encryption, *not* a
new custom AES implementation. Do not claim hardware-bound AES keys,
strong key deletion or production safety based on this component.

Example MAUI Android composition:

```csharp
builder.Services.AddLaveyanaAndroidFailClosedSecureStorage(stableProviderId);
builder.Services.AddSecurity(security =>
    security.UseSecretProvider<MauiSecureStorageSecretProvider>(stableProviderId));
```

This creates a **new, provider-isolated** encrypted preferences file. It
does not read/migrate old `SecureStorage.Default` values. Do not enable both
registrations. Exclude its preferences file from Android Auto Backup, and
test lost-key, backup/restore, process-crash, commit failure and device
reinstall behavior. The platform CI **compiles only**; no Android device
execution has been completed.

There is intentionally no generic data migration or implicit error recovery.
