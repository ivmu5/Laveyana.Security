# Laveyana.Security.Maui.Apple — experimental Secure Enclave signing

**Status:** draft, not production accepted, not published to NuGet.
This iOS/Mac Catalyst workload-specific project is outside the default
`net10.0` solution. It uses the shared `INativeSigningKeyService` from
`Laveyana.Security.Maui`.

Supported operations: Create, Find, Sign and Delete an app-scoped, persistent
NIST P-256 ECDSA private key using the Apple Security framework. Generation
explicitly requests **SecTokenID.SecureEnclave** with a
**WhenUnlockedThisDeviceOnly** access policy and the **PrivateKeyUsage** flag.
There is no software fallback. Private material never leaves Secure Enclave.
Public X9.63 points are converted into validated SubjectPublicKeyInfo values;
ECDSA DER signatures become 64-byte IEEE P1363 values.

Use `AddLaveyanaAppleSecureEnclaveSigning(providerId)` and persist the
provider and key IDs. The service fails on unsupported devices. This does not
require user presence or biometrics; those must be added as an explicit and
separately tested feature, not silently assumed.

## Known risks and limitations

- No atomic cross-process create-if-absent; a concurrent writer can race the
  pre-create lookup. Do not treat `CreateAsync` as a CAS primitive.
- No hardware attestation, key-version lifecycle, automatic rotation,
  rollback-proof history, proof of physical erasure or biometric authorization.
- Persistent Keychain items can outlive an application reinstall. Operations
  interrupted at creation/deletion require reconciliation.
- Device-only keys cannot be transferred or restored on another device.
  Never make them the only copy of an irreplaceable encryption secret.
- The simulator may not have an actual Secure Enclave. A green compile result
  does **not** establish real-device operation.
- To verify a signature, use the SPKI public key and IEEE P1363 format. Neither
  creation nor a public-key read authenticates the human user.

## Build

Requires macOS with Xcode and .NET 10 iOS/Mac Catalyst workloads:

```sh
dotnet workload install ios maccatalyst
dotnet restore platforms/apple/Laveyana.Security.Maui.Apple/Laveyana.Security.Maui.Apple.csproj --force-evaluate
dotnet build platforms/apple/Laveyana.Security.Maui.Apple/Laveyana.Security.Maui.Apple.csproj -c Release --no-restore
```

The dedicated Apple GitHub Actions workflow checks **compilation only**.
Run a signing roundtrip on an actual iOS device and on a supported Mac after
reviewing the project. This candidate still needs project-local authentic
NuGet lock files and a release gate before packaging.
