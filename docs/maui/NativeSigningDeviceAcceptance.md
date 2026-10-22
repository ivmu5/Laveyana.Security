# Native signing — hardware acceptance matrix (not yet executed)

**Status:** UNVERIFIED on physical hardware. Do not mark cases PASS because code
compiled or because a simulator/emulator returned an error. The signer uses
ECDSA NIST P-256 / SHA-256 / 64-byte IEEE P1363 signatures.

## Device record

For each actual target (Windows TPM / Android TEE or StrongBox / iOS Secure
Enclave / Mac Catalyst Secure Enclave), record:
- device model, OS build, .NET runtime, application installation identity
  (package ID or Windows user), hardware capability, test date;
- exact source commit SHA, stable *test-only* ProviderId, fresh KeyId,
  public SPKI SHA-256 fingerprint (never log private material);
- each test's PASS/FAIL/SKIP with errors and cleanup state.

## Required acceptance scenarios

1. Before creation, `FindAsync(keyId)` returns null. Save IDs to test state
   **before** invoking `CreateAsync`.
2. Create a key, verify that returned `ProviderId`/`KeyId` match. The
   public SPKI imports as P-256. Do not treat this as attestation.
3. Instantiate a **new service instance**, find the same key and compare SPKI
   fingerprint. Sign a domain-separated disposable message; verify locally
   with the exported public key and IEEE P1363. Alter the message; verify
   fails. The private key must not be exportable by the platform API.
4. Attempt a duplicate create for the same ID. The original public key
   fingerprint MUST remain unchanged. If the platform replaces the key,
   mark the provider **FAIL / not accepted** and require caller serialization.
5. Restart the **app process** and open/sign the original key using the
   persisted IDs. Separately test a new process in the same OS security
   context where the platform permits it. Record failures and cleanup.
6. Re-test on a locked device, unsupported/no-hardware environment, and
   after platform authorization failures. The operation must fail without
   software fallback. Never use irreplaceable keys in probes.
7. Delete the exact key; a new service instance must return null. Attempt
   a sign; it must fail. Key deletion is NOT physical-erasure proof.
8. Simulate an interrupted creation/deletion and a concurrent same-ID create
   on a disposable key; record whether the outcome is uncertain. Do **not**
   retry non-idempotent creation blindly.
9. Test app uninstall/reinstall and device backup/restore. Record whether
   keychain/keystore entries survive or are inaccessible, per platform.
10. Windows: attempt sign from another **same-user process** and document the
    actual ACL/authorization boundary. Lack of private export does not imply
    application-specific access control.

### Optional TPM execution

Windows includes an opt-in NUnit test:
```powershell
$env:LAVEYANA_RUN_TPM_TESTS = "1"
dotnet test tests/Laveyana.Security.Tests/Laveyana.Security.Tests.csproj -c Release --filter "WindowsTpmRoundTripRequiresExplicitOptIn"
Remove-Item Env:LAVEYANA_RUN_TPM_TESTS
```

Run it only on a Windows PC with an accessible TPM. It uses disposable named
keys; abnormal termination can leave a key that requires manual reconciliation.
This test does not simulate a fresh OS process, a power cut, or a TPM
attestation. No physical-device acceptance has been reported to this project.

## Message-domain separation

The API signs exact bytes without a built-in envelope. Each application
protocol MUST define a canonical message (e.g. a versioned length-delimited
`Laveyana/AppName/Purpose/v1` domain, immutable object/context identifiers
and payload hash). Do not sign arbitrary reused bytes across trust domains
with the same key. Define the encoding before trusting signatures.

## Gate decision

Until evidence covers the above for the target platform: **DEVICE NO-GO**.
This is independent of unresolved general SA-03/04/08 storage gates.
