# Laveyana.Security — Application secret lifecycle (integration guidance)

[Русский](ApplicationSecretLifecycle.ru.md) | **English**

## Why this is not another key manager

Laveyana.Security already exposes `ISecretProvider`, `ISecretManagementProvider`, `SecretHandle` and `PortableKeyRecovery`. They are sufficient to express a **read-only open of an existing key** and an **explicit portable export/recovery operation**.

The existing `ISecretManagementProvider.SetAsync` means **create or replace** according to the provider policy. It is **not** atomic create-if-absent. Calling `GetAsync` and then `SetAsync` does not fix this: two processes can race; on Android a suppressed storage failure can look like absence. Do **not** add a generic `GetOrCreate` around this interface for encryption roots.

## Application-controlled state machine

| Application state | Allowed action | Must not happen |
| --- | --- | --- |
| Known new, empty dataset and explicitly requested initialization | Provision fresh material using an application-vetted setup flow; make key+dataset identity consistent | Assume `GetAsync == null` proves a dataset is new; overwrite an existing key |
| Existing encrypted dataset | `new SecretHandle(reference, provider).UseMaterialAsync(...)`; proceed only if the callback executes successfully | Generate/replace key when the result is `false` |
| Existing dataset, missing or unreadable secret | Fail closed and offer a separate recovery/error flow | Retry with regenerated key, delete data, silently reset user state |
| Explicit restore to a new device/store | Verify an exact expected scope with `PortableKeyRecovery.Unprotect`, then provision through the chosen store's safe app-owned transaction/reconciliation flow | Auto-overwrite a live existing key; interpret a write error or cancellation as definite rollback |

**Who decides if data are new?** The application, based on its own authoritative dataset lifecycle and provenance — not by checking the secret provider's null response. An app must reconcile stale or partially initialized datasets before attempting new provisioning. A marker stored only alongside an equally vulnerable key is not independent evidence.

## Minimal opening pattern

```csharp
SecretHandle handle = new(secretReference, secretProvider);
bool opened = await handle.UseMaterialAsync(bytes =>
{
    // Use borrowed bytes synchronously in the permitted application operation.
    // Never retain the span or perform async work that outlives this callback.
});
if (!opened)
{
    throw new InvalidOperationException(
        "An existing encrypted dataset cannot be opened; explicit recovery is required.");
}
```

Provider exceptions propagate and must not be caught as absence. This only establishes that a secret was read; the application must still validate its dataset identity and authenticate its content before trusting it. A failed dataset authentication cannot be fixed by silently provisioning a new key.

## What this guidance cannot guarantee

- No general-purpose atomic **create-if-absent** or compare-and-swap is provided by `ISecretManagementProvider`. Strong concurrent provisioning requires an independently appropriate storage/transaction boundary.
- MAUI `ISecureStorage` does not prove independent durability, cross-process atomicity, or distinguish a hidden platform failure from true absence.
- `PortableKeyRecovery` covers one **exportable** material value, not a consistent multi-key backup or an encrypted dataset snapshot. It cannot restore non-exportable hardware keys.
- Restoring previous AES-GCM key material does not reconstruct its nonce history and **does not authorize forward encryption** through the software backend (SA-04).
- This workflow is an example/contract guide, **not** production key-custody acceptance. Existing SA-03/04/08 and physical-device acceptance limitations still apply.

The NUnit scenario fixture `ApplicationSecretLifecycleTests` exercises opening, suppressed-null loss, and explicit restoration via existing public APIs. It does not emulate atomic persistence or prove safety of an actual device backend.
