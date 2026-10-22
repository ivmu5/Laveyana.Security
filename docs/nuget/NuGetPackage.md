# Laveyana.Security — preview NuGet packages

**Pre-release software for development and controlled internal experiments.** These .NET 10 libraries are not collectively approved for production secret custody.

The repository publishes separate packages for abstractions, cryptographic primitives, dependency injection, MAUI integration, Windows DPAPI, and the experimental filesystem store.

The filesystem backend is **EXPERIMENTAL / TEST ONLY** and MUST NOT be used for production secrets or irreplaceable keys. `Laveyana.Security.DependencyInjection` references that package; the dependency does **not** imply production approval.

**Known open issues:** SA-03 (snapshot rollback/replay), SA-04 (managed AES-GCM nonce lifetime on reopen/import/restore), SA-08 (filesystem crash/durability proof). Restoring/exporting old key material does not automatically authorize new AES-GCM encryption. MAUI platform behavior has not been validated on physical devices.

Read the [repository README](https://github.com/ivmu5/Laveyana.Security/blob/master/README.md) and [known limitations](https://github.com/ivmu5/Laveyana.Security/blob/master/docs/audit/Laveyana.Security.KnownLimitations.md) before adoption.

Source: https://github.com/ivmu5/Laveyana.Security

License: MIT. No stable API or production-security guarantee is implied by publishing these prerelease packages.
