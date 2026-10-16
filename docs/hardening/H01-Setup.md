# H01 — reproducible verification setup

This is a Phase 27 Partial Audit source snapshot with H01 verification configuration. **Production security gate remains NO-GO.** No .NET build or NUnit execution was possible in the authoring environment.

- SDK `10.0.400`, `rollForward=latestPatch`. Developer SDK `10.0.401` is compatible.
- Keep NUnit + VSTest. Platform tests report explicit skips, while TRX validation requires selected Windows/Linux tests to **pass** on their respective systems.
- Enable lock files in `Directory.Build.props`. **Authentic lock files are not included.** On a machine with .NET 10.0.4xx and access to NuGet, execute `./scripts/Initialize-LockFiles.ps1`, commit all generated `packages.lock.json` files, then push. The CI intentionally rejects missing/outdated locks via `--locked-mode`.
- Push and pull_request workflows build/test on Windows and Linux, emit TRX, and verify platform-specific successful results.
- The nightly workflow repeats both test suites three times on each platform; this is extended regression, not a comprehensive stress suite.
- Configure `main` branch protection in GitHub repository settings **after the first CI run**, requiring PRs and both platforms' status checks; branch restrictions cannot be enforced by files in this ZIP alone.
- Git initialization, remote repository creation, and NuGet publishing are not performed by this archive. All projects retain `IsPackable=false`.

For detailed instructions in Russian, see [H01-Setup.ru.md](H01-Setup.ru.md).
