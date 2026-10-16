# H01 — build, CI and branch protection

**English** | [Русский](H01-Setup.ru.md)

**Status (16 October 2026):** verification infrastructure is operational. `Verify` completed successfully on Windows and Ubuntu, including source/documentation checks and both NUnit jobs. The repository remains pre-release and the Phase 27 security sign-off is **not** complete.

## Reproducible local verification

- .NET SDK is pinned by [`global.json`](../../global.json) to `10.0.400` with `latestPatch` (10.0.4xx feature band).
- Package versions are centrally managed in [`Directory.Packages.props`](../../Directory.Packages.props); generated `packages.lock.json` files are tracked. The restore must succeed in locked mode.
- NUnit 4 + NUnit3TestAdapter + VSTest are retained. Platform-specific tests use explicit skips only when the OS does not support them.
- Compiler warnings are errors. XML comments are required for published library source, not test fixture members.

Run from the repository root:

```sh
dotnet --version
dotnet restore Laveyana.Security.sln --locked-mode
python tools/verify_repository.py
python tools/verify_api_layout.py
python tools/verify_documentation.py
python tools/verify_documentation.py --self-test
dotnet build Laveyana.Security.sln --no-restore -c Release -warnaserror
dotnet test Laveyana.Security.sln --no-build --no-restore -c Release
```

After changing NuGet dependencies, regenerate locks via [`scripts/Initialize-LockFiles.ps1`](../../scripts/Initialize-LockFiles.ps1) on a trusted .NET SDK host, review and commit them. Never edit lock files manually to make CI pass.

## GitHub Actions

The `Verify` workflow runs on Push and Pull Request. Its required job/check names are:

1. `Source & docs`
2. `Build & NUnit (ubuntu-latest)`
3. `Build & NUnit (windows-latest)`

The build/test matrix uses Release and locked restores, produces TRX reports, and checks that platform-selected NUnit tests actually run.

The separate [`Nightly` workflow](../../.github/workflows/nightly.yml) is scheduled daily for **02:17 UTC** and supports manual launch via **Actions → Nightly → Run workflow** once the file reaches the default branch. On both `ubuntu-latest` and `windows-latest`, it performs one locked restore and one Release build, then runs **both complete NUnit test projects five times**, sequentially. Each attempt has distinct unit and integration TRX outputs; `tools/check_trx.py` validates **each attempt separately**, including mandatory platform test passes. Any failed test run or TRX validation fails the corresponding Nightly job, and reports are retained as artifacts for 14 days. Each runner has a 90-minute timeout.

Nightly is **not** a required `Protect master` status check: `Verify` remains the fast Pull Request gate. Scheduled workflows run from `master` only, so the first scheduled or manual run **cannot be confirmed before merge**. Repeated passing tests help discover intermittent regressions, but do not substitute for threat-model-driven adversarial tests, cross-process abuse testing or power-failure simulation.

The active `Protect master` GitHub ruleset targets the default branch (`master` on 16 October 2026): changes require a Pull Request, the three successful checks above, and an up-to-date branch. The ruleset blocks force-pushes and branch deletion. Required review approvals are currently zero. Avoid bypassing checks to expedite a release.

## Normal change workflow

```text
master (protected)
  -> create a topic branch
  -> edit, run local checks, commit
  -> push topic branch
  -> open Pull Request against master
  -> wait for Windows + Ubuntu + source/docs checks
  -> merge when all requirements pass
  -> synchronize local master
```

A new branch with no changes cannot produce a meaningful Pull Request; include a real, reviewable documentation or source change.

## Known verification boundaries

- Green CI establishes that the tested build and test suites pass on the CI runners. It is **not** an independent security audit or evidence of safe production storage.
- CI does not establish protection from Windows pathname replacement races, authenticated-snapshot replay, backup/restore nonce hazards or loss after sudden power failure.
- GitHub rulesets are repository settings, not files contained in source exports. If a fresh repository is created, reconfigure the ruleset and required checks.
- No automatic NuGet publication is configured; projects use `IsPackable=false`.

See [security findings](../audit/Laveyana.Security.Phase27.SecurityAudit.md) for outstanding release blockers and [compilation history](H01-CompilationRepair.md) for the earlier repairs that enabled this CI baseline.
