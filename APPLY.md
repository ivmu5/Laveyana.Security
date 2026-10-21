# MAUI integration overlay — instructions

This ZIP is NOT a full replacement of Laveyana.Security. Copy its `src/`, `tests/`, `docs/`, and the updated root `.props`/`.sln` files into a clean repository clone **after reviewing differences**, preserving the relative paths. These root replacements were prepared against the observed `master` layout on 21 Oct 2026; if `.sln`, `Directory.Packages.props`, or tests `.csproj` changed meanwhile, merge those files rather than overwriting them.

No changes were pushed to GitHub. The code has not been compiled here (no .NET SDK or MAUI workload in this environment).

1. Review source and API. The module is **ISecretManagementProvider**, not IKeyStore or a protector.
2. Ensure Visual Studio / .NET 10 SDK and MAUI workloads are installed for real platform testing. The pure `net10.0` library is designed for normal build/CI without platform-specific workloads.
3. Regenerate NuGet locks using the repository's script in a safe dev environment; keep project policies and commit generated files. New package reference: `Microsoft.Maui.Essentials` 10.0.100.
4. Run repository validators, Release build, NUnit tests, and a real MAUI sample's Set/Get/Delete paths, including application reinstall/backup behaviors.
5. Only after successful tests and review: open a normal PR, let Windows/Linux checks run, merge, and revisit NuGet packaging.

KNOWN GAPS: package has not passed build/tests/platform checks. No durable key lifecycle guarantee, transactional CAS, rollback protection, secure deletion, nonce safety guarantee for reused keys, or automatic recovery.
