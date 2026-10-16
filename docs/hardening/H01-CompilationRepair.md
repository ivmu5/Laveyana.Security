# H01 — first Visual Studio build corrections

Status: **source corrections prepared; compilation and NUnit still unverified**. This is not a production release.

## Addressed diagnostics

- `IDE0011`: inserted required braces around 52 control statements across source and test projects.
- `CS1591`: added English XML documentation to 46 previously undocumented public enum values across nine enums; did not suppress warnings.
- One top-level type per file: separated independent public and internal types while preserving names, accessibility, namespaces, and intentional partial-class files.
- `CS0006`: these missing reference-assembly errors are downstream of compilation failures and must be re-evaluated after correcting the original errors; reference checks were not removed.


## Additional compiler-diagnostic fixes (2026-10-16)

- `CS9108` had already been fixed in `SoftwareKeyReprotectionService`: no ref-like span captured by a nested lambda; a temporary copy is wiped in `finally`. The uploaded archive already contained that correction.
- `CS0618` in `KeyLifecycleTests`: replace the obsolete NUnit `TestDelegate` with `Action`, keeping the same exception assertion.
- `CS9174` in `SoftwareKeyReprotectionTests`: use an explicit `byte[]` for the `ReadOnlyMemory<byte>` parameter.
- `CS1591` in test projects: disable XML documentation generation **only** for the two test assemblies. XML docs remain mandatory for the five shipping library projects. Test fixtures are not public library APIs.
- `CA1416` in Windows DPAPI and ACL tests: add `[SupportedOSPlatform("windows")]` to Windows-only test methods, retaining runtime OS guards and `Assert.Ignore`. The non-Windows negative test remains.
- NuGet-generated lock files supplied in the user archive are retained; `.vs`, `bin`, and `obj` are excluded from the deliverable.

**Limit:** These are source-level fixes based on the supplied compiler diagnostics. No .NET SDK was available to compile or run NUnit in this preparation environment. A fresh Release build with warnings as errors and a test run is still required.

## Validation

- `python tools/verify_repository.py` — PASS.
- `python tools/verify_api_layout.py` — PASS (top-level type placement, enum documentation, control-statement braces).
- `python tools/verify_documentation.py` — PASS.
- .NET 10 Release build, Roslyn analysis, and NUnit — **not run in the archive preparation environment**. Run them in Visual Studio.

## Applying to an existing extracted folder

Extract into a **clean directory**, not on top of old sources: the obsolete `SoftwareKeyExceptions.cs` must not remain alongside the newly separated exception source files. Back up your existing directory and carry over genuine NuGet-generated `packages.lock.json` files into their corresponding project directories. This archive retains the actual NuGet-generated lock files supplied with the project; no lock files were fabricated.

Open the solution, select Release, and use **Build → Rebuild Solution**. If compilation still fails, retain the full error list and Build output. Do not suppress diagnostics to obtain a green result.

The Phase 27 security findings (Windows TOCTOU, snapshot rollback, nonce lifetime, and platform security acceptance) remain open.
