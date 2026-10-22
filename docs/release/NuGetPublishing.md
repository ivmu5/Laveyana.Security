# Automated NuGet prerelease publishing

[Русский](NuGetPublishing.ru.md) | **English**

## Scope

NuGet packages are built for six explicit `src/` projects. Native Android and Apple platform projects, unit/integration tests and the experimental workbench are **not published**. The root `Directory.Build.props` retains `IsPackable=false`; six opted-in projects set `IsPackable=true`. Common package metadata and a safety-oriented README are in `Directory.Build.targets`.

CI on pull requests and `master` **packs but never publishes**. Publication happens **only** after the repository owner publishes a GitHub Release whose tag exactly matches the version in `Directory.Build.props` (e.g. `v1.2610.0-alpha.1`).

The workflow checks that the tagged commit is contained in `master`, re-runs Release build and tests, builds exactly six package artifacts and requests NuGet OIDC credentials **only** during the protected publish job. Releasing to nuget.org is irreversible for a given package ID/version; publishing six packages is not an atomic operation.

## One-time configuration (repository owner)

1. At **nuget.org**, sign in with the account that will own the packages. Select **Trusted Publishing** and add a GitHub policy with **Repository Owner = `ivmu5`**, **Repository = `Laveyana.Security`**, **Workflow File = `publish-nuget.yml`**, and **Environment = `nuget-release`**. Enter only the workflow filename, not a path. The policy must belong to the NuGet account that publishes the six package IDs.
2. In GitHub repository **Settings → Environments**, create `nuget-release` and configure **required reviewers** (and restrict deployments to release tags if supported). Without reviewer protection, creating the Release alone can publish after validation.
3. In GitHub repository **Settings → Secrets and variables → Actions → Variables**, add `NUGET_USERNAME`: your **NuGet.org account username**, not email. The username is not an API token. An environment variable with the same name also works. There is **no long-lived NuGet API key** stored in GitHub.
4. On first release check availability/ownership of all six package IDs on NuGet.org. NuGet Trusted Publishing policy ownership does not reserve third-party package IDs.
5. Merge workflow configuration after reviewing required CI checks. Initial `master` CI validates that all six `.nupkg` files can be built on Windows and Linux.

## Release operation

1. Bump `LaveyanaVersion` in `Directory.Build.props` through a normal PR. Wait until mandatory CI is green, then merge.
2. In **GitHub → Releases → Draft a new release**, create tag `v<VERSION>` targeting an already merged commit on `master`. Mark alpha/beta releases as **Pre-release** and publish.
3. Open **Actions → Publish NuGet**. The `prepare` job builds/tests/packs six packages. Once the GitHub `nuget-release` environment is approved, the `publish` job authenticates via NuGet Trusted Publishing/OIDC and uploads the exact package artifacts.
4. Confirm all six package IDs and version on NuGet.org, allowing for feed indexing delay. For a failed partial publication, investigate individual packages before rerunning; `--skip-duplicate` makes retries possible but does not prove file identity.

**Do not change a released version's package contents**: published versions are immutable; fix errors by incrementing version. Neither automated release nor NuGet listing closes SA-03, SA-04 or SA-08.

Official NuGet docs: https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing
