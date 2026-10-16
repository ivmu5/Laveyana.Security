# Generate authentic NuGet lock files once on the developer's machine, then commit them.
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repositoryRoot
try {
    $version = (& dotnet --version)
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^10\.0\.4\d\d$') {
        throw "Expected .NET SDK 10.0.4xx in repository root, received: $version"
    }
    Write-Host "Using .NET SDK $version"
    & dotnet restore .\Laveyana.Security.sln --force-evaluate
    if ($LASTEXITCODE -ne 0) { throw 'NuGet restore failed; lock files were not verified.' }
    $locks = @(Get-ChildItem -Path .\src, .\tests -Recurse -File -Filter 'packages.lock.json')
    $required = @(
        'src/Laveyana.Security/packages.lock.json',
        'src/Laveyana.Security.DependencyInjection/packages.lock.json',
        'tests/Laveyana.Security.Tests/packages.lock.json',
        'tests/Laveyana.Security.IntegrationTests/packages.lock.json'
    )
    foreach ($relative in $required) {
        if (-not (Test-Path $relative)) { throw "Missing dependency lock file: $relative" }
    }
    & dotnet restore .\Laveyana.Security.sln --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Locked restore failed.' }
    Write-Host "Found $($locks.Count) lock files. Locked restore verified. Commit all packages.lock.json files."
}
finally { Pop-Location }
