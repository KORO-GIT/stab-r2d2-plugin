param(
    [string]$Version = "0.2.8",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $OutputPath) {
    $repoParent = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $OutputPath = Join-Path $repoParent "stabh-r2d2-plugin-$Version.tgz"
}

$required = @("start.sh", "plugin.py", "README.md", "vendor39", "vendor310", "vendor311", "vendor312")
foreach ($entry in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $entry))) {
        throw "Required package entry is missing: $entry"
    }
}

tar -czf $OutputPath `
    --exclude="*/__pycache__" `
    --exclude="*.pyc" `
    -C $PSScriptRoot `
    @required
if ($LASTEXITCODE -ne 0) {
    throw "tar failed with exit code $LASTEXITCODE"
}

$listing = @(tar -tzf $OutputPath)
if ($LASTEXITCODE -ne 0 -or -not ($listing -match "^vendor311/aiohttp/")) {
    throw "Package verification failed: vendor311/aiohttp is absent"
}

$file = Get-Item -LiteralPath $OutputPath
$hash = Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256
Write-Host "Created $($file.FullName)"
Write-Host "Size: $($file.Length) bytes"
Write-Host "SHA256: $($hash.Hash)"
