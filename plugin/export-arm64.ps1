$ErrorActionPreference = "Stop"
$Image = "koropwnz/stab-r2d2-plugin:0.2.5"
$OutputDirectory = Join-Path $PSScriptRoot "dist"
$OutputFile = Join-Path $OutputDirectory "stabh-web-proxy-0.2.5-arm64.tar"

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
docker buildx build `
    --platform linux/arm64 `
    --tag $Image `
    --output "type=docker,dest=$OutputFile" `
    $PSScriptRoot

Write-Host "Created $OutputFile"
Write-Host "Image tag inside the archive: $Image"
