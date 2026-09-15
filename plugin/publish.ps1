$ErrorActionPreference = "Stop"

$Image = "koropwnz/stab-r2d2-plugin"
$Version = "0.1.1"
$FullTag = "${Image}:${Version}"

docker buildx inspect --bootstrap | Out-Null
docker buildx build `
    --platform linux/arm64,linux/amd64 `
    --tag $FullTag `
    --push `
    $PSScriptRoot

Write-Host "Published $FullTag"
