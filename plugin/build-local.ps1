$ErrorActionPreference = "Stop"
$Image = "koropwnz/stab-r2d2-plugin:0.1.2"

docker build --tag $Image .
Write-Host "Built $Image"
