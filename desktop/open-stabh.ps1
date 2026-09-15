param(
    [int[]]$Ports = @(18080, 15050)
)

$ErrorActionPreference = "Stop"

function Test-TcpPort {
    param(
        [string]$Address,
        [int]$TargetPort,
        [int]$TimeoutMilliseconds = 900
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.BeginConnect($Address, $TargetPort, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }
        $client.EndConnect($pending)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

$gateways = @(
    Get-NetIPConfiguration |
        Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" } |
        ForEach-Object { $_.IPv4DefaultGateway.NextHop }
)

$candidates = @(
    $gateways
    "10.70.175.1"
    "10.42.0.1"
    "192.168.4.1"
    "192.168.50.1"
    "192.168.1.1"
) | Where-Object { $_ } | Select-Object -Unique

foreach ($address in $candidates) {
    $available = @(
        $Ports | Where-Object {
            Write-Host "Checking http://${address}:$_/"
            Test-TcpPort -Address $address -TargetPort $_
        }
    )
    if ($available.Count -eq $Ports.Count) {
        foreach ($port in $Ports) {
            $url = "http://${address}:$port/"
            Write-Host "Opening $url"
            Start-Process $url
        }
        exit 0
    }
}

$shown = if ($gateways.Count -gt 0) { $gateways -join ", " } else { "none" }
throw "StabX proxy was not found on ports $($Ports -join ', '). Active IPv4 gateways: $shown. Connect to uapilot/uapilotstab and make sure the R2D2 plugin is running."
