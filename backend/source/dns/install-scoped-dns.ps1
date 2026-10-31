param([switch]$PlanOnly, [switch]$Remove)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$guardDnsRoot = $PSScriptRoot
$guardRoot = Split-Path -Parent $guardDnsRoot
$guardTag = 'ClaudeNetworkGuard scoped DNS privacy v1'
$guardRoots = @('claude.ai','claude.com','anthropic.com','claude.app','claudeusercontent.com','claudemcpcontent.com')
$guardNamespaces = @($guardRoots | ForEach-Object { $_; '.' + $_ })
$guardReport = Join-Path $guardDnsRoot 'nrpt-installation.json'
Import-Module (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsClient.psd1')
Import-Module (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules\NetTCPIP\NetTCPIP.psd1')
if ((Get-Item -LiteralPath $guardRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected guard root refused' }
$guardExisting = @(Get-DnsClientNrptRule -ErrorAction Stop)
$guardOwned = @($guardExisting | Where-Object { $_.Comment -eq $guardTag })
$guardAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($PlanOnly) {
    [pscustomobject]@{mode='plan';administrator=$guardAdmin;namespaces=$guardNamespaces;nameServers=@('127.0.0.1');existingOwnedRules=$guardOwned.Count;defaultDnsWillChange=$false;systemTimezoneWillChange=$false} | ConvertTo-Json -Depth 4
    exit 0
}
if (-not $guardAdmin) { throw 'Administrator consent is required for scoped NRPT rules' }
if ($Remove) {
    foreach ($guardRule in $guardOwned) {
        $guardCheck = Get-DnsClientNrptRule -Name $guardRule.Name
        if ($guardCheck.Comment -ne $guardTag) { throw 'Rule ownership changed; preserved' }
        Remove-DnsClientNrptRule -Name $guardRule.Name -Force
    }
    [pscustomobject]@{outcome='removed_only_owned_rules';count=$guardOwned.Count} | ConvertTo-Json
    exit 0
}
$guardProcessFile = Join-Path $guardDnsRoot 'process.json'
$guardProcess = Get-Content -LiteralPath $guardProcessFile -Raw | ConvertFrom-Json
$guardUdp = @(Get-NetUDPEndpoint -LocalPort 53 | Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -eq $guardProcess.pid })
$guardTcp = @(Get-NetTCPConnection -State Listen -LocalPort 53 | Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -eq $guardProcess.pid })
if ($guardUdp.Count -ne 1 -or $guardTcp.Count -ne 1) { throw 'Owned loopback DNS UDP/TCP listeners are not ready' }
foreach ($guardRule in $guardExisting) {
    if ($guardRule.Comment -ne $guardTag -and @($guardRule.Namespace | Where-Object { $_ -in $guardNamespaces }).Count -gt 0) { throw 'Another policy overlaps the requested namespaces; preserved' }
}
if ($guardOwned.Count -gt 1) { throw 'Multiple previous owned rules require review; preserved' }
$guardCreated = $false
$guardNewRule = $null
try {
    if ($guardOwned.Count -eq 1) {
        $guardNewRule = $guardOwned[0]
    } else {
        $guardNewRule = Add-DnsClientNrptRule -Namespace $guardNamespaces -NameServers @('127.0.0.1') -DisplayName 'Claude scoped encrypted DNS' -Comment $guardTag -PassThru
        $guardCreated = $true
    }
    $guardVerified = Get-DnsClientNrptRule -Name $guardNewRule.Name
    $guardActualNamespaces = @($guardVerified.Namespace | Sort-Object)
    $guardExpectedNamespaces = @($guardNamespaces | Sort-Object)
    if (@(Compare-Object $guardExpectedNamespaces $guardActualNamespaces).Count -gt 0 -or @($guardVerified.NameServers).Count -ne 1 -or @($guardVerified.NameServers)[0] -ne '127.0.0.1') { throw 'Scoped NRPT verification failed' }
    [pscustomobject]@{outcome='installed';ruleName=$guardVerified.Name;comment=$guardTag;namespaces=$guardNamespaces;nameServers=@('127.0.0.1');created=$guardCreated;defaultDnsChanged=$false;systemTimezoneChanged=$false;at=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $guardReport -Encoding UTF8
    Get-Content -LiteralPath $guardReport -Raw
} catch {
    if ($guardCreated -and $guardNewRule) {
        $guardRollback = Get-DnsClientNrptRule -Name $guardNewRule.Name -ErrorAction SilentlyContinue
        if ($guardRollback -and $guardRollback.Comment -eq $guardTag) { Remove-DnsClientNrptRule -Name $guardRollback.Name -Force }
    }
    throw
}
