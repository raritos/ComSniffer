#Requires -RunAsAdministrator
<#  Uninstalls ComSniffer — stops service, removes INF, deletes .sys  #>

$ServiceName = "ComSniffer"

Write-Host ">> Stopping service..." -ForegroundColor Cyan
Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue

Write-Host ">> Deleting service..." -ForegroundColor Cyan
sc.exe delete $ServiceName | Out-Null

Write-Host ">> Removing INF from driver store..." -ForegroundColor Cyan
$oemInfs = pnputil /enum-drivers | Select-String -Pattern "ComSniffer" -Context 5
if ($oemInfs) {
    $oemInfs | ForEach-Object {
        if ($_ -match "(oem\d+\.inf)") {
            pnputil /delete-driver $Matches[1] /uninstall /force
        }
    }
}

Write-Host ">> Removing .sys binary..." -ForegroundColor Cyan
$sys = "$env:SystemRoot\System32\drivers\ComSniffer.sys"
if (Test-Path $sys) { Remove-Item $sys -Force }

Write-Host ">> Re-enabling devices..." -ForegroundColor Cyan
Get-PnpDevice -Class "Ports" | ForEach-Object {
    Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
}

Write-Host "Done. ComSniffer removed." -ForegroundColor Green
