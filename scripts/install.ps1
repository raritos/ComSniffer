#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs ComSniffer.sys as a test-signed filter driver.
    Run in an elevated PowerShell window.

.NOTES
    Windows 10 must be in Test Signing mode for unsigned .sys files.
    ONLY do this on a dev/test machine — NOT production.

    To enable test signing:
        bcdedit /set testsigning on
        Restart-Computer

    To disable afterwards:
        bcdedit /set testsigning off
        Restart-Computer
#>

$DriverDir  = "$PSScriptRoot\..\driver"
$InfPath    = "$DriverDir\ComSniffer.inf"
$SysPath    = "$DriverDir\x64\Debug\ComSniffer.sys"   # adjust for Release if needed
$ServiceName = "ComSniffer"

function Write-Step($msg) { Write-Host ">> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "   OK: $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "   ERR: $msg" -ForegroundColor Red; exit 1 }

# ── 1. Check test signing ────────────────────────────────────────
Write-Step "Checking test signing mode..."
$bcd = bcdedit /enum "{current}" 2>&1 | Select-String "testsigning"
if ($bcd -notmatch "Yes") {
    Write-Host ""
    Write-Host "  Test signing is OFF." -ForegroundColor Yellow
    Write-Host "  Run as admin:  bcdedit /set testsigning on" -ForegroundColor Yellow
    Write-Host "  Then reboot and re-run this script." -ForegroundColor Yellow
    Write-Host ""
    Write-Err "Aborting — driver won't load without test signing."
}
Write-Ok "Test signing is enabled."

# ── 2. Self-sign the driver (dev cert) ──────────────────────────
Write-Step "Creating and applying self-signed test certificate..."
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -like "*ComSnifferTestCert*" } |
        Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ComSnifferTestCert" `
        -Type CodeSigningCert `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyUsage DigitalSignature
    Write-Ok "Created new test certificate."
} else {
    Write-Ok "Reusing existing test certificate."
}

# Trust it
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    "Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    "TrustedPublisher", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

# Sign the .sys
$thumbprint = $cert.Thumbprint
if (Test-Path $SysPath) {
    & signtool sign /sha1 $thumbprint /fd SHA256 /t http://timestamp.digicert.com $SysPath 2>&1
    Write-Ok "Signed: $SysPath"
} else {
    Write-Err "Driver binary not found at: $SysPath`n  Build the project in VS first."
}

# ── 3. Copy driver to System32\drivers ──────────────────────────
Write-Step "Copying driver to System32\drivers..."
$dest = "$env:SystemRoot\System32\drivers\ComSniffer.sys"
Copy-Item $SysPath $dest -Force
Write-Ok "Copied to $dest"

# ── 4. Register the service ──────────────────────────────────────
Write-Step "Registering kernel service..."
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "   Service already exists, stopping and deleting..."
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

sc.exe create $ServiceName `
    type= kernel `
    start= demand `
    binPath= $dest `
    DisplayName= "COM Port Sniffer Filter" | Out-Null

Write-Ok "Service created."

# ── 5. Install INF (adds UpperFilters to device class) ──────────
Write-Step "Installing INF (adds UpperFilters to Ports class)..."
& pnputil /add-driver $InfPath /install 2>&1
Write-Ok "INF installed."

# ── 6. Start service ─────────────────────────────────────────────
Write-Step "Starting service..."
sc.exe start $ServiceName
Start-Sleep -Seconds 1
$status = (Get-Service $ServiceName).Status
Write-Ok "Service status: $status"

# ── 7. Restart COM device ─────────────────────────────────────────
Write-Step "Restarting USB serial devices to attach filter..."
Get-PnpDevice -Class "Ports" | Where-Object { $_.Status -eq "OK" } | ForEach-Object {
    Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false
    Start-Sleep -Milliseconds 500
    Enable-PnpDevice  -InstanceId $_.InstanceId -Confirm:$false
}
Write-Ok "Devices restarted."

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host " ComSniffer installed and running!" -ForegroundColor Green
Write-Host " Start viewer:  python viewer\comsniffer_viewer.py" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
