#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end WinRAR password recovery: RAR5 header -> hashcat -> verify -> extract.

.EXAMPLE
    .\winrar_crack.ps1 -Archive "C:\Downloads\pack.rar" -Wordlist rockyou.txt -Extract

.EXAMPLE
    .\winrar_crack.ps1 -Archive "C:\Downloads\pack.rar" -Mask "?l?l?l?l?l?l"

.EXAMPLE
    .\winrar_crack.ps1 -Archive "C:\Downloads\pack.rar" -Wordlist rockyou.txt -Rule best64
#>
param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [string]$Wordlist,
    [string]$Mask,
    [string]$Rule,
    [string]$Hashcat = "hashcat",
    [string]$SevenZip = "$env:ProgramFiles\7-Zip\7z.exe",
    [switch]$Extract,
    [string]$OutDir,
    [int]$Workload = 3
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path $Archive)) { throw "archive not found: $Archive" }
if (-not $Wordlist -and -not $Mask) { throw "give -Wordlist, -Mask, or both" }
if (-not (Test-Path $SevenZip)) { throw "7z not found at $SevenZip (pass -SevenZip)" }

$work = Join-Path $env:TEMP ("winrar-crack-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null
$hashFile = Join-Path $work "rar5.hash"
$potFile = Join-Path $work "hashcat.pot"
$Archive = (Resolve-Path $Archive).Path
if ($Wordlist) { $Wordlist = (Resolve-Path $Wordlist).Path }

# hashcat resolves ./OpenCL and ./modules relative to the working directory
$hcExe = (Get-Command $Hashcat -ErrorAction SilentlyContinue).Source
if (-not $hcExe) { $hcExe = $Hashcat }
$hcDir = Split-Path -Parent $hcExe
if (-not (Test-Path (Join-Path $hcDir "OpenCL"))) {
    throw "run this from a hashcat folder layout: $hcDir has no OpenCL directory"
}
$hashFile = (Resolve-Path $work).Path + "\rar5.hash"
$potFile = (Resolve-Path $work).Path + "\hashcat.pot"

Write-Host "[1/4] extracting RAR5 hash from headers" -ForegroundColor Cyan
python (Join-Path $here "rar5_hash.py") hash $Archive -o $hashFile | Out-Null
$hash = (Get-Content $hashFile -TotalCount 1).Trim()
if (-not $hash) { throw "no encrypted entries found" }
Write-Host "      $hash" -ForegroundColor DarkGray

$attacks = @()
if ($Wordlist) {
    if (-not (Test-Path $Wordlist)) { throw "wordlist not found: $Wordlist" }
    $common = @(
        "-m", "13000", "-a", "0", $hashFile, $Wordlist,
        "--potfile-path", $potFile, "-w", "$Workload", "--force"
    )
    if ($Rule) { $common += @("-r", $Rule) }
    $attacks += , $common
}
if ($Mask) {
    $attacks += , @(
        "-m", "13000", "-a", "3", $hashFile, $Mask,
        "--potfile-path", $potFile, "-w", "$Workload", "--force"
    )
}

$password = $null
Push-Location $hcDir
try {
    foreach ($hcArgs in $attacks) {
        Write-Host "[2/4] hashcat $($hcArgs -join ' ')" -ForegroundColor Cyan
        & $hcExe @hcArgs
        $show = & $hcExe -m 13000 $hashFile --potfile-path $potFile --show
        if ($show) {
            $password = ($show -split ":", 2)[1].Trim()
            break
        }
    }
} finally {
    Pop-Location
}

if (-not $password) {
    Write-Host "[!] not recovered. Try a bigger wordlist, rules, or a mask." -ForegroundColor Yellow
    exit 1
}

Write-Host "[3/4] password: $password" -ForegroundColor Green
$ok = python (Join-Path $here "rar5_hash.py") verify $Archive $password
if ($LASTEXITCODE -ne 0) { throw "hashcat candidate failed local verification" }

if ($Extract) {
    if (-not $OutDir) {
        $OutDir = Join-Path (Split-Path -Parent $Archive) ([IO.Path]::GetFileNameWithoutExtension($Archive))
    }
    Write-Host "[4/4] extracting to $OutDir" -ForegroundColor Cyan
    & $SevenZip x $Archive "-p$password" "-o$OutDir" -y | Select-Object -Last 3
} else {
    Write-Host "[4/4] skipped extraction (pass -Extract)" -ForegroundColor DarkGray
}


