# Install PromptSafe on Windows (PowerShell):
#   irm https://github.com/ayourr/PromptSafe/releases/latest/download/install.ps1 | iex
# Installs to %LOCALAPPDATA%\Programs\PromptSafe and adds it to your user PATH.
# Set $env:PROMPTSAFE_VERSION = "v0.2.0" first to install a given version.
$ErrorActionPreference = "Stop"
$repo = "ayourr/PromptSafe"
$version = if ($env:PROMPTSAFE_VERSION) { $env:PROMPTSAFE_VERSION } else { "latest" }
$base = if ($version -eq "latest") { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$version" }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$file = "promptsafe-windows-$arch.exe"
$dir = Join-Path $env:LOCALAPPDATA "Programs\PromptSafe"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$tmp = Join-Path $env:TEMP "promptsafe-$([guid]::NewGuid()).exe"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "Downloading $file ($version)..."
Invoke-WebRequest -UseBasicParsing -Uri "$base/$file" -OutFile $tmp
$sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt").Content
if ($sums -is [byte[]]) { $sums = [Text.Encoding]::UTF8.GetString($sums) }
$line = ($sums -split "`n") | Where-Object { $_ -match " $([regex]::Escape($file))\s*$" } | Select-Object -First 1
$want = if ($line) { ($line -split "\s+")[0].ToLower() } else { "" }
$got = (Get-FileHash -Algorithm SHA256 $tmp).Hash.ToLower()
if (-not $want -or $want -ne $got) {
    Remove-Item $tmp -Force
    throw "promptsafe: checksum mismatch, not installing"
}

$exe = Join-Path $dir "promptsafe.exe"
Move-Item -Force $tmp $exe

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $userPath) { $userPath = "" }
if (($userPath -split ";") -notcontains $dir) {
    [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $dir).TrimStart(";"), "User")
    $env:Path = "$env:Path;$dir"
    Write-Host "Added $dir to your PATH (open a new terminal to use it everywhere)."
}
Write-Host "Installed $(& $exe version) to $exe"
