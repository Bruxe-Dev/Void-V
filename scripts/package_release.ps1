param(
    [string]$Version = "1.0.0",
    [string]$BuildDir = "build"
)
$ErrorActionPreference = "Stop"

# Prepend MSYS2 UCRT64 so g++, strip, cmake, and ctest use the right libraries
$env:PATH = "C:\msys64\ucrt64\bin;" + $env:PATH

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    Write-Host "[1/4] Building Release binary and running CTest verification..."
    & powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\build.ps1" -BuildType Release -BuildDir $BuildDir
    if ($LASTEXITCODE -ne 0) { throw "Release build or tests failed" }

    $distDir = Join-Path $root "dist"
    $stageName = "void-vault-v$Version-windows-x64"
    $stageDir = Join-Path $distDir $stageName
    $zipPath = Join-Path $distDir "$stageName.zip"
    $shaPath = Join-Path $distDir "SHA256SUMS.txt"

    if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }
    if (Test-Path $zipPath)  { Remove-Item -Force $zipPath }
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

    Write-Host "[2/4] Staging standalone executable and documentation..."
    $exeSource = Join-Path $root "$BuildDir\void_vault.exe"
    $exeTarget = Join-Path $stageDir "void_vault.exe"
    Copy-Item $exeSource $exeTarget -Force

    # Strip debug symbols from the staged release binary for a smaller footprint
    $stripExe = "C:\msys64\ucrt64\bin\strip.exe"
    if (Test-Path $stripExe) {
        & $stripExe --strip-all $exeTarget
    }

    Copy-Item (Join-Path $root "README.md")          $stageDir -Force
    Copy-Item (Join-Path $root "DEVELOPER_GUIDE.md") $stageDir -Force
    Copy-Item (Join-Path $root "SECURITY.md")        $stageDir -Force
    Copy-Item (Join-Path $root "LICENSE")            $stageDir -Force

    New-Item -ItemType Directory -Force -Path (Join-Path $stageDir "include") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $stageDir "sdk\python") | Out-Null
    Copy-Item (Join-Path $root "include\void_vault_c.h")       (Join-Path $stageDir "include\void_vault_c.h") -Force
    Copy-Item (Join-Path $root "sdk\python\void_vault.py")     (Join-Path $stageDir "sdk\python\void_vault.py") -Force

    Write-Host "[3/4] Creating release archive $zipPath ..."
    Compress-Archive -Path "$stageDir\*" -DestinationPath $zipPath -Force

    Write-Host "[4/4] Generating SHA256SUMS.txt ..."
    $exeHash = (Get-FileHash -Algorithm SHA256 $exeTarget).Hash.ToLower()
    $zipHash = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
    @(
        "$zipHash  $stageName.zip"
        "$exeHash  void_vault.exe"
    ) | Set-Content -Encoding ascii $shaPath

    Write-Host ""
    Write-Host "=== Release Package Ready ==="
    Write-Host "Archive : $zipPath"
    Write-Host "SHA-256 : $shaPath"
    Get-Content $shaPath
} finally {
    Pop-Location
}
