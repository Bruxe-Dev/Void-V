param(
    [string]$Version = "2.0.0",
    [string]$BuildDir = "build"
)
$ErrorActionPreference = "Stop"

# Prepend MSYS2 UCRT64 so g++, strip, cmake, and ctest use the right libraries
$env:PATH = "C:\msys64\ucrt64\bin;" + $env:PATH

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    Write-Host "[1/5] Building Release binaries (void_vault.exe + void_vault.dll) and running CTest..."
    & powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\build.ps1" -BuildType Release -BuildDir $BuildDir
    if ($LASTEXITCODE -ne 0) { throw "Release build or tests failed" }

    $distDir = Join-Path $root "dist"
    $stageName = "void-vault-v$Version-windows-x64"
    $stageDir = Join-Path $distDir $stageName
    $zipPath = Join-Path $distDir "$stageName.zip"

    $sdkStageName = "void-vault-sdk-v$Version"
    $sdkStageDir = Join-Path $distDir $sdkStageName
    $sdkZipPath = Join-Path $distDir "$sdkStageName.zip"

    $shaPath = Join-Path $distDir "SHA256SUMS-v$Version.txt"

    if (Test-Path $stageDir)    { Remove-Item -Recurse -Force $stageDir }
    if (Test-Path $zipPath)     { Remove-Item -Force $zipPath }
    if (Test-Path $sdkStageDir) { Remove-Item -Recurse -Force $sdkStageDir }
    if (Test-Path $sdkZipPath)  { Remove-Item -Force $sdkZipPath }

    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
    New-Item -ItemType Directory -Force -Path $sdkStageDir | Out-Null

    Write-Host "[2/5] Staging standalone executable, shared library (DLL), and documentation..."
    $exeSource = Join-Path $root "$BuildDir\void_vault.exe"
    $dllSource = Join-Path $root "$BuildDir\void_vault.dll"
    $exeTarget = Join-Path $stageDir "void_vault.exe"
    $dllTarget = Join-Path $stageDir "void_vault.dll"

    Copy-Item $exeSource $exeTarget -Force
    if (Test-Path $dllSource) {
        Copy-Item $dllSource $dllTarget -Force
    }

    # Strip debug symbols from the staged release binaries for a smaller footprint
    $stripExe = "C:\msys64\ucrt64\bin\strip.exe"
    if (Test-Path $stripExe) {
        & $stripExe --strip-all $exeTarget
        if (Test-Path $dllTarget) {
            & $stripExe --strip-all $dllTarget
        }
    }

    Copy-Item (Join-Path $root "README.md")          $stageDir -Force
    Copy-Item (Join-Path $root "DEVELOPER_GUIDE.md") $stageDir -Force
    Copy-Item (Join-Path $root "SECURITY.md")        $stageDir -Force
    Copy-Item (Join-Path $root "LICENSE")            $stageDir -Force

    New-Item -ItemType Directory -Force -Path (Join-Path $stageDir "include") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $stageDir "sdk\python") | Out-Null
    Copy-Item (Join-Path $root "include\void_vault_c.h")       (Join-Path $stageDir "include\void_vault_c.h") -Force
    Copy-Item (Join-Path $root "sdk\python\void_vault.py")     (Join-Path $stageDir "sdk\python\void_vault.py") -Force
    Copy-Item (Join-Path $root "sdk\python\pyproject.toml")    (Join-Path $stageDir "sdk\python\pyproject.toml") -Force

    Write-Host "[3/5] Staging dedicated Developer Abstraction SDK bundle ($sdkStageName)..."
    Copy-Item $exeTarget (Join-Path $sdkStageDir "void_vault.exe") -Force
    if (Test-Path $dllTarget) {
        Copy-Item $dllTarget (Join-Path $sdkStageDir "void_vault.dll") -Force
    }
    Copy-Item (Join-Path $root "DEVELOPER_GUIDE.md") $sdkStageDir -Force
    Copy-Item (Join-Path $root "LICENSE")            $sdkStageDir -Force
    New-Item -ItemType Directory -Force -Path (Join-Path $sdkStageDir "include") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $sdkStageDir "sdk\python") | Out-Null
    Copy-Item (Join-Path $root "include\void_vault_c.h")       (Join-Path $sdkStageDir "include\void_vault_c.h") -Force
    Copy-Item (Join-Path $root "sdk\python\void_vault.py")     (Join-Path $sdkStageDir "sdk\python\void_vault.py") -Force
    Copy-Item (Join-Path $root "sdk\python\pyproject.toml")    (Join-Path $sdkStageDir "sdk\python\pyproject.toml") -Force

    Write-Host "[4/5] Creating release archives..."
    Compress-Archive -Path "$stageDir\*" -DestinationPath $zipPath -Force
    Compress-Archive -Path "$sdkStageDir\*" -DestinationPath $sdkZipPath -Force

    Write-Host "[5/5] Generating $shaPath ..."
    $exeHash    = (Get-FileHash -Algorithm SHA256 $exeTarget).Hash.ToLower()
    $dllHash    = if (Test-Path $dllTarget) { (Get-FileHash -Algorithm SHA256 $dllTarget).Hash.ToLower() } else { "n/a" }
    $zipHash    = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
    $sdkZipHash = (Get-FileHash -Algorithm SHA256 $sdkZipPath).Hash.ToLower()
    @(
        "$zipHash  $stageName.zip"
        "$sdkZipHash  $sdkStageName.zip"
        "$exeHash  void_vault.exe"
        "$dllHash  void_vault.dll"
    ) | Set-Content -Encoding ascii $shaPath

    Write-Host ""
    Write-Host "=== Release Packages Ready (v$Version) ==="
    Write-Host "Full Release Archive : $zipPath"
    Write-Host "Developer SDK Bundle : $sdkZipPath"
    Write-Host "SHA-256 Checksums    : $shaPath"
    Get-Content $shaPath
} finally {
    Pop-Location
}
