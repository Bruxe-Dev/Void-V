# Configure, build and test Void Vault with the MSYS2 UCRT64 toolchain.
# Usage (from the void-vault directory):
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1 [-BuildType Release|Debug] [-BuildDir build] [-SkipTests]
param(
    [string]$BuildType = "Release",
    [string]$BuildDir = "build",
    [string]$Msys2Bin = "C:\msys64\ucrt64\bin",
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# Anaconda (and other tools) ship libstdc++/zlib/libsodium DLLs that shadow MSYS2's
# and make cc1plus / test executables fail with 0xc0000139. Put MSYS2 first.
if (-not (Test-Path "$Msys2Bin\g++.exe")) { throw "g++ not found in $Msys2Bin" }
$env:PATH = "$Msys2Bin;" + $env:PATH

cmake -S . -B $BuildDir -G "MinGW Makefiles" "-DCMAKE_BUILD_TYPE=$BuildType"
if ($LASTEXITCODE -ne 0) { throw "configure failed" }
cmake --build $BuildDir -j 4
if ($LASTEXITCODE -ne 0) { throw "build failed" }
if (-not $SkipTests) {
    ctest --test-dir $BuildDir --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}
