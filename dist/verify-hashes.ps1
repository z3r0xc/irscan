# verify-hashes.ps1 - prove this folder has not been altered since it was built.
#
# Recomputes the SHA256 of every file next to it and compares against
# SHA256SUMS.txt. Prints PASS or FAIL per file and exits non-zero if anything
# is missing, added, or different.
#
# Run:  powershell -ExecutionPolicy Bypass -File .\verify-hashes.ps1

$ErrorActionPreference = 'Stop'
$folder   = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifest = Join-Path $folder 'SHA256SUMS.txt'

if (-not (Test-Path -LiteralPath $manifest)) {
    Write-Host "FAIL  SHA256SUMS.txt is missing next to this script"
    exit 1
}

# sha256sum format: "<hash> *<name>" ('*' marks binary mode); tolerate two spaces.
$expected = @{}
foreach ($line in Get-Content -LiteralPath $manifest) {
    if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
        $expected[$Matches[2]] = $Matches[1].ToLower()
    }
}

if ($expected.Count -eq 0) {
    Write-Host "FAIL  SHA256SUMS.txt contains no usable entries"
    exit 1
}

$failed = 0

foreach ($name in ($expected.Keys | Sort-Object)) {
    $path = Join-Path $folder $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Host ("FAIL  {0}  (missing)" -f $name)
        $failed++
        continue
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
    if ($actual -eq $expected[$name]) {
        Write-Host ("PASS  {0}  {1}" -f $name, $actual)
    } else {
        Write-Host ("FAIL  {0}  expected {1}  actual {2}" -f $name, $expected[$name], $actual)
        $failed++
    }
}

# An unlisted file means the folder is not the one that was signed off, even if
# every listed file still matches.
$known = @($expected.Keys) + @('SHA256SUMS.txt')
foreach ($item in Get-ChildItem -LiteralPath $folder -File) {
    if ($known -notcontains $item.Name) {
        Write-Host ("FAIL  {0}  (not listed in SHA256SUMS.txt)" -f $item.Name)
        $failed++
    }
}

Write-Host ""
if ($failed -gt 0) {
    Write-Host "RESULT: FAIL ($failed file(s) did not verify)"
    exit 1
}
Write-Host "RESULT: PASS (all $($expected.Count) file(s) verified)"
exit 0
