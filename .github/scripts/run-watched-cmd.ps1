# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Runs one build command through cmd.exe with raw file redirection so that
# carriage-return progress output (cmake/ninja) reaches a log file even though
# PowerShell only surfaces complete newline-terminated lines. While the child
# runs, a heartbeat prints timestamped status: elapsed time, live compiler
# process counts, log size growth and the last log lines. A phase whose log
# stops growing while no compiler process remains alive is treated as stalled:
# diagnostics are dumped, the process tree is killed and the script fails.
#
# Usage:
#   & run-watched-cmd.ps1 -Phase windows-qt-build `
#       -Command 'cmake --build . --parallel 4' `
#       -WorkDir <dir> [-HeartbeatSeconds 60] [-StallTimeoutSeconds 1200]
#
# The exit code of the wrapped command is propagated as $LASTEXITCODE.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Phase,
    [Parameter(Mandatory = $true)][string]$Command,
    [string]$WorkDir = (Get-Location).Path,
    [int]$HeartbeatSeconds = 60,
    [int]$StallTimeoutSeconds = 1200,
    [string[]]$WatchedProcesses = @('cmake', 'ninja', 'cl', 'link', 'lib', 'midl', 'rc', 'mt')
)

$ErrorActionPreference = 'Stop'

if (-not $env:GITHUB_WORKSPACE) {
    $env:GITHUB_WORKSPACE = (Get-Location).Path
}
$log = Join-Path $env:GITHUB_WORKSPACE ("{0}.log" -f $Phase)
if (Test-Path -LiteralPath $log) {
    Remove-Item -LiteralPath $log -Force
}

function Get-LogTail {
    param([string]$Path, [int]$Lines)
    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $take = [Math]::Min($stream.Length, 65536)
            if ($take -le 0) { return @() }
            $null = $stream.Seek(-$take, 'End')
            $buffer = New-Object byte[] $take
            $read = $stream.Read($buffer, 0, $take)
            $text = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
        } finally {
            $stream.Close()
        }
        return @($text -split "`r?\n" | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -Last $Lines)
    } catch {
        return @()
    }
}

Write-Host ("[{0}] [{1}] start: {2}" -f (Get-Date -Format 'HH:mm:ss'), $Phase, $Command)
$argumentList = '/d /s /c "( ' + $Command + ' ) >> "' + $log + '" 2>&1"'
$child = Start-Process -FilePath $env:ComSpec -ArgumentList $argumentList `
    -WorkingDirectory $WorkDir -PassThru -WindowStyle Hidden
Write-Host ("[{0}] [{1}] pid={2} log={3}" -f (Get-Date -Format 'HH:mm:ss'), $Phase, $child.Id, $log)

# Immediate proof-of-life beat so an invocation is visible without waiting
# for the first periodic heartbeat.
$initialProcs = @(Get-Process -Name $WatchedProcesses -ErrorAction SilentlyContinue)
$initialNames = ($initialProcs | Group-Object Name | ForEach-Object { '{0}x{1}' -f $_.Name, $_.Count }) -join ','
if (-not $initialNames) { $initialNames = 'none' }
Write-Host ("[{0}] [{1}] heartbeat t=0 procs: {2}" -f `
    (Get-Date -Format 'HH:mm:ss'), $Phase, $initialNames)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$lastLength = -1L
$stalledSeconds = 0

while ($false -eq $child.HasExited) {
    Start-Sleep -Seconds $HeartbeatSeconds
    $procs = @(Get-Process -Name $WatchedProcesses -ErrorAction SilentlyContinue)
    $item = Get-Item -LiteralPath $log -ErrorAction SilentlyContinue
    $length = 0L
    if ($item) { $length = $item.Length }
    $delta = $length
    if ($lastLength -ge 0) { $delta = $length - $lastLength }
    $lastLength = $length

    $names = ($procs | Group-Object Name | ForEach-Object { '{0}x{1}' -f $_.Name, $_.Count }) -join ','
    if (-not $names) { $names = 'none' }
    Write-Host ("[{0}] [{1}] elapsed={2}m procs: {3} | bytes={4} (+{5})" -f `
        (Get-Date -Format 'HH:mm:ss'), $Phase, [int][math]::Floor($stopwatch.Elapsed.TotalMinutes), `
        $names, $length, $delta)

    foreach ($line in (Get-LogTail -Path $log -Lines 2)) {
        Write-Host ("    | {0}" -f $line)
    }

    if (($delta -le 0) -and ($procs.Count -eq 0)) {
        $stalledSeconds += $HeartbeatSeconds
        if ($stalledSeconds -ge $StallTimeoutSeconds) {
            Write-Host ("[{0}] [{1}] STALL detected: no output and no compiler process for {2}s." -f `
                (Get-Date -Format 'HH:mm:ss'), $Phase, $StallTimeoutSeconds)
            Write-Host "Last 20 log lines:" -ForegroundColor Yellow
            foreach ($line in (Get-LogTail -Path $log -Lines 20)) { Write-Host ("    | {0}" -f $line) }
            $null = & taskkill.exe /PID $child.Id /T /F 2>&1
            throw ("[{0}] stalled for {1}s with no output and no active compiler process" -f $Phase, $StallTimeoutSeconds)
        }
    } else {
        $stalledSeconds = 0
    }
}

$exitCode = $child.ExitCode
Add-Content -LiteralPath $log -Value ("[watcher] {0} exit={1} elapsed={2}s" -f $Phase, $exitCode, [int]$stopwatch.Elapsed.TotalSeconds)
Write-Host ("[{0}] [{1}] finished exit={2} elapsed={3}m" -f `
    (Get-Date -Format 'HH:mm:ss'), $Phase, $exitCode, [int][math]::Floor($stopwatch.Elapsed.TotalMinutes))

foreach ($line in (Get-LogTail -Path $log -Lines 5)) {
    Write-Host ("    | {0}" -f $line)
}

$global:LASTEXITCODE = $exitCode
if ($exitCode -ne 0) {
    throw ("[{0}] failed with exit code {1}; see {2}" -f $Phase, $exitCode, $log)
}
