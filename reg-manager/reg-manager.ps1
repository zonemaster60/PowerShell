#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =========================
# Registry Backup/Restore UI
# PowerShell 5.1
# =========================

$Script:ProgramVersion = '1.0.0.0'
$Script:ProgramName = if ($PSCommandPath) { Split-Path -Leaf $PSCommandPath } else { 'reg-backup.ps1' }
$Script:ProgramBaseName = [IO.Path]::GetFileNameWithoutExtension($Script:ProgramName)

function Test-IsAdmin {
  <#
      .SYNOPSIS
      Describe purpose of "Test-IsAdmin" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Test-IsAdmin
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Test-IsAdmin

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegExePath {
  <#
      .SYNOPSIS
      Describe purpose of "Get-RegExePath" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-RegExePath
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-RegExePath

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    # Avoid WOW64 registry redirection when running 32-bit PowerShell on 64-bit Windows
    $windir = $env:WINDIR
    $sysnative = Join-Path $windir 'sysnative\reg.exe'
    $system32 = Join-Path $windir 'System32\reg.exe'

    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and (Test-Path -LiteralPath $sysnative)) {
        return $sysnative
    }

    if (-not (Test-Path -LiteralPath $system32)) { throw ('reg.exe not found at: {0}' -f $system32) }
    return $system32
}

function Get-ScriptDir {
  <#
      .SYNOPSIS
      Describe purpose of "Get-ScriptDir" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-ScriptDir
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-ScriptDir

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    if ($PSScriptRoot) { return $PSScriptRoot }
    return (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

function Ensure-Folder([string]$Path) {
  <#
      .SYNOPSIS
      Describe purpose of "Ensure-Folder" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Describe parameter -Path.

      .EXAMPLE
      Ensure-Folder -Path Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Ensure-Folder

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -ItemType Directory -Path -LiteralPath $Path -Force
    }
}

function Quote-CmdArg([string]$Value) {
  <#
      .SYNOPSIS
      Describe purpose of "Quote-CmdArg" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Value
      Describe parameter -Value.

      .EXAMPLE
      Quote-CmdArg -Value Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Quote-CmdArg

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    if ($null -eq $Value) { return '""' }
    if ($Value -match '[\s"]') {
        return '"' + ($Value -replace '"', '\\"') + '"'
    }
    return $Value
}

function Write-Header([string]$Title) {
  <#
      .SYNOPSIS
      Describe purpose of "Write-Header" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Title
      Describe parameter -Title.

      .EXAMPLE
      Write-Header -Title Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Write-Header

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    Clear-Host
    $line = ('=' * 36)
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("{0}  v{1}" -f $Title, $Script:ProgramVersion)
    Write-Host $line -ForegroundColor Cyan
}

function Read-Choice {
  <#
      .SYNOPSIS
      Describe purpose of "Read-Choice" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Prompt
      Describe parameter -Prompt.

      .PARAMETER ValidChoices
      Describe parameter -ValidChoices.

      .EXAMPLE
      Read-Choice -Prompt Value -ValidChoices Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Read-Choice

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$true)][int[]]$ValidChoices
    )
    while ($true) {
        $raw = Read-Host $Prompt
        $n = 0
        if ([int]::TryParse($raw, [ref]$n) -and ($ValidChoices -contains $n)) {
            return $n
        }
        Write-Host ('Invalid choice. Valid: {0}' -f ($ValidChoices -join ', ')) -ForegroundColor Yellow
    }
}

function Read-NonEmpty([string]$Prompt) {
  <#
      .SYNOPSIS
      Describe purpose of "Read-NonEmpty" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Prompt
      Describe parameter -Prompt.

      .EXAMPLE
      Read-NonEmpty -Prompt Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Read-NonEmpty

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    while ($true) {
        $v = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim() }
        Write-Host "Value cannot be empty." -ForegroundColor Yellow
    }
}

function Read-YesNo([string]$Prompt, [bool]$DefaultYes = $true) {
  <#
      .SYNOPSIS
      Describe purpose of "Read-YesNo" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Prompt
      Describe parameter -Prompt.

      .PARAMETER DefaultYes
      Describe parameter -DefaultYes.

      .EXAMPLE
      Read-YesNo -Prompt Value -DefaultYes Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Read-YesNo

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $v = (Read-Host ('{0} {1}' -f $Prompt, $suffix)).Trim()
        if ($v -eq '') { return $DefaultYes }
        switch -Regex ($v) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-Host "Enter y or n." -ForegroundColor Yellow }
        }
    }
}

function Format-Timestamp {
  <#
      .SYNOPSIS
      Describe purpose of "Format-Timestamp" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Format-Timestamp
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Format-Timestamp

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    return (Get-Date).ToString('yyyyMMdd-HHmmss')
}

function ConvertTo-RegExeKey([string]$KeyPath) {
  <#
      .SYNOPSIS
      Describe purpose of "ConvertTo-RegExeKey" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER KeyPath
      Describe parameter -KeyPath.

      .EXAMPLE
      ConvertTo-RegExeKey -KeyPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online ConvertTo-RegExeKey

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $k = $KeyPath.Trim()

    # Accept PowerShell provider style: HKLM:\SOFTWARE or Registry::HKEY_LOCAL_MACHINE\SOFTWARE
    if ($k -match '^(Registry::)?HKEY_LOCAL_MACHINE\\') { $k = $k -replace '^(Registry::)?HKEY_LOCAL_MACHINE\\', 'HKLM\' }
    if ($k -match '^(Registry::)?HKEY_CURRENT_USER\\')  { $k = $k -replace '^(Registry::)?HKEY_CURRENT_USER\\', 'HKCU\' }
    if ($k -match '^(Registry::)?HKEY_CLASSES_ROOT\\')  { $k = $k -replace '^(Registry::)?HKEY_CLASSES_ROOT\\', 'HKCR\' }
    if ($k -match '^(Registry::)?HKEY_USERS\\')         { $k = $k -replace '^(Registry::)?HKEY_USERS\\', 'HKU\' }
    if ($k -match '^(Registry::)?HKEY_CURRENT_CONFIG\\'){ $k = $k -replace '^(Registry::)?HKEY_CURRENT_CONFIG\\', 'HKCC\' }

    $k = $k -replace '^HKLM:\\', 'HKLM\'
    $k = $k -replace '^HKCU:\\', 'HKCU\'
    $k = $k -replace '^HKCR:\\', 'HKCR\'
    $k = $k -replace '^HKU:\\',  'HKU\'
    $k = $k -replace '^HKCC:\\', 'HKCC\'

    # Accept full root (no trailing backslash required)
    switch -Regex ($k.ToUpperInvariant()) {
        '^HKEY_LOCAL_MACHINE' { $k = $k -replace '^HKEY_LOCAL_MACHINE', 'HKLM' }
        '^HKEY_CURRENT_USER'  { $k = $k -replace '^HKEY_CURRENT_USER',  'HKCU' }
        '^HKEY_CLASSES_ROOT'  { $k = $k -replace '^HKEY_CLASSES_ROOT',  'HKCR' }
        '^HKEY_USERS'       { $k = $k -replace '^HKEY_USERS',         'HKU' }
        '^HKEY_CURRENT_CONFIG'{ $k = $k -replace '^HKEY_CURRENT_CONFIG', 'HKCC' }
    }

    # Normalize accidental double slashes
    $k = $k -replace '\\{2,}', '\'
    return $k
}

function Get-SafeFileName([string]$KeyPath) {
  <#
      .SYNOPSIS
      Describe purpose of "Get-SafeFileName" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER KeyPath
      Describe parameter -KeyPath.

      .EXAMPLE
      Get-SafeFileName -KeyPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-SafeFileName

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    # Turn HKLM\SOFTWARE\Foo into HKLM_SOFTWARE_Foo.reg
    $s = (ConvertTo-RegExeKey $KeyPath)
    $s = $s -replace '[:\s]', ''
    $s = $s -replace '[\\\/]', '_'
    $s = $s -replace '[^\w\.\-]', '_'
    if ($s.Length -gt 160) { $s = $s.Substring(0, 160) }
    return $s
}

function Get-FileSha256([string]$Path) {
  <#
      .SYNOPSIS
      Describe purpose of "Get-FileSha256" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Describe parameter -Path.

      .EXAMPLE
      Get-FileSha256 -Path Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-FileSha256

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $h = Get-FileHash -Algorithm SHA256 -LiteralPath $Path
    return $h.Hash
}

function Start-Log([string]$LogPath) {
  <#
      .SYNOPSIS
      Describe purpose of "Start-Log" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER LogPath
      Describe parameter -LogPath.

      .EXAMPLE
      Start-Log -LogPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Start-Log

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    Ensure-Folder (Split-Path -Parent $LogPath)
    "Log started: $(Get-Date -Format o)" | Out-File -LiteralPath $LogPath -Encoding UTF8
}

function Write-Log([string]$LogPath, [string]$Message) {
  <#
      .SYNOPSIS
      Describe purpose of "Write-Log" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER LogPath
      Describe parameter -LogPath.

      .PARAMETER Message
      Describe parameter -Message.

      .EXAMPLE
      Write-Log -LogPath Value -Message Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Write-Log

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $line | Out-File -LiteralPath $LogPath -Append -Encoding UTF8
}

function Get-DefaultConfig {
  <#
      .SYNOPSIS
      Describe purpose of "Get-DefaultConfig" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-DefaultConfig
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-DefaultConfig

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $defaultRoot = Join-Path $env:USERPROFILE 'Documents\RegistryBackups'
    return [ordered]@{
        BackupRoot = $defaultRoot
        AutoZipAfterBackup = $false
        IncludeHashes = $true
    }
}

function Get-ConfigPath {
  <#
      .SYNOPSIS
      Describe purpose of "Get-ConfigPath" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-ConfigPath
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-ConfigPath

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $dir = Get-ScriptDir
    $new = Join-Path $dir ("{0}.config.json" -f $Script:ProgramBaseName)
    $legacy = Join-Path $dir 'RegistryBackupRestore.config.json'

    # Back-compat: read legacy config if present and new file doesn't exist yet
    if ((Test-Path -LiteralPath $legacy) -and -not (Test-Path -LiteralPath $new)) { return $legacy }
    return $new
}

function Load-Config {
  <#
      .SYNOPSIS
      Describe purpose of "Load-Config" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Load-Config
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Load-Config

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $p = Get-ConfigPath
    $d = Get-DefaultConfig
    if (-not (Test-Path -LiteralPath $p)) { return $d }

    try {
        $raw = Get-Content -LiteralPath $p -Raw -Encoding UTF8
        $o = $raw | ConvertFrom-Json

        # Merge defaults
        if (-not $o.PSObject.Properties.Match('BackupRoot')) { $o | Add-Member NoteProperty BackupRoot $d.BackupRoot }
        if (-not $o.PSObject.Properties.Match('AutoZipAfterBackup')) { $o | Add-Member NoteProperty AutoZipAfterBackup $d.AutoZipAfterBackup }
        if (-not $o.PSObject.Properties.Match('IncludeHashes')) { $o | Add-Member NoteProperty IncludeHashes $d.IncludeHashes }

        return @{
            BackupRoot = [string]$o.BackupRoot
            AutoZipAfterBackup = [bool]$o.AutoZipAfterBackup
            IncludeHashes = [bool]$o.IncludeHashes
        }
    } catch {
        return $d
    }
}

function Save-Config([hashtable]$Config) {
  <#
      .SYNOPSIS
      Describe purpose of "Save-Config" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .EXAMPLE
      Save-Config -Config Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Save-Config

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $p = Get-ConfigPath
    $Config | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $p -Encoding UTF8
}

function New-BackupSession([hashtable]$Config, [string]$Label) {
  <#
      .SYNOPSIS
      Describe purpose of "New-BackupSession" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .PARAMETER Label
      Describe parameter -Label.

      .EXAMPLE
      New-BackupSession -Config Value -Label Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online New-BackupSession

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $root = $Config.BackupRoot
    Ensure-Folder $root

    $ts = Format-Timestamp
    $safeLabel = ($Label -replace '[^\w\.\- ]', '_').Trim()
    if ($safeLabel -eq '') { $safeLabel = 'Backup' }
    $safeLabel = $safeLabel -replace '\s+', '_'

    $folderName = "{0}_{1}_{2}" -f $ts, $env:COMPUTERNAME, $safeLabel
    $sessionPath = Join-Path $root $folderName
    Ensure-Folder $sessionPath

    $logPath = Join-Path $sessionPath 'backup.log'
    Start-Log $logPath

    return @{
        SessionPath = $sessionPath
        LogPath = $logPath
        Timestamp = $ts
        Label = $Label
    }
}

function Export-RegistryKey {
  <#
      .SYNOPSIS
      Describe purpose of "Export-RegistryKey" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER KeyPath
      Describe parameter -KeyPath.

      .PARAMETER OutFile
      Describe parameter -OutFile.

      .PARAMETER LogPath
      Describe parameter -LogPath.

      .EXAMPLE
      Export-RegistryKey -KeyPath Value -OutFile Value -LogPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Export-RegistryKey

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    param(
        [Parameter(Mandatory=$true)][string]$KeyPath,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [Parameter(Mandatory=$true)][string]$LogPath
    )

    $reg = Get-RegExePath
    $key = ConvertTo-RegExeKey $KeyPath

    Ensure-Folder (Split-Path -Parent $OutFile)

    # Windows PowerShell 5.1: Start-Process -ArgumentList is a string; build a correctly-quoted command line.
    $argString = ('export {0} {1} /y' -f (Quote-CmdArg $key), (Quote-CmdArg $OutFile))
    Write-Log $LogPath ("EXPORT: reg.exe {0}" -f $argString)

    $p = Start-Process -FilePath $reg -ArgumentList $argString -Wait -NoNewWindow -PassThru
    if ($p.ExitCode -ne 0) {
        throw ('Export failed (exit code {0}) for key: {1}' -f $p.ExitCode, $key)
    }
}

function Import-RegistryFile {
  <#
      .SYNOPSIS
      Describe purpose of "Import-RegistryFile" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER RegFile
      Describe parameter -RegFile.

      .PARAMETER LogPath
      Describe parameter -LogPath.

      .EXAMPLE
      Import-RegistryFile -RegFile Value -LogPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Import-RegistryFile

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    param(
        [Parameter(Mandatory=$true)][string]$RegFile,
        [Parameter(Mandatory=$true)][string]$LogPath
    )

    $reg = Get-RegExePath
    if (-not (Test-Path -LiteralPath $RegFile)) { throw ('REG file not found: {0}' -f $RegFile) }

    # Windows PowerShell 5.1: Start-Process -ArgumentList is a string; build a correctly-quoted command line.
    $argString = ('import {0}' -f (Quote-CmdArg $RegFile))
    Write-Log $LogPath ("IMPORT: reg.exe {0}" -f $argString)

    $p = Start-Process -FilePath $reg -ArgumentList $argString -Wait -NoNewWindow -PassThru
    if ($p.ExitCode -ne 0) {
        throw ('Import failed (exit code {0}) for file: {1}' -f $p.ExitCode, $RegFile)
    }
}

function Build-ManifestObject {
  <#
      .SYNOPSIS
      Describe purpose of "Build-ManifestObject" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Session
      Describe parameter -Session.

      .PARAMETER Config
      Describe parameter -Config.

      .PARAMETER Entries
      Describe parameter -Entries.

      .EXAMPLE
      Build-ManifestObject -Session Value -Config Value -Entries Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Build-ManifestObject

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    param(
        [Parameter(Mandatory=$true)][hashtable]$Session,
        [Parameter(Mandatory=$true)][hashtable]$Config,
        [Parameter(Mandatory=$true)][Collections.ArrayList]$Entries
    )

    $isAdmin = Test-IsAdmin
    $os = Get-CimInstance Win32_OperatingSystem

    return [ordered]@{
        Program = $Script:ProgramName
        ProgramVersion = $Script:ProgramVersion
        CreatedAt = (Get-Date).ToString('o')
        ComputerName = $env:COMPUTERNAME
        UserName = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin = $isAdmin
        OS = [ordered]@{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
        }
        Backup = [ordered]@{
            Label = $Session.Label
            SessionPath = $Session.SessionPath
            EntryCount = $Entries.Count
            IncludeHashes = [bool]$Config.IncludeHashes
            Entries = $Entries
        }
    }
}

function Write-Manifest([hashtable]$Manifest, [string]$Path) {
  <#
      .SYNOPSIS
      Describe purpose of "Write-Manifest" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Manifest
      Describe parameter -Manifest.

      .PARAMETER Path
      Describe parameter -Path.

      .EXAMPLE
      Write-Manifest -Manifest Value -Path Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Write-Manifest

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $Manifest | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $Path -Encoding UTF8
}

function Get-BackupFolders([hashtable]$Config) {
  <#
      .SYNOPSIS
      Describe purpose of "Get-BackupFolders" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .EXAMPLE
      Get-BackupFolders -Config Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-BackupFolders

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $root = $Config.BackupRoot
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    Get-ChildItem -LiteralPath $root -Directory | Sort-Object Name -Descending
}

function Select-BackupSession([hashtable]$Config) {
  <#
      .SYNOPSIS
      Describe purpose of "Select-BackupSession" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .EXAMPLE
      Select-BackupSession -Config Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Select-BackupSession

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $folders = @(Get-BackupFolders $Config)
    if ($folders.Count -eq 0) {
        Write-Host ('No backups found in: {0}' -f $Config.BackupRoot) -ForegroundColor Yellow
        $null = Read-Host "Press Enter to continue"
        return $null
    }

    Write-Host ('Backups in: {0}' -f $Config.BackupRoot)
    for ($i = 0; $i -lt $folders.Count; $i++) {
        $m = Join-Path $folders[$i].FullName 'manifest.json'
        $tag = if (Test-Path -LiteralPath $m) { 'manifest' } else { 'no-manifest' }
        Write-Host ("[{0}] {1} ({2})" -f ($i + 1), $folders[$i].Name, $tag)
    }
    Write-Host "[0] Cancel"

    $valid = @(0..$folders.Count)
    $choice = Read-Choice -Prompt "Select a backup" -ValidChoices $valid
    if ($choice -eq 0) { return $null }
    return $folders[$choice - 1].FullName
}

function Ensure-ZipAssembly {
  <#
      .SYNOPSIS
      Describe purpose of "Ensure-ZipAssembly" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Ensure-ZipAssembly
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Ensure-ZipAssembly

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    Add-Type -AssemblyName System.IO.Compression.FileSystem
}

function Zip-Folder([string]$FolderPath, [string]$ZipPath) {
  <#
      .SYNOPSIS
      Describe purpose of "Zip-Folder" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER FolderPath
      Describe parameter -FolderPath.

      .PARAMETER ZipPath
      Describe parameter -ZipPath.

      .EXAMPLE
      Zip-Folder -FolderPath Value -ZipPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Zip-Folder

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    Ensure-ZipAssembly
    if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
    [IO.Compression.ZipFile]::CreateFromDirectory($FolderPath, $ZipPath)
}

function Try-CreateRestorePoint([string]$LogPath) {
  <#
      .SYNOPSIS
      Describe purpose of "Try-CreateRestorePoint" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER LogPath
      Describe parameter -LogPath.

      .EXAMPLE
      Try-CreateRestorePoint -LogPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Try-CreateRestorePoint

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    try {
        $null = Checkpoint-Computer -Description ("Registry restore ({0})" -f $Script:ProgramBaseName) -RestorePointType "MODIFY_SETTINGS"
        Write-Log $LogPath "Created system restore point."
        return $true
    } catch {
        Write-Log $LogPath ("Restore point creation failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Predefined-KeySets {
  <#
      .SYNOPSIS
      Describe purpose of "Predefined-KeySets" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Predefined-KeySets
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Predefined-KeySets

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    return @(
        [ordered]@{
            Name = 'Common (HKCU + HKLM\SOFTWARE + HKLM\SYSTEM)'
            Keys = @('HKCU', 'HKLM\SOFTWARE', 'HKLM\SYSTEM')
        },
        [ordered]@{
            Name = 'User Profile (HKCU)'
            Keys = @('HKCU')
        },
        [ordered]@{
            Name = 'Machine Software (HKLM\SOFTWARE)'
            Keys = @('HKLM\SOFTWARE')
        },
        [ordered]@{
            Name = 'Machine System (HKLM\SYSTEM)'
            Keys = @('HKLM\SYSTEM')
        },
        [ordered]@{
            Name = 'Shell + Run Keys (common autoruns)'
            Keys = @(
                'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer',
                'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies'
            )
        },
        [ordered]@{
            Name = 'All Roots (HKLM + HKCU + HKCR + HKU + HKCC) (very large)'
            Keys = @('HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC')
        }
    )
}

function Run-BackupFlow([hashtable]$Config, [string[]]$Keys, [string]$Label) {
  <#
      .SYNOPSIS
      Describe purpose of "Run-BackupFlow" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .PARAMETER Keys
      Describe parameter -Keys.

      .PARAMETER Label
      Describe parameter -Label.

      .EXAMPLE
      Run-BackupFlow -Config Value -Keys Value -Label Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Run-BackupFlow

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $session = New-BackupSession -Config $Config -Label $Label
    $entries = New-Object System.Collections.ArrayList

    Write-Header "Registry Backup"
    Write-Host ('Destination: {0}' -f $session.SessionPath)
    Write-Host "Keys:"
    $Keys | ForEach-Object { Write-Host (' - {0}' -f $_) }
    Write-Host ""

    $proceed = Read-YesNo "Start backup now?" $true
    if (-not $proceed) { return }

    foreach ($k in $Keys) {
        $safe = Get-SafeFileName $k
        $out = Join-Path $session.SessionPath ("{0}.reg" -f $safe)

        try {
            Export-RegistryKey -KeyPath $k -OutFile $out -LogPath $session.LogPath
            $fi = Get-Item -LiteralPath $out

            $entry = [ordered]@{
                KeyPath = (ConvertTo-RegExeKey $k)
                File = (Split-Path -Leaf $out)
                SizeBytes = [long]$fi.Length
                ExportedAt = (Get-Date).ToString('o')
            }
            if ($Config.IncludeHashes) {
                $entry.Sha256 = Get-FileSha256 $out
            }
            $null = $entries.Add($entry)

            Write-Host ("OK  {0}" -f $k) -ForegroundColor Green
            Write-Log $session.LogPath ("OK: {0} -> {1}" -f $k, $out)
        } catch {
            Write-Host ("FAIL {0}" -f $k) -ForegroundColor Red
            Write-Log $session.LogPath ("FAIL: {0} : {1}" -f $k, $_.Exception.Message)
        }
    }

    $manifest = Build-ManifestObject -Session $session -Config $Config -Entries $entries
    $manifestPath = Join-Path $session.SessionPath 'manifest.json'
    Write-Manifest -Manifest $manifest -Path $manifestPath
    Write-Log $session.LogPath ("Wrote manifest: {0}" -f $manifestPath)

    if ($Config.AutoZipAfterBackup) {
        try {
            $zipPath = ('{0}.zip' -f $session.SessionPath)
            Zip-Folder -FolderPath $session.SessionPath -ZipPath $zipPath
            Write-Log $session.LogPath ("Created zip: {0}" -f $zipPath)
            Write-Host ("ZIP created: {0}" -f $zipPath) -ForegroundColor Cyan
        } catch {
            Write-Log $session.LogPath ("ZIP failed: {0}" -f $_.Exception.Message)
            Write-Host ("ZIP failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Done."
    Write-Host ('Manifest: {0}' -f $manifestPath)
    Write-Host ('Log:      {0}' -f $session.LogPath)
    $null = Read-Host "Press Enter to continue"
}

function Verify-BackupManifest([string]$ManifestPath) {
  <#
      .SYNOPSIS
      Describe purpose of "Verify-BackupManifest" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER ManifestPath
      Describe parameter -ManifestPath.

      .EXAMPLE
      Verify-BackupManifest -ManifestPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Verify-BackupManifest

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    if (-not (Test-Path -LiteralPath $ManifestPath)) { throw ('Manifest not found: {0}' -f $ManifestPath) }
    $raw = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8
    $m = $raw | ConvertFrom-Json

    $base = Split-Path -Parent $ManifestPath
    $ok = $true
    $checked = 0

    foreach ($e in $m.Backup.Entries) {
        $checked++
        $p = Join-Path $base $e.File
        if (-not (Test-Path -LiteralPath $p)) {
            Write-Host ("MISSING {0}" -f $e.File) -ForegroundColor Red
            $ok = $false
            continue
        }

        if ($m.Backup.IncludeHashes -and $e.PSObject.Properties.Match('Sha256').Count -gt 0) {
            $h = Get-FileSha256 $p
            if ($h -ne $e.Sha256) {
                Write-Host ("HASH-MISMATCH {0}" -f $e.File) -ForegroundColor Red
                $ok = $false
            } else {
                Write-Host ("OK {0}" -f $e.File) -ForegroundColor Green
            }
        } else {
            Write-Host ("OK {0} (no hash check)" -f $e.File) -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host ("Checked: {0} file(s)" -f $checked)
    if ($ok) { Write-Host "Verification: PASS" -ForegroundColor Green }
    else { Write-Host "Verification: FAIL" -ForegroundColor Red }

    return $ok
}

function Restore-FromManifest([string]$ManifestPath) {
  <#
      .SYNOPSIS
      Describe purpose of "Restore-FromManifest" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER ManifestPath
      Describe parameter -ManifestPath.

      .EXAMPLE
      Restore-FromManifest -ManifestPath Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Restore-FromManifest

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $base = Split-Path -Parent $ManifestPath
    $logPath = Join-Path $base 'restore.log'
    Start-Log $logPath

    $raw = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8
    $m = $raw | ConvertFrom-Json

    Write-Header "Registry Restore"
    Write-Host ('Backup: {0}' -f $base)
    Write-Host ('Entries: {0}' -f $m.Backup.EntryCount)
    Write-Host ""

    if (Read-YesNo "Verify files before restore?" $true) {
        try {
            $pass = Verify-BackupManifest -ManifestPath $ManifestPath
            if (-not $pass) {
                if (-not (Read-YesNo "Verification failed. Continue anyway?" $false)) { return }
            }
        } catch {
            Write-Host ("Verification error: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            if (-not (Read-YesNo "Continue anyway?" $false)) { return }
        }
        Write-Host ""
    }

    $makeRp = Read-YesNo "Create a system restore point (if supported)?" $true
    if ($makeRp) {
        $rpOk = Try-CreateRestorePoint -LogPath $logPath
        if ($rpOk) { Write-Host "Restore point created." -ForegroundColor Green }
        else { Write-Host "Restore point not created (see restore.log)." -ForegroundColor Yellow }
        Write-Host ""
    }

    Write-Host "Safety confirmation required."
    Write-Host "Type RESTORE to continue (anything else cancels)."
    $confirm = Read-Host "Confirm"
    if ($confirm -ne 'RESTORE') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    foreach ($e in $m.Backup.Entries) {
        $regFile = Join-Path $base $e.File
        try {
            Import-RegistryFile -RegFile $regFile -LogPath $logPath
            Write-Host ("OK  {0}" -f $e.KeyPath) -ForegroundColor Green
            Write-Log $logPath ("OK: {0}" -f $regFile)
        } catch {
            Write-Host ("FAIL {0}" -f $e.KeyPath) -ForegroundColor Red
            Write-Log $logPath ("FAIL: {0} : {1}" -f $regFile, $_.Exception.Message)
        }
    }

    Write-Host ""
    Write-Host "Restore complete."
    Write-Host ('Log: {0}' -f $logPath)
    Write-Host ""
    Write-Host "Note: Some changes may require sign-out/reboot to fully apply."
    $null = Read-Host "Press Enter to continue"
}

function Menu-Backup([hashtable]$Config) {
  <#
      .SYNOPSIS
      Describe purpose of "Menu-Backup" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .EXAMPLE
      Menu-Backup -Config Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Menu-Backup

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    while ($true) {
        Write-Header "Registry Backup"
        Write-Host ("Backup root: {0}" -f $Config.BackupRoot)
        Write-Host ("Running as admin: {0}" -f (Test-IsAdmin))
        Write-Host ""
        Write-Host "[1] Backup predefined set"
        Write-Host "[2] Backup custom list (multiple keys)"
        Write-Host "[3] Backup single key"
        Write-Host "[4] Show example key paths"
        Write-Host "[0] Back"
        $c = Read-Choice -Prompt "Select" -ValidChoices @(0,1,2,3,4)

        switch ($c) {
            0 { return }
            1 {
                $sets = Predefined-KeySets
                Write-Header "Predefined Sets"
                for ($i = 0; $i -lt $sets.Count; $i++) {
                    Write-Host ("[{0}] {1}" -f ($i + 1), $sets[$i].Name)
                }
                Write-Host "[0] Cancel"
                $valid = @(0..$sets.Count)
                $pick = Read-Choice -Prompt "Select a set" -ValidChoices $valid
                if ($pick -eq 0) { continue }
                $set = $sets[$pick - 1]
                $label = $set.Name
                Run-BackupFlow -Config $Config -Keys $set.Keys -Label $label
            }
            2 {
                Write-Header "Custom Key List"
                Write-Host "Enter one key per line. Blank line to finish."
                Write-Host "Examples: HKCU, HKLM\SOFTWARE, HKLM\SYSTEM, HKCU\Software\MyApp"
                $keys = New-Object System.Collections.Generic.List[string]
                while ($true) {
                    $k = Read-Host "Key"
                    if ([string]::IsNullOrWhiteSpace($k)) { break }
                    $keys.Add($k.Trim())
                }
                if ($keys.Count -eq 0) {
                    Write-Host "No keys entered." -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 700
                    continue
                }
                $label = Read-NonEmpty "Backup label"
                Run-BackupFlow -Config $Config -Keys $keys.ToArray() -Label $label
            }
            3 {
                Write-Header "Single Key Backup"
                $k = Read-NonEmpty "Key path"
                $label = "SingleKey_{0}" -f (Get-SafeFileName $k)
                Run-BackupFlow -Config $Config -Keys @($k) -Label $label
            }
            4 {
                Write-Header "Example Key Paths"
                @(
                    'HKCU',
                    'HKCU\Software',
                    'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer',
                    'HKLM\SOFTWARE',
                    'HKLM\SYSTEM',
                    'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                    'HKCR',
                    'HKU\.DEFAULT',
                    'HKCC'
                ) | ForEach-Object { Write-Host $_ }
                Write-Host ""
                Write-Host "Tip: You can also paste PowerShell-style paths like HKLM:\SOFTWARE."
                $null = Read-Host "Press Enter to continue"
            }
        }
    }
}

function Menu-Restore([hashtable]$Config) {
  <#
      .SYNOPSIS
      Describe purpose of "Menu-Restore" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .EXAMPLE
      Menu-Restore -Config Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Menu-Restore

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    while ($true) {
        Write-Header "Registry Restore"
        Write-Host ("Backup root: {0}" -f $Config.BackupRoot)
        Write-Host ("Running as admin: {0}" -f (Test-IsAdmin))
        Write-Host ""
        Write-Host "[1] Restore from a backup folder (manifest.json)"
        Write-Host "[2] Import a standalone .reg file"
        Write-Host "[0] Back"
        $c = Read-Choice -Prompt "Select" -ValidChoices @(0,1,2)

        switch ($c) {
            0 { return }
            1 {
                $sessionPath = Select-BackupSession -Config $Config
                if (-not $sessionPath) { continue }
                $manifestPath = Join-Path $sessionPath 'manifest.json'
                if (-not (Test-Path -LiteralPath $manifestPath)) {
                    Write-Host "manifest.json not found in that folder." -ForegroundColor Yellow
                    $null = Read-Host "Press Enter to continue"
                    continue
                }
                Restore-FromManifest -ManifestPath $manifestPath
            }
            2 {
                Write-Header "Import REG File"
                $p = Read-NonEmpty "Full path to .reg file"
                $logPath = Join-Path $env:TEMP ("reg_import_{0}.log" -f (Format-Timestamp))
                Start-Log $logPath

                Write-Host ""
                Write-Host "Safety confirmation required."
                Write-Host "Type IMPORT to continue (anything else cancels)."
                $confirm = Read-Host "Confirm"
                if ($confirm -ne 'IMPORT') {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 600
                    continue
                }

                try {
                    Import-RegistryFile -RegFile $p -LogPath $logPath
                    Write-Host "Import complete." -ForegroundColor Green
                } catch {
                    Write-Host ("Import failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                Write-Host ('Log: {0}' -f $logPath)
                $null = Read-Host "Press Enter to continue"
            }
        }
    }
}

function Menu-Verify([hashtable]$Config) {
  <#
      .SYNOPSIS
      Describe purpose of "Menu-Verify" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .EXAMPLE
      Menu-Verify -Config Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Menu-Verify

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    while ($true) {
        Write-Header "Verify Backups"
        Write-Host "[1] Verify a backup (manifest.json)"
        Write-Host "[2] Verify all backups"
        Write-Host "[0] Back"
        $c = Read-Choice -Prompt "Select" -ValidChoices @(0,1,2)

        switch ($c) {
            0 { return }
            1 {
                $sessionPath = Select-BackupSession -Config $Config
                if (-not $sessionPath) { continue }
                $manifestPath = Join-Path $sessionPath 'manifest.json'
                Write-Header "Verify Backup"
                try {
                    $null = Verify-BackupManifest -ManifestPath $manifestPath
                } catch {
                    Write-Host ("Verification error: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                $null = Read-Host "Press Enter to continue"
            }
            2 {
                Write-Header "Verify All Backups"
                $folders = @(Get-BackupFolders $Config)
                if ($folders.Count -eq 0) {
                    Write-Host "No backups found." -ForegroundColor Yellow
                    $null = Read-Host "Press Enter to continue"
                    continue
                }

                foreach ($f in $folders) {
                    $manifestPath = Join-Path $f.FullName 'manifest.json'
                    Write-Host ""
                    Write-Host $f.Name
                    if (-not (Test-Path -LiteralPath $manifestPath)) {
                        Write-Host "No manifest.json" -ForegroundColor Yellow
                        continue
                    }
                    try {
                        $null = Verify-BackupManifest -ManifestPath $manifestPath
                    } catch {
                        Write-Host ("Verification error: {0}" -f $_.Exception.Message) -ForegroundColor Red
                    }
                }

                Write-Host ""
                $null = Read-Host "Press Enter to continue"
            }
        }
    }
}

function Menu-Manage([hashtable]$Config) {
  <#
      .SYNOPSIS
      Describe purpose of "Menu-Manage" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .EXAMPLE
      Menu-Manage -Config Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Menu-Manage

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    while ($true) {
        Write-Header "Manage Backups"
        Write-Host ("Backup root: {0}" -f $Config.BackupRoot)
        Write-Host ""
        Write-Host "[1] Compress a backup folder to ZIP"
        Write-Host "[2] Delete a backup folder"
        Write-Host "[3] Open backup root in Explorer"
        Write-Host "[0] Back"
        $c = Read-Choice -Prompt "Select" -ValidChoices @(0,1,2,3)

        switch ($c) {
            0 { return }
            1 {
                $sessionPath = Select-BackupSession -Config $Config
                if (-not $sessionPath) { continue }
                $zipPath = ('{0}.zip' -f $sessionPath)
                Write-Header "Compress Backup"
                Write-Host ('Folder: {0}' -f $sessionPath)
                Write-Host ('ZIP:    {0}' -f $zipPath)
                if (-not (Read-YesNo "Create/overwrite ZIP now?" $true)) { continue }
                try {
                    Zip-Folder -FolderPath $sessionPath -ZipPath $zipPath
                    Write-Host "ZIP created." -ForegroundColor Green
                } catch {
                    Write-Host ("ZIP failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                $null = Read-Host "Press Enter to continue"
            }
            2 {
                $sessionPath = Select-BackupSession -Config $Config
                if (-not $sessionPath) { continue }
                Write-Header "Delete Backup"
                Write-Host ('Folder: {0}' -f $sessionPath)
                Write-Host ""
                Write-Host "Type DELETE to confirm (anything else cancels)."
                $confirm = Read-Host "Confirm"
                if ($confirm -ne 'DELETE') {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 600
                    continue
                }
                try {
                    Remove-Item -LiteralPath $sessionPath -Recurse -Force
                    Write-Host "Deleted." -ForegroundColor Green
                } catch {
                    Write-Host ("Delete failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                }
                $null = Read-Host "Press Enter to continue"
            }
            3 {
                Ensure-Folder $Config.BackupRoot
                $null = Start-Process explorer.exe -ArgumentList @($Config.BackupRoot)
            }
        }
    }
}

function Menu-Settings([hashtable]$Config) {
  <#
      .SYNOPSIS
      Describe purpose of "Menu-Settings" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Config
      Describe parameter -Config.

      .EXAMPLE
      Menu-Settings -Config Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Menu-Settings

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    while ($true) {
        Write-Header "Settings"
        Write-Host ("[1] Set backup root directory      : {0}" -f $Config.BackupRoot)
        Write-Host ("[2] Toggle auto-zip after backup   : {0}" -f $Config.AutoZipAfterBackup)
        Write-Host ("[3] Toggle include SHA256 hashes   : {0}" -f $Config.IncludeHashes)
        Write-Host "[4] Show config file path"
        Write-Host "[5] Reset to defaults"
        Write-Host "[0] Back"
        $c = Read-Choice -Prompt "Select" -ValidChoices @(0,1,2,3,4,5)

        switch ($c) {
            0 { Save-Config $Config
      return }
            1 {
                $p = Read-NonEmpty "New backup root path"
                Ensure-Folder $p
                $Config.BackupRoot = $p
                Save-Config $Config
            }
            2 {
                $Config.AutoZipAfterBackup = -not $Config.AutoZipAfterBackup
                Save-Config $Config
            }
            3 {
                $Config.IncludeHashes = -not $Config.IncludeHashes
                Save-Config $Config
            }
            4 {
                Write-Host ""
                Write-Host ("Config: {0}" -f (Get-ConfigPath))
                $null = Read-Host "Press Enter to continue"
            }
            5 {
                $d = Get-DefaultConfig
                $Config.BackupRoot = $d.BackupRoot
                $Config.AutoZipAfterBackup = $d.AutoZipAfterBackup
                $Config.IncludeHashes = $d.IncludeHashes
                Save-Config $Config
            }
        }
    }
}

function script:Main {
  <#
      .SYNOPSIS
      Describe purpose of "Main" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Main
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Main

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


    $Config = Load-Config

    while ($true) {
        Write-Header "Registry Backup & Restore"
        Write-Host ("Running as admin: {0}" -f (Test-IsAdmin))
        Write-Host ("Backup root:      {0}" -f $Config.BackupRoot)
        Write-Host ""
        Write-Host "[1] Backup"
        Write-Host "[2] Restore"
        Write-Host "[3] Verify backups"
        Write-Host "[4] Manage backups"
        Write-Host "[5] Settings"
        Write-Host "[0] Exit"
        $c = Read-Choice -Prompt "Select" -ValidChoices @(0,1,2,3,4,5)

        switch ($c) {
            0 { return }
            1 { Menu-Backup -Config $Config }
            2 { Menu-Restore -Config $Config }
            3 { Menu-Verify -Config $Config }
            4 { Menu-Manage -Config $Config }
            5 { Menu-Settings -Config $Config }
        }
    }
}

Main

# SIG # Begin signature block
# MIID4QYJKoZIhvcNAQcCoIID0jCCA84CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUmX8BLz9ydthzMmHzQTyN/mZq
# WOagggH/MIIB+zCCAWSgAwIBAgIQK8KPnyZqh7ZLgu5QUg7L1TANBgkqhkiG9w0B
# AQUFADAYMRYwFAYDVQQDDA1EYXZpZCBTY291dGVuMB4XDTI2MDExNzE0MTcyM1oX
# DTMwMDExNzAwMDAwMFowGDEWMBQGA1UEAwwNRGF2aWQgU2NvdXRlbjCBnzANBgkq
# hkiG9w0BAQEFAAOBjQAwgYkCgYEAuixS48kf0xGGzx74Y45fjPFNwvOudmeITTBN
# FJVdCxYJ1J6Mym5fj2oIkPr2LEJn8Z9SDDaNunk6DPRgHvbHuKfpBbvwNcYz17Xi
# ll2A2cudyMGf61ourjQJIwvmhyYD3mv8tBRA7cu0jCPcJgfZaoPxi9foJlOJAZkp
# hWLUtSECAwEAAaNGMEQwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFLB3
# VS+syNCZjA1TABGZWX/r9DisMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUF
# AAOBgQCqQdqfPWwwDvuTu3+xFp1nc2HUGCYiQFvrMwHcjjwY5YquK2ebkhsbX7gn
# x47StrKakOaBZzqe5TtpbcuNVq24vb/MgJX48ImwH8VUAM/Ov++HdJyA5QUZpGNk
# qLr4aBGs6ACVmKgOZdaJqI4d29lUSdwq7gbRdUsuzluwg0x/iTGCAUwwggFIAgEB
# MCwwGDEWMBQGA1UEAwwNRGF2aWQgU2NvdXRlbgIQK8KPnyZqh7ZLgu5QUg7L1TAJ
# BgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAj
# BgkqhkiG9w0BCQQxFgQUPjORYD+FrWpRycrTl8JYMQgfNd8wDQYJKoZIhvcNAQEB
# BQAEgYCcw1tohzMOpS2Dl5o3tkTUCBw/8AZIaiH96aVUjuZuVuwzP+qWXMcmNfsq
# PYxHF3Fj9utGGacohXnBMPOsIqptc0/b0BP/PTZlREPkOAAYfht7UN2n4WeK//7v
# i0gskqq+1ccXkNRkliJZG/cWFvC4KPuW9DK6mbj/LNVEbjZkfg==
# SIG # End signature block
