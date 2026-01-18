#!/usr/bin/env powershell
#requires -version 5.1

<#
    .SYNOPSIS
    Backup, edit, and restore Windows environment variables.

    .DESCRIPTION
    Exports User and/or Machine environment variables to a JSON file. Supports an
    edit workflow (open JSON in editor), plus restore/diff/validate and PATH-focused
    utilities.

    This script uses .NET's [Environment] API, which persists variables at the
    proper scope.

    .PARAMETER Backup
    Create a backup JSON file.

    .PARAMETER Restore
    Restore from a backup JSON file.

    .PARAMETER Edit
    Opens a backup JSON for editing (creates one if missing) and optionally opens
    a PATH-only "sidecar" file you can edit line-by-line.

    .PARAMETER List
    Print current environment variables (optionally as JSON).

    .PARAMETER Diff
    Compare current environment variables vs a backup JSON.

    .PARAMETER Validate
    Validate that a JSON backup is well-formed.

    .PARAMETER Path
    Path to the backup JSON file.

    .PARAMETER Scopes
    Which scopes to backup/restore: user, machine, or both.

    .PARAMETER Mode
    Restore behavior:
    merge - only set keys present in backup
    full  - also remove keys not present in backup (within selected scopes)

    .PARAMETER Force
    Do not prompt for confirmation.

    .PARAMETER Editor
    Editor command to use for -Edit (optional). Examples:
    notepad
    code

    .PARAMETER AsJson
    For -List: output JSON instead of a table.

    .PARAMETER PathScope
    For PATH helpers: which PATH scope (user/machine).

    .PARAMETER PathFile
    Path to a path-entries text file (one entry per line).

    .PARAMETER PathExport
    Export PATH entries (one per line) to -PathFile.

    .PARAMETER PathImport
    Import PATH entries from -PathFile and apply to that scope.

    .PARAMETER Normalize
    For PATH import/export: normalize + de-duplicate entries.

    .EXAMPLE
    # Backup both scopes
    .\env-manager.ps1 -Backup -Path .\backup.json -Scopes both

    .EXAMPLE
    # Edit JSON in an editor (creates backup if missing)
    .\env-manager.ps1 -Edit -Path .\backup.json -Scopes both -Editor notepad

    .EXAMPLE
    # Export PATH entries to a text file
    .\env-manager.ps1 -PathExport -PathScope user -PathFile .\path.user.txt -Normalize

    .EXAMPLE
    # Import PATH entries from a text file (applies immediately)
    .\env-manager.ps1 -PathImport -PathScope user -PathFile .\path.user.txt -Normalize

    .EXAMPLE
    # Restore only keys present in backup (safer)
    .\env-manager.ps1 -Restore -Path .\backup.json -Scopes both -Mode merge

    .EXAMPLE
    # Full restore (dangerous): also delete keys missing from backup
    .\env-manager.ps1 -Restore -Path .\backup.json -Scopes both -Mode full

    .EXAMPLE
    # Diff current env vars vs a backup
    .\env-manager.ps1 -Diff -Path .\backup.json -Scopes both
#>

[CmdletBinding(DefaultParameterSetName = 'Help', SupportsShouldProcess=$true, ConfirmImpact = 'High')]
param(
  [Parameter(ParameterSetName = 'Backup', Mandatory = $true)]
  [switch] $Backup,

  [Parameter(ParameterSetName = 'Restore', Mandatory = $true)]
  [switch] $Restore,

  [Parameter(ParameterSetName = 'Edit', Mandatory = $true)]
  [switch] $Edit,

  [Parameter(ParameterSetName = 'List', Mandatory = $true)]
  [switch] $List,

  [Parameter(ParameterSetName = 'Diff', Mandatory = $true)]
  [switch] $Diff,

  [Parameter(ParameterSetName = 'Validate', Mandatory = $true)]
  [switch] $Validate,

  [Parameter(ParameterSetName = 'PathExport', Mandatory = $true)]
  [switch] $PathExport,

  [Parameter(ParameterSetName = 'PathImport', Mandatory = $true)]
  [switch] $PathImport,

  [Parameter(ParameterSetName = 'Menu', Mandatory = $true)]
  [switch] $Menu,

  [Parameter(Mandatory = $true, ParameterSetName = 'Backup')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Edit')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Diff')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Validate')]
  [string] $Path,

  [Parameter(ParameterSetName = 'Backup')]
  [Parameter(ParameterSetName = 'Restore')]
  [Parameter(ParameterSetName = 'Edit')]
  [Parameter(ParameterSetName = 'Diff')]
  [ValidateSet('user', 'machine', 'both')]
  [string] $Scopes = 'both',

  [Parameter(ParameterSetName = 'Restore')]
  [ValidateSet('merge', 'full')]
  [string] $Mode = 'merge',

  [Parameter(ParameterSetName = 'Restore')]
  [switch] $Force,

  [Parameter(ParameterSetName = 'Edit')]
  [string] $Editor,

  [Parameter(ParameterSetName = 'List')]
  [ValidateSet('user', 'machine', 'both')]
  [string] $ListScopes = 'both',

  [Parameter(ParameterSetName = 'List')]
  [switch] $AsJson,

  [Parameter(ParameterSetName = 'PathExport')]
  [Parameter(ParameterSetName = 'PathImport')]
  [ValidateSet('user', 'machine')]
  [string] $PathScope = 'user',

  [Parameter(ParameterSetName = 'PathExport', Mandatory = $true)]
  [Parameter(ParameterSetName = 'PathImport', Mandatory = $true)]
  [string] $PathFile,

  [Parameter(ParameterSetName = 'PathExport')]
  [Parameter(ParameterSetName = 'PathImport')]
  [switch] $Normalize
)

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
  $p = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-EnvMap {
  <#
      .SYNOPSIS
      Describe purpose of "Read-EnvMap" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Scope
      Describe parameter -Scope.

      .EXAMPLE
      Read-EnvMap -Scope Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Read-EnvMap

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [ValidateSet('User', 'Machine')] [string] $Scope
  )

  $out = @{}
  $vars = [Environment]::GetEnvironmentVariables($Scope)
  foreach ($k in $vars.Keys) {
    $name = [string]$k
    $out[$name] = [string]$vars[$k]
  }

  return $out
}

function New-BackupObject {
  <#
      .SYNOPSIS
      Describe purpose of "New-BackupObject" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Scopes
      Describe parameter -Scopes.

      .EXAMPLE
      New-BackupObject -Scopes Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online New-BackupObject

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [ValidateSet('user', 'machine', 'both')] [string] $Scopes
  )

  $metaObj = [ordered]@{
    createdAt = (Get-Date).ToString('o')
    host = $env:COMPUTERNAME
    user = $env:USERNAME
    source = 'env-manager.ps1'
    notes = ''
  }

  $backup = [ordered]@{
    type = 'windows-env-backup-v1'
    meta = $metaObj
    user = @{}
    machine = @{}
  }

  if ($Scopes -eq 'user' -or $Scopes -eq 'both') {
    $backup.user = Read-EnvMap -Scope User
  }

  if ($Scopes -eq 'machine' -or $Scopes -eq 'both') {
    $backup.machine = Read-EnvMap -Scope Machine
  }

  return $backup
}

function Write-BackupJson {
  <#
      .SYNOPSIS
      Describe purpose of "Write-BackupJson" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Describe parameter -Path.

      .PARAMETER Scopes
      Describe parameter -Scopes.

      .EXAMPLE
      Write-BackupJson -Path Value -Scopes Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Write-BackupJson

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [string] $Path,
    [Parameter(Mandatory = $true)] [ValidateSet('user', 'machine', 'both')] [string] $Scopes
  )

  $obj = New-BackupObject -Scopes $Scopes

  $dir = Split-Path -Parent -Path $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    $null = New-Item -ItemType Directory -Path $dir
  }

  $json = $obj | ConvertTo-Json -Depth 10
  Set-Content -LiteralPath $Path -Value $json -Encoding UTF8

  Write-Verbose -Message ('Wrote backup: {0}' -f $Path)
}

function Read-BackupJson {
  <#
      .SYNOPSIS
      Describe purpose of "Read-BackupJson" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Describe parameter -Path.

      .EXAMPLE
      Read-BackupJson -Path Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Read-BackupJson

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [string] $Path
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    throw ('Backup file not found: {0}' -f $Path)
  }

  $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
  $b = $raw | ConvertFrom-Json -ErrorAction Stop

  if (-not $b -or $b.type -ne 'windows-env-backup-v1') {
    throw 'Not a recognized backup format (expected type windows-env-backup-v1).'
  }

  return $b
}

function ConvertTo-Hashtable {
  <#
      .SYNOPSIS
      Describe purpose of "ConvertTo-Hashtable" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Obj
      Describe parameter -Obj.

      .EXAMPLE
      ConvertTo-Hashtable -Obj Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online ConvertTo-Hashtable

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory = $true)] [Object]$Obj)

  $ht = @{}
  if (-not $Obj) { return $ht }

  # Allow "comments" arrays, etc. Only interpret PSObject properties as keys.
  foreach ($p in $Obj.PSObject.Properties) {
    if ($p.Name -eq '__comment' -or $p.Name -eq '__comments') { continue }
    if ($p.Name -eq 'meta' -or $p.Name -eq 'type') { continue }
    $ht[$p.Name] = [string]$p.Value
  }

  return $ht
}

function Set-EnvVarsFromMap {
  <#
      .SYNOPSIS
      Describe purpose of "Set-EnvVarsFromMap" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Map
      Describe parameter -Map.

      .PARAMETER Scope
      Describe parameter -Scope.

      .EXAMPLE
      Set-EnvVarsFromMap -Map Value -Scope Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Set-EnvVarsFromMap

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [hashtable] $Map,
    [Parameter(Mandatory = $true)] [ValidateSet('User', 'Machine')] [string] $Scope
  )

  foreach ($k in $Map.Keys) {
    [Environment]::SetEnvironmentVariable([string]$k, [string]$Map[$k], $Scope)
  }
}

function Remove-EnvVarsNotInMap {
  <#
      .SYNOPSIS
      Describe purpose of "Remove-EnvVarsNotInMap" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Map
      Describe parameter -Map.

      .PARAMETER Scope
      Describe parameter -Scope.

      .EXAMPLE
      Remove-EnvVarsNotInMap -Map Value -Scope Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Remove-EnvVarsNotInMap

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [hashtable] $Map,
    [Parameter(Mandatory = $true)] [ValidateSet('User', 'Machine')] [string] $Scope
  )

  $current = [Environment]::GetEnvironmentVariables($Scope)
  foreach ($k in $current.Keys) {
    $name = [string]$k
    if (-not $Map.ContainsKey($name)) {
      [Environment]::SetEnvironmentVariable($name, $null, $Scope)
    }
  }
}

function Broadcast-EnvChange {
  <#
      .SYNOPSIS
      Describe purpose of "Broadcast-EnvChange" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Broadcast-EnvChange
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Broadcast-EnvChange

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  try {
    Add-Type -Namespace Win32 -Name Native -MemberDefinition @'
      [System.Runtime.InteropServices.DllImport(\"user32.dll\", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Auto)]
      public static extern System.IntPtr SendMessageTimeout(System.IntPtr hWnd, int Msg, System.IntPtr wParam, string lParam, int fuFlags, int uTimeout, out System.IntPtr lpdwResult);
'@

    $HWND_BROADCAST = [IntPtr]0xffff
    $WM_SETTINGCHANGE = 0x1A
    $result = [IntPtr]::Zero

    # SMTO_ABORTIFHUNG = 0x2
    $null = [Win32.Native]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [IntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
  } catch {
      # get error record
      [Management.Automation.ErrorRecord]$e = $_

      # retrieve information about runtime error
      $info = [PSCustomObject]@{
        Exception = $e.Exception.Message
        Reason    = $e.CategoryInfo.Reason
        Target    = $e.CategoryInfo.TargetName
        Script    = $e.InvocationInfo.ScriptName
        Line      = $e.InvocationInfo.ScriptLineNumber
        Column    = $e.InvocationInfo.OffsetInLine
      }
      
      # output information. Post-process collected info, and log info (optional)
      $info
  }
}

function Normalize-WindowsPathEntry {
  <#
      .SYNOPSIS
      Describe purpose of "Normalize-WindowsPathEntry" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Entry
      Describe parameter -Entry.

      .EXAMPLE
      Normalize-WindowsPathEntry -Entry Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Normalize-WindowsPathEntry

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory = $true)] [string] $Entry)

  $s = $Entry.Trim()
  if (-not $s) { return '' }

  $s = $s -replace '/', '\\'

  # keep C:\ but trim other trailing backslashes
  if ($s -match '^[A-Za-z]:\\$') { return $s }
  $s = $s -replace '\\+$', ''
  return $s
}

function Split-PathEntries {
  <#
      .SYNOPSIS
      Describe purpose of "Split-PathEntries" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Value
      Describe parameter -Value.

      .EXAMPLE
      Split-PathEntries -Value Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Split-PathEntries

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  [CmdletBinding()]
  param([string] $Value)

  return @(
    ([string]$(if ($null -ne $Value) { $Value } else { '' })).Split(';') |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ }
  )
}

function Unique-PreserveOrder {
  <#
      .SYNOPSIS
      Describe purpose of "Unique-PreserveOrder" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Values
      Describe parameter -Values.

      .EXAMPLE
      Unique-PreserveOrder -Values Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Unique-PreserveOrder

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [string[]] $Values
  )

  $seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
  $out = New-Object -TypeName 'System.Collections.Generic.List[string]'

  foreach ($v in $Values) {
    $k = $v.ToLowerInvariant()
    if ($seen.Add($k)) {
      $null = $out.Add($v)
    }
  }

  return ,$out.ToArray()
}

function Export-PathFile {
  <#
      .SYNOPSIS
      Describe purpose of "Export-PathFile" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Scope
      Describe parameter -Scope.

      .PARAMETER PathFile
      Describe parameter -PathFile.

      .PARAMETER Normalize
      Describe parameter -Normalize.

      .EXAMPLE
      Export-PathFile -Scope Value -PathFile Value -Normalize
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Export-PathFile

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [ValidateSet('user', 'machine')] [string] $Scope,
    [Parameter(Mandatory = $true)] [string] $PathFile,
    [switch] $Normalize
  )

  $psScope = if ($Scope -eq 'machine') { 'Machine' } else { 'User' }
  $raw = [Environment]::GetEnvironmentVariable('PATH', $psScope)
  $entries = Split-PathEntries -Value $raw

  if ($Normalize) {
    $entries = $entries | ForEach-Object { Normalize-WindowsPathEntry -Entry $_ } | Where-Object { $_ }
    $entries = Unique-PreserveOrder -Values $entries
  }

  $dir = Split-Path -Parent -Path $PathFile
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    $null = New-Item -ItemType Directory -Path $dir
  }

  Set-Content -LiteralPath $PathFile -Value ($entries -join "`r`n") -Encoding UTF8
  Write-Host ('Wrote PATH file: {0}' -f $PathFile) -ForegroundColor Green
}

function Import-PathFile {
  <#
      .SYNOPSIS
      Describe purpose of "Import-PathFile" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Scope
      Describe parameter -Scope.

      .PARAMETER PathFile
      Describe parameter -PathFile.

      .PARAMETER Normalize
      Describe parameter -Normalize.

      .EXAMPLE
      Import-PathFile -Scope Value -PathFile Value -Normalize
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Import-PathFile

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [ValidateSet('user', 'machine')] [string] $Scope,
    [Parameter(Mandatory = $true)] [string] $PathFile,
    [switch] $Normalize
  )

  if (-not (Test-Path -LiteralPath $PathFile)) {
    throw ('PATH file not found: {0}' -f $PathFile)
  }

  $lines = (Get-Content -LiteralPath $PathFile) | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  $entries = @($lines)

  if ($Normalize) {
    $entries = $entries | ForEach-Object { Normalize-WindowsPathEntry -Entry $_ } | Where-Object { $_ }
    $entries = Unique-PreserveOrder -Values $entries
  }

  $joined = ($entries -join ';')
  $psScope = if ($Scope -eq 'machine') { 'Machine' } else { 'User' }

  if ($Scope -eq 'machine' -and -not (Test-IsAdmin)) {
    Write-Warning -Message 'Updating MACHINE PATH usually requires running as Administrator.'
  }

  if ($PSCmdlet.ShouldProcess(('PATH ({0})' -f $Scope), ('Set PATH from {0}' -f $PathFile))) {
    [Environment]::SetEnvironmentVariable('PATH', $joined, $psScope)
    Broadcast-EnvChange
  }

  Write-Host ('Applied PATH for {0}.' -f $Scope) -ForegroundColor Green
}

function Get-BackupMaps {
  <#
      .SYNOPSIS
      Describe purpose of "Get-BackupMaps" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Backup
      Describe parameter -Backup.

      .EXAMPLE
      Get-BackupMaps -Backup Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-BackupMaps

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [Object]$Backup
  )

  return @{
    user = ConvertTo-Hashtable -Obj $Backup.user
    machine = ConvertTo-Hashtable -Obj $Backup.machine
  }
}

function Get-Diff {
  <#
      .SYNOPSIS
      Describe purpose of "Get-Diff" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Desired
      Describe parameter -Desired.

      .PARAMETER Current
      Describe parameter -Current.

      .EXAMPLE
      Get-Diff -Desired Value -Current Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-Diff

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [hashtable] $Desired,
    [Parameter(Mandatory = $true)] [hashtable] $Current
  )

  $keys = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
  foreach ($k in $Desired.Keys) { $null = $keys.Add([string]$k) }
  foreach ($k in $Current.Keys) { $null = $keys.Add([string]$k) }

  $out = @()

  foreach ($k in ($keys | Sort-Object)) {
    $hasDesired = $Desired.ContainsKey($k)
    $hasCurrent = $Current.ContainsKey($k)

    if (-not $hasDesired -and $hasCurrent) {
      $out += [pscustomobject]@{ Key = $k
        Change = 'Remove'
        Current = $Current[$k]
      Desired = $null }
      continue
    }

    if ($hasDesired -and -not $hasCurrent) {
      $out += [pscustomobject]@{ Key = $k
        Change = 'Add'
        Current = $null
      Desired = $Desired[$k] }
      continue
    }

    if ($hasDesired -and $hasCurrent -and [string]$Desired[$k] -ne [string]$Current[$k]) {
      $out += [pscustomobject]@{ Key = $k
        Change = 'Update'
        Current = $Current[$k]
      Desired = $Desired[$k] }
      continue
    }
  }

  return $out
}

function Confirm-Restore {
  <#
      .SYNOPSIS
      Describe purpose of "Confirm-Restore" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Mode
      Describe parameter -Mode.

      .PARAMETER Scopes
      Describe parameter -Scopes.

      .PARAMETER Path
      Describe parameter -Path.

      .PARAMETER Maps
      Describe parameter -Maps.

      .EXAMPLE
      Confirm-Restore -Mode Value -Scopes Value -Path Value -Maps Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Confirm-Restore

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [ValidateSet('merge', 'full')] [string] $Mode,
    [Parameter(Mandatory = $true)] [ValidateSet('user', 'machine', 'both')] [string] $Scopes,
    [Parameter(Mandatory = $true)] [string] $Path,
    [Parameter(Mandatory = $true)] [hashtable] $Maps
  )

  if ($Mode -eq 'merge') {
    $msg = ("About to RESTORE (merge) from: {0}`nScopes: {1}`nThis will set keys present in the backup (does NOT delete extras)." -f $Path, $Scopes)
    return $PSCmdlet.ShouldContinue($msg, 'Confirm restore?')
  }

  $dangerMsg = ("About to RESTORE (FULL) from: {0}`nScopes: {1}`nFULL restore will also DELETE keys not present in the backup for selected scopes." -f $Path, $Scopes)
  if (-not $PSCmdlet.ShouldContinue($dangerMsg, 'Confirm FULL restore?')) { return $false }

  # Optional extra: show approximate delete counts.
  if ($Scopes -eq 'user' -or $Scopes -eq 'both') {
    $currentUser = Read-EnvMap -Scope User
    $diffUser = Get-Diff -Desired $Maps.user -Current $currentUser
    $removeCount = ($diffUser | Where-Object { $_.Change -eq 'Remove' }).Count
    if ($removeCount -gt 0) {
      Write-Warning -Message ('FULL restore would remove {0} USER keys not present in backup.' -f $removeCount)
    }
  }

  if ($Scopes -eq 'machine' -or $Scopes -eq 'both') {
    $currentMachine = Read-EnvMap -Scope Machine
    $diffMachine = Get-Diff -Desired $Maps.machine -Current $currentMachine
    $removeCount = ($diffMachine | Where-Object { $_.Change -eq 'Remove' }).Count
    if ($removeCount -gt 0) {
      Write-Warning -Message ('FULL restore would remove {0} SYSTEM keys not present in backup.' -f $removeCount)
    }
  }

  return $PSCmdlet.ShouldContinue('Proceed with FULL restore now?', 'Last chance')
}

function Restore-FromBackup {
  <#
      .SYNOPSIS
      Describe purpose of "Restore-FromBackup" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Describe parameter -Path.

      .PARAMETER Scopes
      Describe parameter -Scopes.

      .PARAMETER Mode
      Describe parameter -Mode.

      .PARAMETER Force
      Describe parameter -Force.

      .EXAMPLE
      Restore-FromBackup -Path Value -Scopes Value -Mode Value -Force
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Restore-FromBackup

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [string] $Path,
    [Parameter(Mandatory = $true)] [ValidateSet('user', 'machine', 'both')] [string] $Scopes,
    [Parameter(Mandatory = $true)] [ValidateSet('merge', 'full')] [string] $Mode,
    [switch] $Force
  )

  $b = Read-BackupJson -Path $Path
  $maps = Get-BackupMaps -Backup $b

  if (($Scopes -eq 'machine' -or $Scopes -eq 'both') -and -not (Test-IsAdmin)) {
    Write-Warning -Message 'Restoring MACHINE scope may require running PowerShell as Administrator.'
  }

  if (-not $Force) {
    if (-not (Confirm-Restore -Mode $Mode -Scopes $Scopes -Path $Path -Maps $maps)) {
      Write-Host 'Cancelled.' -ForegroundColor Yellow
      return
    }
  }

  if ($Scopes -eq 'user' -or $Scopes -eq 'both') {
    if ($PSCmdlet.ShouldProcess('User environment', ('Restore ({0})' -f $Mode))) {
      Write-Host 'Applying USER environment variables...' -ForegroundColor Cyan
      Set-EnvVarsFromMap -Map $maps.user -Scope User
      if ($Mode -eq 'full') { Remove-EnvVarsNotInMap -Map $maps.user -Scope User }
    }
  }

  if ($Scopes -eq 'machine' -or $Scopes -eq 'both') {
    if ($PSCmdlet.ShouldProcess('Machine environment', ('Restore ({0})' -f $Mode))) {
      Write-Host 'Applying SYSTEM environment variables...' -ForegroundColor Cyan
      Set-EnvVarsFromMap -Map $maps.machine -Scope Machine
      if ($Mode -eq 'full') { Remove-EnvVarsNotInMap -Map $maps.machine -Scope Machine }
    }
  }

  Broadcast-EnvChange
  Write-Host 'Done.' -ForegroundColor Green
}

function Show-Env {
  <#
      .SYNOPSIS
      Describe purpose of "Show-Env" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Scopes
      Describe parameter -Scopes.

      .PARAMETER AsJson
      Describe parameter -AsJson.

      .EXAMPLE
      Show-Env -Scopes Value -AsJson
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Show-Env

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [ValidateSet('user', 'machine', 'both')] [string] $Scopes,
    [switch] $AsJson
  )

  $obj = New-BackupObject -Scopes $Scopes

  if ($AsJson) {
    $obj | ConvertTo-Json -Depth 10
    return
  }

  $rows = @()

  if ($Scopes -eq 'user' -or $Scopes -eq 'both') {
    foreach ($k in ($obj.user.Keys | Sort-Object)) {
      $rows += [pscustomobject]@{ Scope = 'User'
        Key = $k
      Value = $obj.user[$k] }
    }
  }

  if ($Scopes -eq 'machine' -or $Scopes -eq 'both') {
    foreach ($k in ($obj.machine.Keys | Sort-Object)) {
      $rows += [pscustomobject]@{ Scope = 'Machine'
        Key = $k
      Value = $obj.machine[$k] }
    }
  }

  $rows | Format-Table -AutoSize
}

function Show-Diff {
  <#
      .SYNOPSIS
      Describe purpose of "Show-Diff" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Describe parameter -Path.

      .PARAMETER Scopes
      Describe parameter -Scopes.

      .EXAMPLE
      Show-Diff -Path Value -Scopes Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Show-Diff

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [string] $Path,
    [Parameter(Mandatory = $true)] [ValidateSet('user', 'machine', 'both')] [string] $Scopes
  )

  $b = Read-BackupJson -Path $Path
  $maps = Get-BackupMaps -Backup $b

  $out = @()

  if ($Scopes -eq 'user' -or $Scopes -eq 'both') {
    $currentUser = Read-EnvMap -Scope User
    $diffUser = Get-Diff -Desired $maps.user -Current $currentUser
    foreach ($d in $diffUser) {
      $out += [pscustomobject]@{ Scope = 'User'
        Key = $d.Key
        Change = $d.Change
        Current = $d.Current
      Desired = $d.Desired }
    }
  }

  if ($Scopes -eq 'machine' -or $Scopes -eq 'both') {
    $currentMachine = Read-EnvMap -Scope Machine
    $diffMachine = Get-Diff -Desired $maps.machine -Current $currentMachine
    foreach ($d in $diffMachine) {
      $out += [pscustomobject]@{ Scope = 'Machine'
        Key = $d.Key
        Change = $d.Change
        Current = $d.Current
      Desired = $d.Desired }
    }
  }

  if ($out.Count -eq 0) {
    Write-Host 'No differences.' -ForegroundColor Green
    return
  }

  $out | Sort-Object -Property Scope, Change, Key | Format-Table -AutoSize
}

function Validate-Backup {
  <#
      .SYNOPSIS
      Describe purpose of "Validate-Backup" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Describe parameter -Path.

      .EXAMPLE
      Validate-Backup -Path Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Validate-Backup

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory = $true)] [string] $Path)

  $b = Read-BackupJson -Path $Path

  # Ensure user/machine are objects if present.
  if ($null -ne $b.user -and -not ($b.user -is [psobject])) {
    throw 'Backup.user must be an object (map of key->value).'
  }
  if ($null -ne $b.machine -and -not ($b.machine -is [psobject])) {
    throw 'Backup.machine must be an object (map of key->value).'
  }

  Write-Host ('OK: {0}' -f $Path) -ForegroundColor Green
  if ($b.meta -and $b.meta.createdAt) {
    Write-Host ('CreatedAt: {0}' -f $b.meta.createdAt)
  }
}

function Open-Editor {
  <#
      .SYNOPSIS
      Describe purpose of "Open-Editor" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Path
      Describe parameter -Path.

      .PARAMETER Editor
      Describe parameter -Editor.

      .EXAMPLE
      Open-Editor -Path Value -Editor Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Open-Editor

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [string] $Path,
    [string] $Editor
  )

  if ($Editor) {
    $null = Start-Process -FilePath $Editor -ArgumentList @($Path)
    return
  }

  if (Get-Command -Name code -ErrorAction SilentlyContinue) {
    $null = Start-Process -FilePath 'code' -ArgumentList @($Path)
  } else {
    $null = Start-Process -FilePath 'notepad.exe' -ArgumentList @($Path)
  }
}

function Read-MenuChoice {
  <#
      .SYNOPSIS
      Describe purpose of "Read-MenuChoice" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Prompt
      Describe parameter -Prompt.

      .EXAMPLE
      Read-MenuChoice -Prompt Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Read-MenuChoice

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory = $true)] [string] $Prompt)

  Write-Host ''
  $inputValue = Read-Host -Prompt $Prompt
  if ($null -eq $inputValue) { return '' }
  return ([string]$inputValue).Trim()
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


  $p = $MyInvocation.MyCommand.Path
  if ($p) { return (Split-Path -Parent -Path $p) }
  return (Get-Location).Path
}

function Get-MenuConfigPath {
  <#
      .SYNOPSIS
      Describe purpose of "Get-MenuConfigPath" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-MenuConfigPath
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-MenuConfigPath

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $dir = Get-ScriptDir
  return (Join-Path -Path $dir -ChildPath 'env-manager.config.json')
}

function Load-MenuConfig {
  <#
      .SYNOPSIS
      Describe purpose of "Load-MenuConfig" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Load-MenuConfig
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Load-MenuConfig

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $cfgPath = Get-MenuConfigPath
  if (-not (Test-Path -LiteralPath $cfgPath)) { return $null }

  try {
    $raw = Get-Content -LiteralPath $cfgPath -Raw -ErrorAction Stop
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
  } catch {
    return $null
  }
}

function Save-MenuConfig {
  <#
      .SYNOPSIS
      Describe purpose of "Save-MenuConfig" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER BackupPath
      Describe parameter -BackupPath.

      .PARAMETER PathUserFile
      Describe parameter -PathUserFile.

      .PARAMETER PathMachineFile
      Describe parameter -PathMachineFile.

      .EXAMPLE
      Save-MenuConfig -BackupPath Value -PathUserFile Value -PathMachineFile Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Save-MenuConfig

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [string] $BackupPath,
    [Parameter(Mandatory = $true)] [string] $PathUserFile,
    [Parameter(Mandatory = $true)] [string] $PathMachineFile
  )

  $cfgPath = Get-MenuConfigPath
  $obj = [ordered]@{
    type = 'env-manager-menu-config-v1'
    updatedAt = (Get-Date).ToString('o')
    backupPath = $BackupPath
    pathUserFile = $PathUserFile
    pathMachineFile = $PathMachineFile
  }

  $json = $obj | ConvertTo-Json -Depth 5
  Set-Content -LiteralPath $cfgPath -Value $json -Encoding UTF8
  Write-Host ('Saved menu config: {0}' -f $cfgPath) -ForegroundColor Green
}

function Resolve-MenuPath {
  <#
      .SYNOPSIS
      Describe purpose of "Resolve-MenuPath" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER InputPath
      Describe parameter -InputPath.

      .PARAMETER BaseDir
      Describe parameter -BaseDir.

      .EXAMPLE
      Resolve-MenuPath -InputPath Value -BaseDir Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Resolve-MenuPath

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)] [string] $InputPath,
    [Parameter(Mandatory = $true)] [string] $BaseDir
  )

  $p = $InputPath.Trim()
  if (-not $p) { return '' }

  if ([IO.Path]::IsPathRooted($p)) { return $p }
  return (Join-Path -Path $BaseDir -ChildPath $p)
}

function Invoke-Menu {
  <#
      .SYNOPSIS
      Describe purpose of "Invoke-Menu" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Editor
      Describe parameter -Editor.

      .EXAMPLE
      Invoke-Menu -Editor Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Invoke-Menu

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  [CmdletBinding()]
  param([string] $Editor)

  $dir = Get-ScriptDir

  $backupPath = Join-Path -Path $dir -ChildPath 'backup.json'
  $pathUserFile = Join-Path -Path $dir -ChildPath 'path.user.txt'
  $pathMachineFile = Join-Path -Path $dir -ChildPath 'path.machine.txt'

  $cfg = Load-MenuConfig
  if ($cfg -and $cfg.type -eq 'env-manager-menu-config-v1') {
    if ($cfg.backupPath) { $backupPath = Resolve-MenuPath -InputPath ([string]$cfg.backupPath) -BaseDir $dir }
    if ($cfg.pathUserFile) { $pathUserFile = Resolve-MenuPath -InputPath ([string]$cfg.pathUserFile) -BaseDir $dir }
    if ($cfg.pathMachineFile) { $pathMachineFile = Resolve-MenuPath -InputPath ([string]$cfg.pathMachineFile) -BaseDir $dir }
  }

  while ($true) {
    Clear-Host
    Write-Host 'Windows Env Manager' -ForegroundColor Cyan
    Write-Host '===================' -ForegroundColor Cyan
    Write-Host ('Backup file:      {0}' -f $backupPath)
    Write-Host ('PATH user file:   {0}' -f $pathUserFile)
    Write-Host ('PATH system file: {0}' -f $pathMachineFile)
    Write-Host ''
    Write-Host '1) Backup (user/machine/both)'
    Write-Host '2) Edit backup.json (and export PATH sidecars)'
    Write-Host '3) Validate backup.json'
    Write-Host '4) Diff current vs backup.json'
    Write-Host '5) Restore (merge) from backup.json'
    Write-Host '6) Restore (full) from backup.json  (DANGEROUS)'
    Write-Host '7) Export PATH entries to file'
    Write-Host '8) Import PATH entries from file'
    Write-Host '9) List current env vars'
    Write-Host '10) Change active file paths'
    Write-Host '11) Save file paths as defaults'
    Write-Host '12) Open script folder'
    Write-Host '13) Reset paths to defaults'
    Write-Host '14) Reset + forget saved defaults'
    Write-Host '0) Exit'

    $choice = Read-MenuChoice -Prompt 'Select an option'

    try {
      switch ($choice) {
        '1' {
          $scopes = Read-MenuChoice -Prompt 'Scopes (user/machine/both)'
          if (-not $scopes) { $scopes = 'both' }
          Write-BackupJson -Path $backupPath -Scopes $scopes
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '2' {
          if (-not (Test-Path -LiteralPath $backupPath)) {
            Write-Host ('Backup missing; creating {0}' -f $backupPath) -ForegroundColor Yellow
            Write-BackupJson -Path $backupPath -Scopes both
          }

          Open-Editor -Path $backupPath -Editor $Editor

          Export-PathFile -Scope user -PathFile $pathUserFile -Normalize
          Export-PathFile -Scope machine -PathFile $pathMachineFile -Normalize

          Write-Host ''
          Write-Host 'JSON + PATH files opened/exported.' -ForegroundColor Green
          Write-Host 'When done editing:' -ForegroundColor Yellow
          Write-Host '  Restore: .\\env-manager.ps1 -Restore -Path \'$backupPath\" -Scopes both -Mode merge"
          Write-Host '  Apply PATH user:   .\\env-manager.ps1 -PathImport -PathScope user -PathFile \'$pathUserFile\" -Normalize"
          Write-Host '  Apply PATH system: .\\env-manager.ps1 -PathImport -PathScope machine -PathFile \'$pathMachineFile\" -Normalize"

          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '3' {
          Validate-Backup -Path $backupPath
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '4' {
          Show-Diff -Path $backupPath -Scopes both
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '5' {
          Restore-FromBackup -Path $backupPath -Scopes both -Mode merge
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '6' {
          Restore-FromBackup -Path $backupPath -Scopes both -Mode full
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '7' {
          $scope = Read-MenuChoice -Prompt 'PATH scope (user/machine)'
          if (-not $scope) { $scope = 'user' }

          $file = if ($scope -eq 'machine') { $pathMachineFile } else { $pathUserFile }
          Export-PathFile -Scope $scope -PathFile $file -Normalize

          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '8' {
          $scope = Read-MenuChoice -Prompt 'PATH scope (user/machine)'
          if (-not $scope) { $scope = 'user' }

          $file = if ($scope -eq 'machine') { $pathMachineFile } else { $pathUserFile }
          Import-PathFile -Scope $scope -PathFile $file -Normalize

          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '9' {
          $asJson = Read-MenuChoice -Prompt 'Output as JSON? (y/N)'
          Show-Env -Scopes both -AsJson:($asJson -match '^(y|yes)$')
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '10' {
          $b = Read-MenuChoice -Prompt ('Backup path (current: {0})' -f $backupPath)
          if ($b) { $backupPath = Resolve-MenuPath -InputPath $b -BaseDir $dir }

          $pu = Read-MenuChoice -Prompt ('PATH user file (current: {0})' -f $pathUserFile)
          if ($pu) { $pathUserFile = Resolve-MenuPath -InputPath $pu -BaseDir $dir }

          $pm = Read-MenuChoice -Prompt ('PATH system file (current: {0})' -f $pathMachineFile)
          if ($pm) { $pathMachineFile = Resolve-MenuPath -InputPath $pm -BaseDir $dir }

          Write-Host 'Updated active paths.' -ForegroundColor Green
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '11' {
          Save-MenuConfig -BackupPath $backupPath -PathUserFile $pathUserFile -PathMachineFile $pathMachineFile
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '12' {
          $null = Start-Process -FilePath 'explorer.exe' -ArgumentList @($dir)
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '13' {
          $backupPath = Join-Path -Path $dir -ChildPath 'backup.json'
          $pathUserFile = Join-Path -Path $dir -ChildPath 'path.user.txt'
          $pathMachineFile = Join-Path -Path $dir -ChildPath 'path.machine.txt'
          Write-Host 'Reset active paths to defaults (session only).' -ForegroundColor Green
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '14' {
          $backupPath = Join-Path -Path $dir -ChildPath 'backup.json'
          $pathUserFile = Join-Path -Path $dir -ChildPath 'path.user.txt'
          $pathMachineFile = Join-Path -Path $dir -ChildPath 'path.machine.txt'

          $cfgPath = Get-MenuConfigPath
          if (Test-Path -LiteralPath $cfgPath) {
            Remove-Item -LiteralPath $cfgPath -Force
            Write-Host ('Deleted saved config: {0}' -f $cfgPath) -ForegroundColor Green
          } else {
            Write-Host 'No saved config found.' -ForegroundColor Yellow
          }

          Write-Host 'Reset active paths to defaults.' -ForegroundColor Green
          $null = Read-MenuChoice -Prompt 'Press Enter to continue'
        }
        '0' { return }
        default {
          Write-Host 'Invalid option.' -ForegroundColor Yellow
          Start-Sleep -Milliseconds 800
        }
      }
    } catch {
      Write-Host ''
      $msg = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { [string]$_ }
      Write-Host $msg -ForegroundColor Red
      $null = Read-MenuChoice -Prompt 'Press Enter to continue'
    }
  }
}

switch ($PSCmdlet.ParameterSetName) {
  'Backup' {
    Write-BackupJson -Path $Path -Scopes $Scopes
  }
  'Restore' {
    Restore-FromBackup -Path $Path -Scopes $Scopes -Mode $Mode -Force:$Force
  }
  'Edit' {
    if (-not (Test-Path -LiteralPath $Path)) {
      Write-Host ('Backup missing; creating {0}' -f $Path) -ForegroundColor Yellow
      Write-BackupJson -Path $Path -Scopes $Scopes
    }

    Open-Editor -Path $Path -Editor $Editor

    # Also offer a PATH editing file that is easier to work with.
    $pathUserFile = [IO.Path]::ChangeExtension($Path, $null) + '.path.user.txt'
    $pathMachineFile = [IO.Path]::ChangeExtension($Path, $null) + '.path.machine.txt'

    if ($Scopes -eq 'user' -or $Scopes -eq 'both') {
      Export-PathFile -Scope user -PathFile $pathUserFile -Normalize
      Write-Host ('PATH (user) exported to: {0}' -f $pathUserFile) -ForegroundColor Yellow
    }

    if ($Scopes -eq 'machine' -or $Scopes -eq 'both') {
      Export-PathFile -Scope machine -PathFile $pathMachineFile -Normalize
      Write-Host ('PATH (system) exported to: {0}' -f $pathMachineFile) -ForegroundColor Yellow
    }

    Write-Host 'Edit JSON and/or PATH files, then apply:' -ForegroundColor Yellow
    Write-Host '  .\\env-manager.ps1 -Restore -Path \'$Path\" -Scopes $Scopes -Mode merge" -ForegroundColor Yellow
    Write-Host '  .\\env-manager.ps1 -PathImport -PathScope user -PathFile \'$pathUserFile\" -Normalize" -ForegroundColor Yellow
    Write-Host '  .\\env-manager.ps1 -PathImport -PathScope machine -PathFile \'$pathMachineFile\" -Normalize" -ForegroundColor Yellow
  }
  'List' {
    Show-Env -Scopes $ListScopes -AsJson:$AsJson
  }
  'Diff' {
    Show-Diff -Path $Path -Scopes $Scopes
  }
  'Validate' {
    Validate-Backup -Path $Path
  }
  'PathExport' {
    Export-PathFile -Scope $PathScope -PathFile $PathFile -Normalize:$Normalize
  }
  'PathImport' {
    Import-PathFile -Scope $PathScope -PathFile $PathFile -Normalize:$Normalize
  }
  'Menu' {
    Invoke-Menu -Editor $Editor
  }
  default {
    # If no parameter set matched (eg. no args), show menu.
    Invoke-Menu -Editor $Editor
  }
}

# SIG # Begin signature block
# MIID4QYJKoZIhvcNAQcCoIID0jCCA84CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUiuV1e0hiA4iatKUCnYreTHZT
# b0qgggH/MIIB+zCCAWSgAwIBAgIQK8KPnyZqh7ZLgu5QUg7L1TANBgkqhkiG9w0B
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
# BgkqhkiG9w0BCQQxFgQUJu0xVfh1MQQeR33IwA7TddAKp14wDQYJKoZIhvcNAQEB
# BQAEgYA2mgPIQZWl+xqbmlqxHkNDtKrkYmnbbsfO57bw2LITG+3hG2haDhfCfKR1
# XH989h1YteBDHMXIQKOoIzNtP1o3wn8ZxGuNGR2G/AOEmux8tmTj94TGeAQy25p3
# dXW+8ylm7sHnFNYZ4R1UI1zhhvJB7dWl879JMbfMuYFTaKbrvg==
# SIG # End signature block
