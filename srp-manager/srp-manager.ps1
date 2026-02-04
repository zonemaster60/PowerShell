#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Menu')]
param(
  [Parameter(ParameterSetName = 'Menu')]
  [switch]$Menu,

  [Parameter(ParameterSetName = 'List')]
  [switch]$List,

  [Parameter(ParameterSetName = 'Create', Mandatory)]
  [string]$CreateDescription,

  [Parameter(ParameterSetName = 'Create')]
  [ValidateSet('APPLICATION_INSTALL','APPLICATION_UNINSTALL','DEVICE_DRIVER_INSTALL','MODIFY_SETTINGS','CANCELLED_OPERATION')]
  [string]$CreateType = 'MODIFY_SETTINGS',

  [Parameter(ParameterSetName = 'Create')]
  [switch]$IgnoreFrequency,

  [Parameter(ParameterSetName = 'Create')]
  [ValidatePattern('^[A-Za-z]:(\\+)?$')]
  [string]$CreateDrive = "$($env:SystemDrive)\",

  [Parameter(ParameterSetName = 'Create')]
  [switch]$EnableIfNeeded,

  [Parameter(ParameterSetName = 'Create')]
  [switch]$NoTagPrefix,

  [Parameter(ParameterSetName = 'Restore', Mandatory)]
  [int]$RestoreSequenceNumber,

  [Parameter(ParameterSetName = 'Delete', Mandatory)]
  [int]$DeleteSequenceNumber,

  [Parameter(ParameterSetName = 'Enable', Mandatory)]
  [ValidatePattern('^[A-Za-z]:(\\+)?$')]
  [string]$EnableOnDrive
)

$script:UnboundArgs = $args

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $false }

  # UAC-safe check: confirm elevated token by running an admin-only command.
  try {
    & "$env:windir\System32\fltmc.exe" *> $null
    if (Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue) {
      return ($LASTEXITCODE -eq 0)
    }
    return $false
  } catch { return $false }
}

function ConvertTo-EscapedSingleQuotedString {
  param([Parameter(Mandatory)][string]$Value)
  "'" + ($Value -replace "'", "''") + "'"
}

function Get-ReinvokeArgumentList {
  # Reconstruct args from bound parameters so we can elevate reliably.
  $result = New-Object System.Collections.Generic.List[string]

  foreach ($kv in $PSBoundParameters.GetEnumerator()) {
    $name = [string]$kv.Key
    $value = $kv.Value

    if ($value -is [System.Management.Automation.SwitchParameter]) {
      if ($value.IsPresent) { $null = $result.Add("-$name") }
      continue
    }

    if ($value -is [bool]) {
      if ($value) { $null = $result.Add("-$name") }
      continue
    }

    $null = $result.Add("-$name")
    if ($null -eq $value) {
      $null = $result.Add("''")
    }
    elseif ($value -is [int] -or $value -is [long] -or $value -is [uint32] -or $value -is [double]) {
      $null = $result.Add([string]$value)
    }
    else {
      $null = $result.Add((ConvertTo-EscapedSingleQuotedString -Value ([string]$value)))
    }
  }

  # Preserve any unbound arguments too.
  if ($script:UnboundArgs -and $script:UnboundArgs.Count) {
    foreach ($a in $script:UnboundArgs) {
      $null = $result.Add((ConvertTo-EscapedSingleQuotedString -Value ([string]$a)))
    }
  }

  $result.ToArray()
}

function Invoke-SelfElevated {
  param([switch]$Interactive)

  if (-not $PSCommandPath) { throw 'Cannot self-elevate: PSCommandPath is empty.' }

  $scriptPath = $PSCommandPath

  if ($Interactive) {
    # For interactive menu mode we can't proxy IO; launch elevated window.
    $argList = @(
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-File', $scriptPath
    )

    try {
      Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList | Out-Null
    }
    catch {
      throw "Elevation was cancelled or failed: $($_.Exception.Message)"
    }
    exit 0
  }

  $tmp = [IO.Path]::GetTempFileName()
  $invokeArgs = Get-ReinvokeArgumentList

  $scriptPathSq = ConvertTo-EscapedSingleQuotedString -Value $scriptPath
  $tmpSq = ConvertTo-EscapedSingleQuotedString -Value $tmp
  $joined = if ($invokeArgs -and $invokeArgs.Length) { $invokeArgs -join ' ' } else { '' }

  $cmd = "& $scriptPathSq $joined *>&1 | Out-File -LiteralPath $tmpSq -Encoding UTF8; " +
    "`$v = Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue; " +
    "if (`$v) { exit [int]`$v.Value } else { exit 0 }"

  $argList = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-Command', $cmd
  )

  try {
    $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -PassThru -Wait
  }
  catch {
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    throw "Elevation was cancelled or failed: $($_.Exception.Message)"
  }

  try {
    if (Test-Path -LiteralPath $tmp) {
      $text = Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue
      if ($text) { Write-Output $text.TrimEnd("`r","`n") }
    }
  }
  finally {
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
  }

  exit $p.ExitCode
}

# Auto-elevate when needed.
if (-not (Test-IsAdmin)) {
  if ($PSBoundParameters.Count -eq 0 -or $PSCmdlet.ParameterSetName -eq 'Menu') {
    Invoke-SelfElevated -Interactive
  } else {
    Invoke-SelfElevated
  }
}

function Assert-Admin {
  <#
      .SYNOPSIS
      Describe purpose of "Assert-Admin" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Assert-Admin
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Assert-Admin

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  if (-not (Test-IsAdmin)) { throw "Elevation required. Re-run PowerShell as Administrator." }
}

function Convert-WmiDateTime {
  <#
      .SYNOPSIS
      Describe purpose of "Convert-WmiDateTime" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Value
      Describe parameter -Value.

      .EXAMPLE
      Convert-WmiDateTime -Value Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Convert-WmiDateTime

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory)][string]$Value)
  [Management.ManagementDateTimeConverter]::ToDateTime($Value)
}

function Get-SystemRestorePoints {
  <#
      .SYNOPSIS
      Describe purpose of "Get-SystemRestorePoints" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-SystemRestorePoints
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-SystemRestorePoints

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Assert-Admin
  $items = @(Get-WmiObject -Namespace root/default -Class SystemRestore)
  $items |
    ForEach-Object {
      [pscustomobject]@{
        SequenceNumber   = [int]$_.SequenceNumber
        CreatedAt        = Convert-WmiDateTime $_.CreationTime
        Description      = [string]$_.Description
        RestorePointType = [int]$_.RestorePointType
        EventType        = [int]$_.EventType
        Source           = Get-RestorePointSource -RestorePoint $_
      }
    } |
    Sort-Object SequenceNumber -Descending
}

function Wait-ForNewRestorePoint {
  param(
    [Parameter(Mandatory)][int]$BeforeMaxSequence,
    [Parameter(Mandatory)][string]$Description,
    [int]$TimeoutSeconds = 45
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    Start-Sleep -Milliseconds 750
    $all = @(Get-SystemRestorePoints)
    $newest = $all | Select-Object -First 1

    if ($newest -and ($newest.SequenceNumber -gt $BeforeMaxSequence)) { return $newest }

    $match = $all | Where-Object { $_.Description -eq $Description } | Select-Object -First 1
    if ($match) { return $match }
  } while ((Get-Date) -lt $deadline)

  return $null
}

function Set-RestorePointFrequencyOverride {
  <#
      .SYNOPSIS
      Describe purpose of "Set-RestorePointFrequencyOverride" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Enable
      Describe parameter -Enable.

      .EXAMPLE
      Set-RestorePointFrequencyOverride -Enable Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Set-RestorePointFrequencyOverride

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory)][bool]$Enable)

  $keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
  $name = 'SystemRestorePointCreationFrequency'

  $hadOld = $false
  $old = $null
  $p = Get-ItemProperty -Path $keyPath -Name $name -ErrorAction SilentlyContinue
  if ($null -ne $p) {
    $hadOld = $true
    $old = [int]$p.$name
  }

  if ($Enable) {
    $null = New-Item -Path $keyPath -Force
    $null = New-ItemProperty -Path $keyPath -Name $name -PropertyType DWord -Value 0 -Force
  }

  [pscustomobject]@{ HadOld = $hadOld
    OldValue = $old
    KeyPath = $keyPath
  Name = $name }
}

function Normalize-DriveRoot {
  param([Parameter(Mandatory)][string]$Drive)

  $d = $Drive.Trim()
  if ($d -match '^[A-Za-z]:$') { return ($d + '\\') }
  if ($d -match '^[A-Za-z]:(\\)+$') { return ($d.Substring(0,2) + '\\') }
  throw "Drive must look like C: or C:\\"
}

function Get-RestorePointSource {
  param([Parameter(Mandatory)][object]$RestorePoint)

  $desc = [string]$RestorePoint.Description
  $rpt = 0
  try { $rpt = [int]$RestorePoint.RestorePointType } catch { $rpt = 0 }

  if ($desc -match '^\[SRP\]' -or $desc -match '^SRP(\b|\s)') { return 'SRP-Manager' }
  if ($desc -match '(?i)windows\s+update' -or $rpt -eq 17) { return 'Windows Update' }
  return 'Other'
}

function Get-SystemRestoreClass {
  # Direct WMI class reference is more reliable than Get-WmiObject -List.
  [WMIClass]'\\\\.\\root\\default:SystemRestore'
}

function Format-CreateRestorePointError {
  param([Parameter(Mandatory)][int]$ReturnValue)

  $hint = switch ($ReturnValue) {
    0 { 'Success.' }
    2 { 'Access denied. Run PowerShell as Administrator.' }
    3 { 'Insufficient storage. Increase System Protection disk usage.' }
    4 { 'System Protection is disabled. Enable it on your system drive (menu option 5).' }
    5 { 'System Protection is disabled or blocked by policy. Enable it and try again.' }
    default { 'Unknown/unspecified failure.' }
  }

  "CreateRestorePoint failed. ReturnValue=$ReturnValue. $hint"
}

function Restore-RestorePointFrequencyOverride {
  <#
      .SYNOPSIS
      Describe purpose of "Restore-RestorePointFrequencyOverride" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER State
      Describe parameter -State.

      .EXAMPLE
      Restore-RestorePointFrequencyOverride -State Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Restore-RestorePointFrequencyOverride

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory)][Object]$State)
  if ($State.HadOld) {
    $null = Set-ItemProperty -Path $State.KeyPath -Name $State.Name -Value $State.OldValue -Force
  } else {
    Remove-ItemProperty -Path $State.KeyPath -Name $State.Name -ErrorAction SilentlyContinue
  }
}

function New-SystemRestorePoint {
  <#
      .SYNOPSIS
      Describe purpose of "New-SystemRestorePoint" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Description
      Describe parameter -Description.

      .PARAMETER Type
      Describe parameter -Type.

      .PARAMETER IgnoreFrequency
      Describe parameter -IgnoreFrequency.

      .EXAMPLE
      New-SystemRestorePoint -Description Value -Type Value -IgnoreFrequency
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online New-SystemRestorePoint

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory)][string]$Description,
    [Parameter(Mandatory)][ValidateSet('APPLICATION_INSTALL','APPLICATION_UNINSTALL','DEVICE_DRIVER_INSTALL','MODIFY_SETTINGS','CANCELLED_OPERATION')]
    [string]$Type,
    [switch]$IgnoreFrequency,
    [string]$Drive = "$($env:SystemDrive)\\",
    [switch]$EnableIfNeeded,
    [switch]$NoTagPrefix
  )

  Assert-Admin

  $desc = $Description.Trim()
  if ([string]::IsNullOrWhiteSpace($desc)) { throw "Description cannot be empty." }
  if ($desc.Length -gt 255) { throw "Description is too long (max 255 characters)." }

  if (-not $NoTagPrefix) {
    if ($desc -notmatch '^\[SRP\]' -and $desc -notmatch '^SRP(\b|\s)') {
      $tagged = "[SRP] $desc"
      if ($tagged.Length -le 255) { $desc = $tagged }
    }
  }

  $before = @(Get-SystemRestorePoints)
  $beforeMaxSeq = if ($before.Count) { [int]($before | Measure-Object -Property SequenceNumber -Maximum).Maximum } else { 0 }

  $overrideState = $null
  try {
    if ($IgnoreFrequency) {
      $overrideState = Set-RestorePointFrequencyOverride -Enable $true
    }

    $driveRoot = Normalize-DriveRoot $Drive
    if ($EnableIfNeeded) {
      try {
        Enable-ComputerRestore -Drive $driveRoot -ErrorAction Stop | Out-Null
      }
      catch {
        # Best-effort; creation will surface the actual error if it still fails.
      }
    }

    # Preferred: Checkpoint-Computer often provides clearer error messages.
    $checkpointError = $null
    try {
      Checkpoint-Computer -Description $desc -RestorePointType $Type
      $rp = Wait-ForNewRestorePoint -BeforeMaxSequence $beforeMaxSeq -Description $desc
      if ($rp) { return $rp }
      throw "Checkpoint-Computer returned without error, but no new restore point appeared."
    }
    catch {
      $checkpointError = $_.Exception.Message

      # Fallback: WMI CreateRestorePoint with numeric ReturnValue.
      $typeMap = @{
        APPLICATION_INSTALL    = 0
        APPLICATION_UNINSTALL  = 1
        DEVICE_DRIVER_INSTALL  = 10
        MODIFY_SETTINGS        = 12
        CANCELLED_OPERATION    = 13
      }

      $sr = Get-SystemRestoreClass
      if (-not $sr) { throw "WMI class SystemRestore not available (root\default:SystemRestore)." }

      # EventType: 100 = BEGIN_SYSTEM_CHANGE (common for manual restore points)
      try {
        $rc = [int]$sr.CreateRestorePoint($desc, [uint32]$typeMap[$Type], [uint32]100)
      }
      catch {
        $wmiError = $_.Exception.Message
        throw "CreateRestorePoint failed via WMI: $wmiError. Checkpoint-Computer error: $checkpointError"
      }

      if ($rc -ne 0) {
        $msg = Format-CreateRestorePointError -ReturnValue $rc
        if ($checkpointError) { $msg += " Checkpoint-Computer error: $checkpointError" }
        throw $msg
      }

      $rp = Wait-ForNewRestorePoint -BeforeMaxSequence $beforeMaxSeq -Description $desc
      if ($rp) { return $rp }

      $after = @(Get-SystemRestorePoints)
      $newest = $after | Select-Object -First 1
      $newestMsg = if ($newest) {
        "SequenceNumber=$($newest.SequenceNumber) CreatedAt=$($newest.CreatedAt) Description='$($newest.Description)'"
      } else {
        '<none>'
      }

      $msg = "CreateRestorePoint returned success, but no new restore point appeared within the timeout. Latest observed: $newestMsg."
      if ($checkpointError) { $msg += " Checkpoint-Computer error: $checkpointError" }
      throw $msg
    }
  }
  finally {
    if ($IgnoreFrequency -and $overrideState) {
      Restore-RestorePointFrequencyOverride -State $overrideState
    }
  }
}

function Invoke-SystemRestore {
  <#
      .SYNOPSIS
      Describe purpose of "Invoke-SystemRestore" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER SequenceNumber
      Describe parameter -SequenceNumber.

      .EXAMPLE
      Invoke-SystemRestore -SequenceNumber Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Invoke-SystemRestore

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory)][int]$SequenceNumber)

  Assert-Admin

  $sr = Get-SystemRestoreClass
  if (-not $sr) { throw "WMI class SystemRestore not available (root\default:SystemRestore)." }

  $rc = $sr.Restore([uint32]$SequenceNumber)
  if ($rc -ne 0) { throw ('Restore failed to start. ReturnValue={0}' -f $rc) }

  ('Restore initiated for SequenceNumber={0}. A reboot may be required to complete.' -f $SequenceNumber)
}

function Remove-SystemRestorePoint {
  <#
      .SYNOPSIS
      Describe purpose of "Remove-SystemRestorePoint" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER SequenceNumber
      Describe parameter -SequenceNumber.

      .EXAMPLE
      Remove-SystemRestorePoint -SequenceNumber Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Remove-SystemRestorePoint

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory)][int]$SequenceNumber)

  Assert-Admin

  if (-not ('SR.NativeMethods' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace SR {
  public static class NativeMethods {
    [DllImport("srclient.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int SRRemoveRestorePoint(int dwRPNum);
  }
}
"@
  }

  $rc = [SR.NativeMethods]::SRRemoveRestorePoint($SequenceNumber)
  if ($rc -ne 0) {
    throw (('Delete failed. SRRemoveRestorePoint returned {0} (typically a Win32 error code). ' +
      'On many Windows builds, deleting individual restore points is not supported; use VSS delete oldest/all instead.') -f $rc)
  }

  ('Deleted restore point SequenceNumber={0}.' -f $SequenceNumber)
}

function Remove-ShadowCopies {
  param(
    [Parameter(Mandatory)][ValidateSet('Oldest','All')][string]$Mode,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:$')][string]$ForDrive
  )

  Assert-Admin

  function New-AsrBlockedMessage {
    param(
      [Parameter(Mandatory)][string]$Attempt,
      [string]$Details
    )

    $msg = "Microsoft Defender Exploit Guard / ASR blocked shadow copy deletion ($Attempt). " +
      "Even as Administrator, ASR can enforce policy blocks. " +
      "If this is a managed device, only your security policy can allow it. " +
      "Workaround without changing policy: use the built-in System Protection UI (SystemPropertiesProtection.exe) and delete restore points from there."

    if ($Details) { $msg += " Details: $Details" }
    $msg
  }

  function Get-VolumeDeviceId {
    param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:$')][string]$Drive)
    $vol = Get-CimInstance -ClassName Win32_Volume -Filter ("DriveLetter='{0}'" -f $Drive)
    if (-not $vol) { throw "Could not find volume for drive $Drive" }
    [string]$vol.DeviceID
  }

  function Get-ShadowCopiesForDrive {
    param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:$')][string]$Drive)
    $deviceId = Get-VolumeDeviceId -Drive $Drive
    @(Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.VolumeName -eq $deviceId } | Sort-Object InstallDate)
  }

  # Attempt deletion via WMI/CIM first (often less likely to be blocked than vssadmin.exe).
  try {
    $shadows = Get-ShadowCopiesForDrive -Drive $ForDrive
    if (-not $shadows.Count) { return "No shadow copies found for $ForDrive" }

    $targets = if ($Mode -eq 'Oldest') { @($shadows | Select-Object -First 1) } else { $shadows }
    foreach ($sc in $targets) {
      $r = Invoke-CimMethod -InputObject $sc -MethodName Delete
      if ($r -and $r.ReturnValue -ne 0) {
        throw "WMI delete failed (ReturnValue=$($r.ReturnValue)) for ShadowID=$($sc.ID)"
      }
    }

    if ($Mode -eq 'Oldest') { return "Deleted oldest shadow copy for $ForDrive" }
    return "Deleted all shadow copies for $ForDrive"
  }
  catch {
    $wmiErr = $_.Exception.Message

    # Fall back to vssadmin for environments where CIM delete isn't available.
    # Note: this is commonly blocked by Defender ASR rules.
    $args = @('delete','shadows',"/For=$ForDrive",'/Quiet')
    if ($Mode -eq 'Oldest') { $args += '/Oldest' }
    else { $args += '/All' }

    $out = [IO.Path]::GetTempFileName()
    $err = [IO.Path]::GetTempFileName()
    try {
      $p = Start-Process -FilePath "$env:windir\System32\vssadmin.exe" -ArgumentList $args -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
      $stdout = (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
      $stderr = (Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue)
      $text = (($stdout + "`n" + $stderr).Trim())

      if ($p.ExitCode -ne 0) {
        if ($text -match '(?i)access\s+is\s+denied') {
          throw (New-AsrBlockedMessage -Attempt 'vssadmin.exe' -Details ("WMI/CIM failed: $wmiErr"))
        }

        if ($text) { throw "vssadmin failed (ExitCode=$($p.ExitCode)). Output: $text" }
        throw "vssadmin failed (ExitCode=$($p.ExitCode))."
      }

      if ($text) { return $text }
      "Deleted shadow copies ($Mode) for $ForDrive"
    }
    finally {
      Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath $err -ErrorAction SilentlyContinue
    }
  }
}

function Open-SystemProtectionUI {
  Assert-Admin
  $path = "$env:windir\System32\SystemPropertiesProtection.exe"
  if (Test-Path -LiteralPath $path) {
    Start-Process -FilePath $path | Out-Null
    return 'Opened System Protection UI.'
  }

  Start-Process -FilePath "$env:windir\System32\control.exe" -ArgumentList 'sysdm.cpl,,4' | Out-Null
  'Opened System Properties (System Protection tab).'
}

function Enable-SystemProtection {
  <#
      .SYNOPSIS
      Describe purpose of "Enable-SystemProtection" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Drive
      Describe parameter -Drive.

      .EXAMPLE
      Enable-SystemProtection -Drive Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Enable-SystemProtection

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory)][string]$Drive)
  Assert-Admin
  $d = Normalize-DriveRoot $Drive
  Enable-ComputerRestore -Drive $d
  ('System Protection enabled on {0}' -f $d)
}

function Read-Choice {
  <#
      .SYNOPSIS
      Describe purpose of "Read-Choice" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Prompt
      Describe parameter -Prompt.

      .PARAMETER Valid
      Describe parameter -Valid.

      .EXAMPLE
      Read-Choice -Prompt Value -Valid Value
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
    [Parameter(Mandatory)][string]$Prompt,
    [Parameter(Mandatory)][string[]]$Valid
  )
  while ($true) {
    $v = (Read-Host $Prompt).Trim()
    if ($Valid -contains $v) { return $v }
    Write-Host ('Invalid choice. Valid: {0}' -f ($Valid -join ', ')) -ForegroundColor Yellow
  }
}

function Read-Int {
  <#
      .SYNOPSIS
      Describe purpose of "Read-Int" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Prompt
      Describe parameter -Prompt.

      .EXAMPLE
      Read-Int -Prompt Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Read-Int

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param([Parameter(Mandatory)][string]$Prompt)
  while ($true) {
    $s = (Read-Host $Prompt).Trim()
    $n = 0
    if ([int]::TryParse($s, [ref]$n)) { return $n }
    Write-Host "Enter a whole number." -ForegroundColor Yellow
  }
}

function Read-YesNo {
  <#
      .SYNOPSIS
      Describe purpose of "Read-YesNo" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Prompt
      Describe parameter -Prompt.

      .PARAMETER DefaultNo
      Describe parameter -DefaultNo.

      .EXAMPLE
      Read-YesNo -Prompt Value -DefaultNo
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


  param([Parameter(Mandatory)][string]$Prompt, [switch]$DefaultNo)
  while ($true) {
    $suffix = if ($DefaultNo) { " (y/N)" } else { " (Y/n)" }
    $s = (Read-Host ($Prompt + $suffix)).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($s)) { return (-not $DefaultNo) }
    if ($s -in @('y','yes')) { return $true }
    if ($s -in @('n','no')) { return $false }
    Write-Host "Answer y or n." -ForegroundColor Yellow
  }
}

function Show-RestorePoints {
  <#
      .SYNOPSIS
      Describe purpose of "Show-RestorePoints" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Show-RestorePoints
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Show-RestorePoints

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $rps = @(Get-SystemRestorePoints)
  if ($rps.Count -eq 0) {
    Write-Host "No restore points found." -ForegroundColor Yellow
    return
  }
  $rps | Format-Table SequenceNumber, CreatedAt, Source, RestorePointType, EventType, Description -AutoSize
}

function Show-RestorePointsDetailed {
  $rps = @(Get-SystemRestorePoints)
  if ($rps.Count -eq 0) {
    Write-Host "No restore points found." -ForegroundColor Yellow
    return
  }

  $rps |
    Sort-Object CreatedAt -Descending |
    Format-Table SequenceNumber, CreatedAt, Source, RestorePointType, EventType, Description -AutoSize
}

function Start-RestorePointMenu {
  <#
      .SYNOPSIS
      Describe purpose of "Start-RestorePointMenu" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Start-RestorePointMenu
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Start-RestorePointMenu

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $firstScreen = $true
  while ($true) {
    if (-not $firstScreen) {
      Read-Host "Press Enter to continue" | Out-Null
    }
    $firstScreen = $false
    Clear-Host
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host "System Restore Point Manager" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host "  1) List restore points"
    Write-Host "  9) List restore points (details)"
    Write-Host "  2) Create restore point"
    Write-Host "  3) Restore to a restore point"
    Write-Host "  4) Delete oldest restore point (recommended)"
    Write-Host "  5) Enable System Protection on a drive"
    Write-Host "  6) Delete restore point by SequenceNumber (best-effort)"
    Write-Host "  7) Delete all restore points (via VSS)"
    Write-Host "  8) Open System Protection UI"
    Write-Host "  0) Exit"
    Write-Host ""

    $choice = Read-Choice -Prompt "Select an option" -Valid @('0','1','2','3','4','5','6','7','8','9')

    try {
      switch ($choice) {
        '1' {
          Show-RestorePoints
        }
        '9' {
          Show-RestorePointsDetailed
        }
        '2' {
          Assert-Admin
          $desc = (Read-Host "Description").Trim()
          if ([string]::IsNullOrWhiteSpace($desc)) { throw "Description cannot be empty." }

          Write-Host "Type:"
          Write-Host "  1) MODIFY_SETTINGS (recommended)"
          Write-Host "  2) APPLICATION_INSTALL"
          Write-Host "  3) APPLICATION_UNINSTALL"
          Write-Host "  4) DEVICE_DRIVER_INSTALL"
          Write-Host "  5) CANCELLED_OPERATION"

          $t = Read-Choice -Prompt "Select type" -Valid @('1','2','3','4','5')
          $type = switch ($t) {
            '1' { 'MODIFY_SETTINGS' }
            '2' { 'APPLICATION_INSTALL' }
            '3' { 'APPLICATION_UNINSTALL' }
            '4' { 'DEVICE_DRIVER_INSTALL' }
            '5' { 'CANCELLED_OPERATION' }
          }

          $ignore = Read-YesNo -Prompt "Ignore frequency limit (often needed)" -DefaultNo
          $enable = Read-YesNo -Prompt "Try enabling System Protection if needed" -DefaultNo
          $rp = New-SystemRestorePoint -Description $desc -Type $type -IgnoreFrequency:$ignore -Drive "$($env:SystemDrive)\\" -EnableIfNeeded:$enable
          Write-Host "Created:" -ForegroundColor Green
          $rp | Format-List SequenceNumber, CreatedAt, Description
        }
        '3' {
          Assert-Admin
          Show-RestorePoints
          $seq = Read-Int -Prompt "Enter SequenceNumber to restore to"
          $ok = Read-YesNo -Prompt ('Start restore to SequenceNumber={0} (you may need to reboot)' -f $seq) -DefaultNo
          if ($ok) {
            Invoke-SystemRestore -SequenceNumber $seq | Write-Host -ForegroundColor Green
          } else {
            Write-Host "Cancelled." -ForegroundColor Yellow
          }
        }
        '4' {
          Assert-Admin
          $drive = (Read-Host "Drive for VSS delete (example: C:)").Trim()
          if ($drive -notmatch '^[A-Za-z]:$') { throw "Drive must look like C:" }

          Show-RestorePoints
          $ok = Read-YesNo -Prompt ("Delete OLDEST restore point/shadow copy for {0}" -f $drive) -DefaultNo
          if ($ok) {
            try {
              Remove-ShadowCopies -Mode Oldest -ForDrive $drive | Write-Host -ForegroundColor Green
            }
            catch {
              $msg = $_.Exception.Message
              Write-Host $msg -ForegroundColor Red
              if ($msg -match '(?i)exploit\s+guard|attack\s+surface\s+reduction|\bASR\b') {
                Write-Host 'Opening System Protection UI as a fallback...' -ForegroundColor Yellow
                Open-SystemProtectionUI | Write-Host -ForegroundColor Green
              }
            }
          }
          else { Write-Host "Cancelled." -ForegroundColor Yellow }
        }
        '5' {
          Assert-Admin
          $drive = (Read-Host "Drive (example: C: or C:\\)").Trim()
          if ($drive -notmatch '^[A-Za-z]:(\\)?$') { throw "Drive must look like C: or C:\\" }
          Enable-SystemProtection -Drive $drive | Write-Host -ForegroundColor Green
        }
        '6' {
          Assert-Admin
          Show-RestorePoints
          $seq = Read-Int -Prompt "Enter SequenceNumber to delete"
          $ok = Read-YesNo -Prompt ('Delete restore point SequenceNumber={0} (best-effort; may fail on this Windows build)' -f $seq) -DefaultNo
          if ($ok) { Remove-SystemRestorePoint -SequenceNumber $seq | Write-Host -ForegroundColor Green }
          else { Write-Host "Cancelled." -ForegroundColor Yellow }
        }
        '7' {
          Assert-Admin
          $drive = (Read-Host "Drive for VSS delete (example: C:)").Trim()
          if ($drive -notmatch '^[A-Za-z]:$') { throw "Drive must look like C:" }
          $ok = Read-YesNo -Prompt ("Delete ALL restore points/shadow copies for {0}" -f $drive) -DefaultNo
          if ($ok) { Remove-ShadowCopies -Mode All -ForDrive $drive | Write-Host -ForegroundColor Green }
          else { Write-Host "Cancelled." -ForegroundColor Yellow }
        }
        '8' {
          Open-SystemProtectionUI | Write-Host -ForegroundColor Green
        }
        '0' {
          return
        }
      }
    }
    catch {
      Write-Host $_.Exception.Message -ForegroundColor Red
    }
  }
}

# Default behavior: menu when no args provided
if ($PSBoundParameters.Count -eq 0 -or $PSCmdlet.ParameterSetName -eq 'Menu') {
  Start-RestorePointMenu
  return
}

switch ($PSCmdlet.ParameterSetName) {
  'List'   { Get-SystemRestorePoints | Format-Table SequenceNumber, CreatedAt, Source, RestorePointType, EventType, Description -AutoSize }
  'Create' { New-SystemRestorePoint -Description $CreateDescription -Type $CreateType -IgnoreFrequency:$IgnoreFrequency -Drive $CreateDrive -EnableIfNeeded:$EnableIfNeeded -NoTagPrefix:$NoTagPrefix }
  'Restore'{ Invoke-SystemRestore -SequenceNumber $RestoreSequenceNumber }
  'Delete' { Remove-SystemRestorePoint -SequenceNumber $DeleteSequenceNumber }
  'Enable' { Enable-SystemProtection -Drive $EnableOnDrive }
}

# SIG # Begin signature block
# MIID4QYJKoZIhvcNAQcCoIID0jCCA84CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDPX6WqE4VJucAP2mCKtDSbTh
# wH6gggH/MIIB+zCCAWSgAwIBAgIQK8KPnyZqh7ZLgu5QUg7L1TANBgkqhkiG9w0B
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
# BgkqhkiG9w0BCQQxFgQU21IKas2+BZlYqF4jZ1d215jCnJEwDQYJKoZIhvcNAQEB
# BQAEgYAkQnR3a5PSQyqDAp1V6sBiGmx41sVTwMuiPGP3diExRE9poF7FcWWYGXfC
# 8ZzpkFOPMat1gaVduLCp22vgdmypU5Bbc5dtmgIqjduBfoyS7UEdu72OQ+gyx93t
# 9CCIGzOtDTK+7/ZQ2iPwGZX5ZFUFhudCU3ZrXqyMDXzy9LaNpQ==
# SIG # End signature block
