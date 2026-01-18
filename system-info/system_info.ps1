[CmdletBinding()]
param(
  # Default output saves next to this script.
  [string]$OutFile,

  # Pretty JSON is the default; use -Compress for one-line output.
  [switch]$Compress,

  # If set, prints all devices/drivers at once (can be huge).
  [switch]$NoPaging,

  # Optional filters for displayed/saved device list.
  # Examples:
  #   -DeviceClass Net
  #   -DeviceNameLike "*Bluetooth*"
  [string]$DeviceClass,
  [string]$DeviceNameLike,

  # Optional filters for displayed/saved driver list.
  # Examples:
  #   -DriverProviderLike "*Intel*"
  #   -DriverDeviceNameLike "*Realtek*"
  [string]$DriverProviderLike,
  [string]$DriverDeviceNameLike
)

$ErrorActionPreference = 'SilentlyContinue'

function Get-OsSoftwareInfo {
  <#
      .SYNOPSIS
      Describe purpose of "Get-OsSoftwareInfo" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-OsSoftwareInfo
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-OsSoftwareInfo

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $os = Get-CimInstance Win32_OperatingSystem
  $cs = Get-CimInstance Win32_ComputerSystem

  [pscustomobject]@{
    ComputerName      = $env:COMPUTERNAME
    UserName          = $env:USERNAME
    OSName            = $os.Caption
    OSVersion         = $os.Version
    BuildNumber       = $os.BuildNumber
    InstallDate       = $os.InstallDate
    LastBootUpTime    = $os.LastBootUpTime
    Manufacturer      = $cs.Manufacturer
    Model             = $cs.Model
    Domain            = $cs.Domain
  }
}

function Get-HardwareInfo {
  <#
      .SYNOPSIS
      Describe purpose of "Get-HardwareInfo" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-HardwareInfo
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-HardwareInfo

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
  $bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
  $mem = Get-CimInstance Win32_PhysicalMemory

  $totalMemBytes = ($mem | Measure-Object -Property Capacity -Sum).Sum

  [pscustomobject]@{
    CPU = [pscustomobject]@{
      Name              = $cpu.Name
      Manufacturer      = $cpu.Manufacturer
      Cores             = $cpu.NumberOfCores
      LogicalProcessors = $cpu.NumberOfLogicalProcessors
      MaxClockSpeedMHz  = $cpu.MaxClockSpeed
      ProcessorId       = $cpu.ProcessorId
    }
    BIOS = [pscustomobject]@{
      Manufacturer      = $bios.Manufacturer
      SMBIOSBIOSVersion = $bios.SMBIOSBIOSVersion
      SerialNumber      = $bios.SerialNumber
      ReleaseDate       = $bios.ReleaseDate
    }
    Memory = [pscustomobject]@{
      TotalBytes = $totalMemBytes
      TotalGB    = [math]::Round($totalMemBytes / 1GB, 2)
      Modules    = @($mem | ForEach-Object {
          [pscustomobject]@{
            CapacityGB   = [math]::Round($_.Capacity / 1GB, 2)
            SpeedMHz     = $_.Speed
            Manufacturer = $_.Manufacturer
            PartNumber   = $_.PartNumber
            SerialNumber = $_.SerialNumber
          }
        })
    }
    Disks = @(
      Get-CimInstance Win32_DiskDrive | ForEach-Object {
        [pscustomobject]@{
          Model        = $_.Model
          SizeGB       = [math]::Round($_.Size / 1GB, 2)
          Interface    = $_.InterfaceType
          SerialNumber = $_.SerialNumber
        }
      }
    )
  }
}

function Get-NetworkInfo {
  <#
      .SYNOPSIS
      Describe purpose of "Get-NetworkInfo" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-NetworkInfo
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-NetworkInfo

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $adapters = Get-NetAdapter | Sort-Object -Property Status, Name
  $ip = Get-NetIPAddress |
    Where-Object { $_.AddressFamily -in @("IPv4", "IPv6") } |
    Sort-Object -Property InterfaceIndex

  [pscustomobject]@{
    Hostname = $env:COMPUTERNAME
    Adapters = @($adapters | ForEach-Object {
        [pscustomobject]@{
          Name                 = $_.Name
          InterfaceDescription = $_.InterfaceDescription
          Status               = $_.Status
          MacAddress           = $_.MacAddress
          LinkSpeed            = ('{0}' -f $_.LinkSpeed)
        }
      })
    IPAddresses = @($ip | ForEach-Object {
        [pscustomobject]@{
          InterfaceAlias = $_.InterfaceAlias
          IPAddress      = $_.IPAddress
          PrefixLength   = $_.PrefixLength
        }
      })
    DnsClientServerAddresses = @(
      Get-DnsClientServerAddress | ForEach-Object {
        [pscustomobject]@{
          InterfaceAlias  = $_.InterfaceAlias
          ServerAddresses = $_.ServerAddresses
        }
      }
    )
    Routes = @(
      Get-NetRoute | Select-Object -First 200 | ForEach-Object {
        [pscustomobject]@{
          DestinationPrefix = $_.DestinationPrefix
          NextHop           = $_.NextHop
          InterfaceAlias    = $_.InterfaceAlias
          RouteMetric       = $_.RouteMetric
        }
      }
    )
  }
}

function Get-InternetInfo {
  <#
      .SYNOPSIS
      Describe purpose of "Get-InternetInfo" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-InternetInfo
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-InternetInfo

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $pingTarget = "1.1.1.1"
  $dnsTarget = "www.microsoft.com"

  $pingOk = Test-Connection -ComputerName $pingTarget -Count 1 -Quiet
  $dnsResult = Resolve-DnsName $dnsTarget -ErrorAction SilentlyContinue | Select-Object -First 1

  [pscustomobject]@{
    PingTarget  = $pingTarget
    PingOk      = [bool]$pingOk
    DnsTestName = $dnsTarget
    DnsResolved = [bool]$dnsResult
    DnsAnswer   = $dnsResult.IPAddress
  }
}

function Get-DevicesInfo {
  <#
      .SYNOPSIS
      Describe purpose of "Get-DevicesInfo" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-DevicesInfo
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-DevicesInfo

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $pnp = Get-PnpDevice | Sort-Object -Property Class, FriendlyName

  if ($DeviceClass) {
    $pnp = $pnp | Where-Object { $_.Class -eq $DeviceClass }
  }
  if ($DeviceNameLike) {
    $pnp = $pnp | Where-Object { $_.FriendlyName -like $DeviceNameLike }
  }

  [pscustomobject]@{
    PnpDevices = @(
      $pnp | ForEach-Object {
        [pscustomobject]@{
          FriendlyName = $_.FriendlyName
          Class        = $_.Class
          Status       = $_.Status
          InstanceId   = $_.InstanceId
          Manufacturer = $_.Manufacturer
        }
      }
    )
  }
}

function Get-DriversInfo {
  <#
      .SYNOPSIS
      Describe purpose of "Get-DriversInfo" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Get-DriversInfo
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-DriversInfo

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  $signed = Get-CimInstance Win32_PnPSignedDriver |
    Sort-Object -Property DriverProviderName, DeviceName

  if ($DriverProviderLike) {
    $signed = $signed | Where-Object { $_.DriverProviderName -like $DriverProviderLike }
  }
  if ($DriverDeviceNameLike) {
    $signed = $signed | Where-Object { $_.DeviceName -like $DriverDeviceNameLike }
  }

  [pscustomobject]@{
    SignedDrivers = @(
      $signed | ForEach-Object {
        [pscustomobject]@{
          DeviceName     = $_.DeviceName
          DriverVersion  = $_.DriverVersion
          DriverDate     = $_.DriverDate
          DriverProvider = $_.DriverProviderName
          InfName        = $_.InfName
          IsSigned       = $_.IsSigned
        }
      }
    )
  }
}

$report = [pscustomobject]@{
  Meta = [pscustomobject]@{
    Timestamp = (Get-Date).ToString("o")
    Tool      = "system_info.ps1"
    Elevated  = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator
    )
  }
  Hardware = Get-HardwareInfo
  Software = Get-OsSoftwareInfo
  Internet = Get-InternetInfo
  Network  = Get-NetworkInfo
  Devices  = Get-DevicesInfo
  Drivers  = Get-DriversInfo
}

function Write-Section {
  <#
      .SYNOPSIS
      Describe purpose of "Write-Section" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER Title
      Describe parameter -Title.

      .EXAMPLE
      Write-Section -Title Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Write-Section

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  
  [CmdletBinding()]
  param
  (
    [string]
    $Title
  )
  Write-Host ""
  Write-Host ('=== {0} ===' -f $Title) -ForegroundColor Cyan
}

function Pause-BeforeSave {
  <#
      .SYNOPSIS
      Describe purpose of "Pause-BeforeSave" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .EXAMPLE
      Pause-BeforeSave
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Pause-BeforeSave

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Write-Host ""
  Write-Host "Review the info above." -ForegroundColor Yellow
  Write-Host ('Press any key to save JSON to: {0}' -f $OutFile) -ForegroundColor Yellow

  try {
    if ($Host.UI -and $Host.UI.RawUI) {
      $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
      return
    }
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

  # Fallback for hosts without RawUI support.
  $null = Read-Host "Press ENTER to save"
}

function Write-PagedTable {
  <#
      .SYNOPSIS
      Describe purpose of "Write-PagedTable" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER InputObject
      Describe parameter -InputObject.

      .PARAMETER PageSize
      Describe parameter -PageSize.

      .PARAMETER DisablePaging
      Describe parameter -DisablePaging.

      .EXAMPLE
      Write-PagedTable -InputObject Value -PageSize Value -DisablePaging
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Write-PagedTable

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  param(
    [Parameter(Mandatory = $true)]
    [Object]$InputObject,

    [int]$PageSize = 35,

    [switch]$DisablePaging
  )

  $rows = @($InputObject)
  if ($rows.Count -eq 0) {
    Write-Host "(none)" -ForegroundColor DarkGray
    return
  }

  if ($DisablePaging) {
    $rows | Format-Table -AutoSize | Out-String -Width 4000 | Write-Host
    return
  }

  $i = 0
  while ($i -lt $rows.Count) {
    $chunk = $rows[$i..([math]::Min($i + $PageSize - 1, $rows.Count - 1))]
    $chunk | Format-Table -AutoSize | Out-String -Width 4000 | Write-Host

    $i += $PageSize
    if ($i -lt $rows.Count) {
      Write-Host ("-- Showing {0}-{1} of {2}. Press any key for more --" -f ($i - $PageSize + 1), $i, $rows.Count) -ForegroundColor Yellow
      try {
        if ($Host.UI -and $Host.UI.RawUI) {
          $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        } else {
          $null = Read-Host "Press ENTER for more"
        }
      } catch {
        $null = Read-Host "Press ENTER for more"
      }
      Write-Host ""
    }
  }
}

# Display summary on screen
Clear-Host
Write-Host "System Info Report" -ForegroundColor Green
Write-Host ('Generated: {0}' -f $report.Meta.Timestamp) -ForegroundColor DarkGray
Write-Host ('Elevated:  {0}' -f $report.Meta.Elevated) -ForegroundColor DarkGray

Write-Section "Software"
$report.Software | Format-List | Out-String | Write-Host

Write-Section "Hardware"
$report.Hardware.CPU | Format-List | Out-String | Write-Host
$report.Hardware.BIOS | Format-List | Out-String | Write-Host
$report.Hardware.Memory | Select-Object -ExpandProperty TotalGB | Format-List | Out-String | Write-Host
Write-Host "Disks:" -ForegroundColor DarkGray
$report.Hardware.Disks | Format-Table -AutoSize | Out-String | Write-Host

Write-Section "Internet"
$report.Internet | Format-List | Out-String | Write-Host

Write-Section "Network (Adapters)"
$report.Network.Adapters | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "IP Addresses:" -ForegroundColor DarkGray
$report.Network.IPAddresses | Format-Table -AutoSize | Out-String | Write-Host

Write-Section "Devices (ALL)"
Write-PagedTable -InputObject $report.Devices.PnpDevices -DisablePaging:$NoPaging

Write-Section "Drivers (ALL)"
Write-PagedTable -InputObject $report.Drivers.SignedDrivers -DisablePaging:$NoPaging

Pause-BeforeSave

# Choose default output next to script.
if (-not $OutFile -or $OutFile.Trim().Length -eq 0) {
  $scriptDir = $PSScriptRoot
  if (-not $scriptDir -or $scriptDir.Trim().Length -eq 0) {
    # Fallback for some hosts (should be rare)
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
  }
  $OutFile = Join-Path $scriptDir "system-info.json"
}

$json = if ($Compress) { $report | ConvertTo-Json -Depth 8 -Compress } else { $report | ConvertTo-Json -Depth 8 }

# Resolve OutFile robustly.
$resolvedOutFile = $OutFile
try {
  $resolvedOutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
} catch {
  try {
    $resolvedOutFile = [IO.Path]::GetFullPath($OutFile)
  } catch {
    $resolvedOutFile = $OutFile
  }
}

try {
  $json | Out-File -FilePath $resolvedOutFile -Encoding utf8 -Force
  Write-Host ('Saved: {0}' -f $resolvedOutFile) -ForegroundColor Green
} catch {
  Write-Host ('Failed to save: {0}' -f $resolvedOutFile) -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
}

# SIG # Begin signature block
# MIID4QYJKoZIhvcNAQcCoIID0jCCA84CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUw04rx/RT3NKKhUQn+0nDcitV
# wqmgggH/MIIB+zCCAWSgAwIBAgIQK8KPnyZqh7ZLgu5QUg7L1TANBgkqhkiG9w0B
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
# BgkqhkiG9w0BCQQxFgQUv2Z8otKh5AVFNNitjroOntvw5xowDQYJKoZIhvcNAQEB
# BQAEgYAugBA0gVe7GQ4Xu35kFUDaa1f56yW9KOS2+XrreMGHFTfoDUcVTbUm/sXG
# RZqdsdO8x8+jPYjTU4QngFiWoBtC0fmAbbJNu9EQ+KVt9zXrnzsmbuIQEpWAYpvt
# N0hyG44jKs6AjLKLh1KQLRawiQ7AcEK9JUqqz+zTY/AWd/vgOw==
# SIG # End signature block
