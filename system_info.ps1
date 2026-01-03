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

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

function Get-OsSoftwareInfo {
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
          LinkSpeed            = "$($_.LinkSpeed)"
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

function Write-Section([string]$Title) {
  Write-Host ""
  Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Pause-BeforeSave {
  Write-Host ""
  Write-Host "Review the info above." -ForegroundColor Yellow
  Write-Host "Press any key to save JSON to: $OutFile" -ForegroundColor Yellow

  try {
    if ($Host.UI -and $Host.UI.RawUI) {
      $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
      return
    }
  } catch {
    # fall back below
  }

  # Fallback for hosts without RawUI support.
  $null = Read-Host "Press ENTER to save"
}

function Write-PagedTable {
  param(
    [Parameter(Mandatory = $true)]
    $InputObject,

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
Write-Host "Generated: $($report.Meta.Timestamp)" -ForegroundColor DarkGray
Write-Host "Elevated:  $($report.Meta.Elevated)" -ForegroundColor DarkGray

Write-Section "Software"
$report.Software | Format-List | Out-String | Write-Host

Write-Section "Hardware"
$report.Hardware.CPU | Format-List | Out-String | Write-Host
$report.Hardware.BIOS | Format-List | Out-String | Write-Host
$report.Hardware.Memory | Select-Object TotalGB | Format-List | Out-String | Write-Host
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
    $resolvedOutFile = [System.IO.Path]::GetFullPath($OutFile)
  } catch {
    $resolvedOutFile = $OutFile
  }
}

try {
  $json | Out-File -FilePath $resolvedOutFile -Encoding utf8 -Force
  Write-Host "Saved: $resolvedOutFile" -ForegroundColor Green
} catch {
  Write-Host "Failed to save: $resolvedOutFile" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
}
