<#
.SYNOPSIS
    Switch an Ethernet adapter between DHCP and a static IPv4 address.

.DESCRIPTION
    This script configures the specified network adapter either to use DHCP
    for IPv4 or to apply a static IPv4 configuration (IP, prefix length, gateway, DNS).

.PARAMETER InterfaceName
    Name of the network adapter (e.g. "Ethernet").

.PARAMETER Mode
    "dhcp" or "static". When "dhcp" is chosen, both IP and DNS are set to DHCP.

.PARAMETER IPAddress
    IPv4 address for static mode.

.PARAMETER PrefixLength
    Prefix length (netmask) for static mode, e.g. 24.

.PARAMETER Gateway
    Default gateway (optional).

.PARAMETER Dns
    DNS servers as a comma-separated list (e.g. "8.8.8.8,1.1.1.1"). Optional in static mode.

.PARAMETER Force
    Disables interactive confirmations (SwitchParameter).

.EXAMPLE
    .\Set-EthernetMode.ps1 -InterfaceName "Ethernet" -Mode static -IPAddress 192.168.1.50 -PrefixLength 24 -Gateway 192.168.1.1 -Dns "8.8.8.8,1.1.1.1"

    Sets the static IP 192.168.1.50/24 with gateway and two DNS servers.

.EXAMPLE
    .\Set-EthernetMode.ps1 -InterfaceName "Ethernet" -Mode dhcp

    Switches the adapter to DHCP (IPv4 and DNS).

#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$InterfaceName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("dhcp","static","show")] 
    [string]$Mode,
    
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$')]
    [string]$IPAddress,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,32)]
    [int]$PrefixLength,
    
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$')]
    [string]$Gateway,
    
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$|^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3},(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$')]
    [string]$DNS,
    
    [switch]$Force
    )
    
function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Error "This script requires Administrator privileges. Start PowerShell as Administrator and try again."
        exit 1
    }
}

function Get-Interface {
    param($name)
    $if = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
    if (-not $if) {
        Write-Error "Network adapter '$name' was not found. Available adapters:"
        Get-NetAdapter | Select-Object -Property Name, Status
        exit 2
    }
    return $if
}

function Set-DhcpMode {
[CmdletBinding(SupportsShouldProcess=$true)]
param($ifName)
if ($PSCmdlet.ShouldProcess("Adapter: $ifName","Aktiviere DHCP (IPv4 + DNS)")) {
    Write-Verbose "Setting IPv4 to DHCP..."
    # Remove existing IPv4 addresses
    $existing = Get-NetIPConfiguration -InterfaceAlias $ifName -ErrorAction SilentlyContinue
    foreach ($cfg in $existing) {
        foreach ($addr in $cfg.IPv4Address) {
            if ($addr.IPAddress) {
                Remove-NetIPAddress -InterfaceAlias $ifName -IPAddress $addr.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        if ($null -ne $cfg.IPv4DefaultGateway -and $cfg.IPv4DefaultGateway.NextHop) {
            Remove-NetRoute -InterfaceAlias $ifName -NextHop $cfg.IPv4DefaultGateway.NextHop -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}
    Try {
        Set-NetIPInterface -InterfaceAlias $ifName -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
    } Catch {
        # Some systems don't allow Set-NetIPInterface -Dhcp; fallback to Remove and Enable
        Write-Verbose "Set-NetIPInterface failed: $_. Trying alternative using Remove-NetIPAddress and netsh to enable DHCP." 
        Get-NetIPAddress -InterfaceAlias $ifName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        # Enable DHCP for IPv4 - use Netsh as a fallback
        netsh interface ip set address name="$ifName" source=dhcp | Out-Null
    }
    
    Write-Verbose "Setting DNS to DHCP..."
    Try {
        Set-DnsClientServerAddress -InterfaceAlias $ifName -ResetServerAddresses -ErrorAction Stop
    } Catch {
        # fallback to netsh
        netsh interface ip set dns name="$ifName" source=dhcp | Out-Null
    }
    
    Write-Output "Adapter '$ifName' is now configured for DHCP."
}

function Set-StaticMode {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param($ifName, $ip, $prefix, $gateway, $DNS)
    if (-not $ip -or -not $prefix) {
        Write-Error "-IPAddress and -PrefixLength must be provided for static mode."
        exit 3
    }

    if ($PSCmdlet.ShouldProcess("Adapter: $ifName","Setze statische IPv4: $ip/$prefix")) {
        Write-Verbose "Setting static IPv4..."
        # Remove existing IPv4 addresses
        $existing = Get-NetIPConfiguration -InterfaceAlias $ifName -ErrorAction SilentlyContinue
        foreach ($cfg in $existing) {
            foreach ($addr in $cfg.IPv4Address) {
                if ($addr.IPAddress) {
                    Remove-NetIPAddress -InterfaceAlias $ifName -IPAddress $addr.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
            if ($null -ne $cfg.IPv4DefaultGateway -and $cfg.IPv4DefaultGateway.NextHop) {
                Remove-NetRoute -InterfaceAlias $ifName -NextHop $cfg.IPv4DefaultGateway.NextHop -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        # Add new IP
        New-NetIPAddress -InterfaceAlias $ifName -IPAddress $ip -PrefixLength $prefix -ErrorAction Stop

        # Add default gateway if provided
        if ($gateway) {
            New-NetRoute -InterfaceAlias $ifName -DestinationPrefix '0.0.0.0/0' -NextHop $gateway -ErrorAction Stop
        }

        # Set DNS if provided
        if ($DNS) {
            $arr = $DNS -split '\s*,\s*' | Where-Object { $_ -ne '' }
            if ($arr.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceAlias $ifName -ServerAddresses $arr -ErrorAction Stop
            }
        }

        Write-Output "Adapter '$ifName' configured with static IP $ip/$prefix."
    }
}

function Test-NetworkConfig {
    [CmdletBinding()]
    param($ifName)

    $result = @{
        Adapter = $null
        IPv4 = $null
        Gateway = $null
        DNS = $null
        DHCPEnabled = $false
        Success = $false
    }

    try {
        $config = Get-NetIPConfiguration -InterfaceAlias $ifName -ErrorAction Stop
        #$result.Adapter = Get-NetAdapter -Name $ifName -ErrorAction Stop
        $result.Adapter = $config.InterfaceDescription
        $result.IPv4 = $config.IPv4Address.IPAddress
        $result.Gateway = $config.IPv4DefaultGateway.NextHop
        $result.DNS = (Get-DnsClientServerAddress -InterfaceAlias $ifName -ErrorAction Stop | 
                      Where-Object {$_.AddressFamily -eq 2}).ServerAddresses
        $result.DHCPEnabled = (Get-NetIPInterface -InterfaceAlias $ifName -AddressFamily IPv4).Dhcp -eq 'Enabled'
        $result.Success = $true
    } catch {
        Write-Warning "Fehler beim Testen der Netzwerkkonfiguration: $_"
    }

    return [PSCustomObject]$result
}

# Main
Assert-Admin

if ($Mode -eq 'dhcp') {
    if (-not $Force) {
        $confirm = Read-Host "Set adapter '$InterfaceName' to DHCP? (y/n)"
        if ($confirm -notin 'y','Y','j','J') { Write-Output "Cancelled."; exit 0 }
    }
    Set-DhcpMode -ifName $InterfaceName
} elseif ($Mode -eq 'static') {
    if (-not $Force) {
        $confirm = Read-Host "Set adapter '$InterfaceName' to static IP? (y/n)"
        if ($confirm -notin 'y','Y','j','J') { Write-Output "Cancelled."; exit 0 }
    }
    Set-StaticMode -ifName $InterfaceName -ip $IPAddress -prefix $PrefixLength -gateway $Gateway -DNS $DNS
} else {
    $test = Test-NetworkConfig -ifName $InterfaceName
    $test | Format-List
}
