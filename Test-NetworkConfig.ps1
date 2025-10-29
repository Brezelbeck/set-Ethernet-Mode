# Test der Netzwerkkonfiguration
param(
    [Parameter(Mandatory=$true)]
    [string]$InterfaceAlias)

function Test-NetworkConfig {
    [CmdletBinding()]
    $result = @{
        Adapter = $null
        IPv4 = $null
        Gateway = $null
        DNS = $null
        DHCPEnabled = $false
        Success = $false
    }

    try {
        $result.Adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
        $config = Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias -ErrorAction Stop
        $result.IPv4 = $config.IPv4Address.IPAddress
        $result.Gateway = $config.IPv4DefaultGateway.NextHop
        $result.DNS = (Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ErrorAction Stop | 
                      Where-Object {$_.AddressFamily -eq 2}).ServerAddresses
        $result.DHCPEnabled = (Get-NetIPInterface -InterfaceAlias $InterfaceAlias -AddressFamily IPv4).Dhcp -eq 'Enabled'
        $result.Success = $true
    } catch {
        Write-Warning "Fehler beim Testen der Netzwerkkonfiguration: $_"
    }

    return [PSCustomObject]$result
}

# Beispielaufruf:
$test = Test-NetworkConfig -InterfaceAlias $InterfaceAlias
$test | Format-List