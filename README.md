# Set-EthernetMode.ps1

Short script to switch a Windows Ethernet adapter between DHCP and a static IPv4 configuration.

Usage

- Enable DHCP:

  .\Set-EthernetMode.ps1 -InterfaceName "Ethernet" -Mode dhcp

- Set a static IP:

  .\Set-EthernetMode.ps1 -InterfaceName "Ethernet" -Mode static -IPAddress 192.168.1.50 -PrefixLength 24 -Gateway 192.168.1.1 -Dns "8.8.8.8,1.1.1.1"

- Show/Test config:

  .\Set-EthernetMode.ps1 -InterfaceName "Ethernet" -Mode show

Notes

- The script must be run with Administrator privileges.
- Use `-Force` to suppress interactive confirmations.
- The script only modifies IPv4 settings.

Troubleshooting

- Adapter not found: run `Get-NetAdapter` to find the correct adapter name.
- Restore DHCP manually using:

  netsh interface ip set address name="Ethernet" source=dhcp
  netsh interface ip set dns name="Ethernet" source=dhcp

License

- Public domain / freely usable.