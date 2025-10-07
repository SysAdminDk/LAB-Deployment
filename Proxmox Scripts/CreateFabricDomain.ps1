<#

    Create required servers for the FABRIC Domain.

    2 x Domain Controllers
    2 x Radius Servers (MFA)
    2 x Remote Desktop Gateways
    2 x Entra Application Proxy / App Gateway
    2 x T0 Management server

    Optional
    2 x Radius Servers (NPS)


#>

# Do Not Just Execute.
# ------------------------------------------------------------
break


# Path to PVE scripts and Functions.
# ------------------------------------------------------------
$RootPath = "D:\PVE Scripts"


# List of VMs to create.
# ------------------------------------------------------------
$VMConfig = @(
    [PSCustomObject]@{ VMName = "ADDS-01";  IPAddress = "10.36.200.11"; VMCores=2;  VMMemory=4; OSDisk=50; } # Active Directory
    [PSCustomObject]@{ VMName = "ADDS-02";  IPAddress = "10.36.200.12"; VMCores=2;  VMMemory=4; OSDisk=50; } # Active Directory
    [PSCustomObject]@{ VMName = "MGMT-01";  IPAddress = "10.36.200.23"; VMCores=2;  VMMemory=4; OSDisk=50; } # T0 Management server / Jumpstation
    [PSCustomObject]@{ VMName = "MGMT-02";  IPAddress = "10.36.200.24"; VMCores=2;  VMMemory=4; OSDisk=50; } # T0 Management server / Jumpstation
    [PSCustomObject]@{ VMName = "RDGW-01";  IPAddress = "10.36.200.31"; VMCores=2;  VMMemory=4; OSDisk=50; } # Remote Desktop Gateway
    [PSCustomObject]@{ VMName = "RDGW-02";  IPAddress = "10.36.200.32"; VMCores=2;  VMMemory=4; OSDisk=50; } # Remote Desktop Gateway
    [PSCustomObject]@{ VMName = "AMFA-01";  IPAddress = "10.36.200.33"; VMCores=2;  VMMemory=4; OSDisk=50; } # Remote Desktop NPS MFA.
    [PSCustomObject]@{ VMName = "AMFA-02";  IPAddress = "10.36.200.34"; VMCores=2;  VMMemory=4; OSDisk=50; } # Remote Desktop NPS MFA.
    [PSCustomObject]@{ VMName = "NPAS-01";  IPAddress = "10.36.100.46"; VMCores=2;  VMMemory=4; OSDisk=50; } # Radius auth
    [PSCustomObject]@{ VMName = "NPAS-02";  IPAddress = "10.36.100.47"; VMCores=2;  VMMemory=4; OSDisk=50; } # Radius auth
    [PSCustomObject]@{ VMName = "FILE-01";  IPAddress = "10.36.100.52"; VMCores=2;  VMMemory=4; OSDisk=50; } # File Service
)


# Import PVE modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false
Get-ChildItem -Path "$RootPath\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


# Connect to PVE Cluster
# ------------------------------------------------------------
$PVESecret = Get-Content "$RootPath\PVE-Secret.json" | Convertfrom-Json
$PVEConnect = PVE-Connect -Authkey "$($PVESecret.User)!$($PVESecret.TokenID)=$($PVESecret.Token)" -Hostaddr $($PVESecret.Host)


# Get the Deployment server info
# ------------------------------------------------------------
$MasterServer = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "LAB-Deploy"


# Get information required to create the template (VM)
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -IncludeNode $MasterServer.Node


# Create the servers listed.
# ------------------------------------------------------------
$VMConfig | ForEach-Object {
    Write-Host "Create Server : $($_.VMName).$DefaultDomain"
    & "$RootPath\New-PVEServer.ps1" -NewVMFQDN "$($_.VMName).$DefaultDomain" `
                                    -NewVmIp $_.IPAddress `
                                    -LocalUsername $DefaultUser `
                                    -LocalPassword $DefaultPass `
                                    -VMMemory $_.VMMemory `
                                    -VMCores $_.VMCores `
                                    -OSDisk $_.OSDisk `
                                    -DefaultConnection $PVEConnect `
                                    -DefaultLocation $PVELocation
}
