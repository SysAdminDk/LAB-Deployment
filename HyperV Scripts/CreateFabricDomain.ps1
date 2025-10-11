<#

    Requires
    - HyperV Node(s) with Disk, CPU and memory to handle the amount of VMs
    - Create Master Deployment server using, Create-DeploymentServer.ps1
    - VM Template(s) have been created using New-PVEVMTemplate.ps1



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


# Defaults.
# ------------------------------------------------------------
$DefaultUser = "Administrator"
$DefaultPass = "P@ssword2025.!!"
$DefaultDomain = "Fabric.SecInfra.Dk"


# List of VMs to create.
# ------------------------------------------------------------
$VMConfig = @(
    [PSCustomObject]@{ VMName = "ADDS-01";  IPAddress = "10.36.200.11"; VMCores=2;  VMMemory=4; OSDisk=50; } # Active Directory
    [PSCustomObject]@{ VMName = "ADDS-02";  IPAddress = "10.36.200.12"; VMCores=2;  VMMemory=4; OSDisk=50; } # Active Directory
    [PSCustomObject]@{ VMName = "MGMT-01";  IPAddress = "10.36.200.23"; VMCores=4;  VMMemory=8; OSDisk=50; } # T0 Management server / Jumpstation
    [PSCustomObject]@{ VMName = "MGMT-02";  IPAddress = "10.36.200.24"; VMCores=4;  VMMemory=8; OSDisk=50; } # T0 Management server / Jumpstation
    [PSCustomObject]@{ VMName = "RDGW-01";  IPAddress = "10.36.200.31"; VMCores=2;  VMMemory=4; OSDisk=50; } # Remote Desktop Gateway
    [PSCustomObject]@{ VMName = "RDGW-02";  IPAddress = "10.36.200.32"; VMCores=2;  VMMemory=4; OSDisk=50; } # Remote Desktop Gateway
    [PSCustomObject]@{ VMName = "AMFA-01";  IPAddress = "10.36.200.33"; VMCores=2;  VMMemory=4; OSDisk=50; } # Remote Desktop NPS MFA.
    [PSCustomObject]@{ VMName = "AMFA-02";  IPAddress = "10.36.200.34"; VMCores=2;  VMMemory=4; OSDisk=50; } # Remote Desktop NPS MFA.
    [PSCustomObject]@{ VMName = "NPAS-01";  IPAddress = "10.36.100.46"; VMCores=2;  VMMemory=4; OSDisk=50; } # Radius auth
    [PSCustomObject]@{ VMName = "NPAS-02";  IPAddress = "10.36.100.47"; VMCores=2;  VMMemory=4; OSDisk=50; } # Radius auth
    [PSCustomObject]@{ VMName = "FILE-01";  IPAddress = "10.36.100.52"; VMCores=2;  VMMemory=4; OSDisk=50; } # File Service
)


# Create the servers listed.
# ------------------------------------------------------------
$VMConfig | ForEach-Object {
    Write-Host "Create Server : $($_.VMName).$DefaultDomain"






}
