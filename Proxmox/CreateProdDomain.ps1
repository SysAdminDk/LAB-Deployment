<#

    Create required servers for the PROD Domain.

    Tier 0 (10 Servers)
    3 x Active Directory Domain Controllers
    1 x Active Directory Certificate Authority
    2 x Entra Connect Sync
    2 x Entra Password Protection Proxy

    2 x Management server

    Tier 1 (24 Servers)
    2 x Remote Desktop Gateways
    2 x Radius Servers (MFA)
    2 x Entra Application Proxy / App Gateway

    2 x DHCP Servers
    2 x RRAS Servers (Always On VPN)
    2 x NPAS Servers (Always On VPN)

    2 x File Servers
    1 x DFS Server

    2 x Management server
    1 x Limited Management server

    2 x Remote Desktop Connection Broker Database Servers
    2 x Remote Desktop Connection Broker Servers
    2 x Remote Desktop Licensing Servers

    Optional Tier 2 (3 Servers)
    2 x Management server
    1 x Limited Management server


    Optional Tier Endpoint (9) (3 Servers)
    2 x Management server
    1 x Limited Management server

#>

# Do Not Just Execute.
# ------------------------------------------------------------
break


# Path to PVE scripts and Functions.
# ------------------------------------------------------------
$RootPath = "D:\PVE Scripts"


$DefaultUser = "Administrator"
$DefaultPass = "P@ssword2025.!!"


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
$MasterServer = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "Deploy"


# Get information required to create the template (VM)
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -IncludeNode $MasterServer.Node


.\New-PVEServer.ps1 -NewVMFQDN "ADDS-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.11" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "ADDS-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.12" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "ADDS-03.Prod.SecInfra.Dk" -NewVmIp "10.36.100.13" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

.\New-PVEServer.ps1 -NewVMFQDN "ADCA-03.Prod.SecInfra.Dk" -NewVmIp "10.36.100.16" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

.\New-PVEServer.ps1 -NewVMFQDN "AADC-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.18" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "AADC-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.19" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "AAPP-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.21" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "AAPP-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.22" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "MGMT-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.23" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "MGMT-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.24" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

.\New-PVEServer.ps1 -NewVMFQDN "RDGW-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.31" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RDGW-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.32" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "AMFA-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.33" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "AMFA-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.34" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "MEAP-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.35" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "MEAP-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.36" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RDDB-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.37" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RDDB-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.38" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RDCB-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.39" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RDCB-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.40" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RDLI-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.41" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RDLI-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.42" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

.\New-PVEServer.ps1 -NewVMFQDN "DHCP-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.44" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "DHCP-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.45" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "NPAS-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.46" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "NPAS-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.47" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RRAS-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.48" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "RRAS-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.49" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

.\New-PVEServer.ps1 -NewVMFQDN "DFSR-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.51" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "FILE-02.Prod.SecInfra.Dk" -NewVmIp "10.36.100.52" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "FILE-01.Prod.SecInfra.Dk" -NewVmIp "10.36.100.53" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

.\New-PVEServer.ps1 -NewVMFQDN "MGMT-11.Prod.SecInfra.Dk" -NewVmIp "10.36.100.55" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "MGMT-12.Prod.SecInfra.Dk" -NewVmIp "10.36.100.56" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "MGMT-19.Prod.SecInfra.Dk" -NewVmIp "10.36.100.57" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-21.Prod.SecInfra.Dk" -NewVmIp "10.36.100.63" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-22.Prod.SecInfra.Dk" -NewVmIp "10.36.100.64" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-29.Prod.SecInfra.Dk" -NewVmIp "10.36.100.65" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-91.Prod.SecInfra.Dk" -NewVmIp "10.36.100.67" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-92.Prod.SecInfra.Dk" -NewVmIp "10.36.100.68" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-99.Prod.SecInfra.Dk" -NewVmIp "10.36.100.69" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
