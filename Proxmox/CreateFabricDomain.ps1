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


# Import my PVE modules
# ------------------------------------------------------------
Get-ChildItem -Path "D:\PVE Scripts\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


# Connect to PVE Cluster
# ------------------------------------------------------------
$PVEConnect = PVE-Connect -Authkey "root@pam!Powershell=16dcf2b5-1ca1-41cd-9e97-3c1d3d308ec0" -Hostaddr "10.36.1.27"


# Get the Deployment server info
# ------------------------------------------------------------
$MasterServer = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "LAB-Deploy"


# Get information required to create the template (VM)
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -IncludeNode $MasterServer.Node


& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "ADDS-01.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.11" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "ADDS-02.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.12" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "Deploy.Fabric.SecInfra.Dk"  -NewVmIp "10.36.100.19" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=DeployentServers,OU=Servers,OU=Tier0,OU=Admin" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "RDGW-01.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.21" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=RemoteDesktopGatewayServers,OU=Servers,OU=Tier1,OU=Admin" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "RDGW-02.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.22" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=RemoteDesktopGatewayServers,OU=Servers,OU=Tier1,OU=Admin" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "AMFA-01.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.23" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=RemoteDesktopMFAServers,OU=Servers,OU=Tier1,OU=Admin" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "AMFA-02.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.24" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=RemoteDesktopMFAServers,OU=Servers,OU=Tier1,OU=Admin" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "NPAS-01.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.25" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=RadiusServiceServers,OU=Servers,OU=Tier1,OU=Admin" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "NPAS-02.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.26" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=RadiusServiceServers,OU=Servers,OU=Tier1,OU=Admin" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "FILE-01.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.27" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=FileServers,OU=Servers,OU=Tier1,OU=Admin" -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "MGMT-01.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.31" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=JumpStations,OU=Tier0,OU=Admin" -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation -Verbose
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "MGMT-02.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.32" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=JumpStations,OU=Tier0,OU=Admin" -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation -Verbose
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "MGMT-11.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.33" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=JumpStations,OU=Tier1,OU=Admin" -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation -Verbose
& "D:\PVE Scripts\New-PVEServer.ps1" -NewVMFQDN "MGMT-12.Fabric.SecInfra.Dk" -NewVmIp "10.36.100.34" -LocalUsername "Administrator" -LocalPassword "P@ssword2025.!!" -MachineOU "OU=JumpStations,OU=Tier1,OU=Admin" -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation -Verbose


<#
Name,ComputerName,IPAddress,Deploy
AADC01,FAAADC01,172.16.0.52,TRUE
ADCA01,FAADCA01,172.16.0.20,TRUE

DEPL01,FADEPL01,172.16.0.26,TRUE ??

#>