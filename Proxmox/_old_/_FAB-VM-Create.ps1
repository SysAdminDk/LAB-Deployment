# To prevent execution
# ------------------------------------------------------------
break

# You know why.
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force


# Configure Defaults.
# ------------------------------------------------------------
$ScriptPath = "D:\Scripts"
$DefaultPassword = "Dharma05052023.!!"
$DefaultStorage = "VMData"
$DefaultSwitch = "vmbr10"
#$ProductKey = "xxxxx-xxxxx-xxxxx-xxxxx-xxxxx" # Server 2022
$ProductKey = "6BNHF-JJK28-KBQYX-324MR-Q9RHQ" # Server 2025
$DomainName = "FAB.SecInfra.Dk"


# List of servers for the FAB Domain
# ------------------------------------------------------------
$FabServerInfo = @(
    [PSCustomObject]@{ Name = "ADDS-01";     IpAddress = "10.36.10.11"; Role="DC"     } # Active Directory Domain Controller (FMSO)
    [PSCustomObject]@{ Name = "ADDS-02";     IpAddress = "10.36.10.12"; Role="DC"     } # Active Directory Domain Controller (DC)
    [PSCustomObject]@{ Name = "ADDS-03";     IpAddress = "10.36.10.13"; Role="DC"     } # Active Directory Domain Controller (DC)

    [PSCustomObject]@{ Name = "ADCA-01";     IpAddress = "10.36.10.16"; Role="CA"     } # Active Directory Certificate Authority (Issuing / Standalone)
    [PSCustomObject]@{ Name = "AACS-01";     IpAddress = "10.36.10.18"; Role="CS"     } # Active Directory Cloud Sync / Entra ID Cloud Sync

    [PSCustomObject]@{ Name = "TASK-01";     IpAddress = "10.36.10.19"; Role="RPA"    } # Tier 0 Automation server (Scheduled Tasks)

    [PSCustomObject]@{ Name = "MGMT-01";     IpAddress = "10.36.10.21"; Role="MGMT"   } # Management Server Tier 0
    [PSCustomObject]@{ Name = "MGMT-02";     IpAddress = "10.36.10.22"; Role="MGMT"   } # Management Server Tier 0
    [PSCustomObject]@{ Name = "WACS-01";     IpAddress = "10.36.10.29"; Role="MGMT"   } # Windows Admin Center

    [PSCustomObject]@{ Name = "Tx-RDGW";     IpAddress = "10.36.10.41"; Role="HA"     } # Remote Desktop Gateway Cluster name Tier x (Shared)
    [PSCustomObject]@{ Name = "RDGW-01";     IpAddress = "10.36.10.42"; Role="RDGW"   } # Remote Desktop Gateway server Tier x (Shared)
    [PSCustomObject]@{ Name = "RDGW-02";     IpAddress = "10.36.10.43"; Role="RDGW"   } # Remote Desktop Gateway server Tier x (Shared)
    [PSCustomObject]@{ Name = "AMFA-01";     IpAddress = "10.36.10.47"; Role="MFA"    } # Azure Multifactor Authentication (Radius)
    [PSCustomObject]@{ Name = "AMFA-02";     IpAddress = "10.36.10.48"; Role="MFA"    } # Azure Multifactor Authentication (Radius)

    [PSCustomObject]@{ Name = "FILE-01";     IpAddress = "10.36.10.72"; Role="FILE"   } # File and Storage Server (Storage Replica / Active DFS-R)
    [PSCustomObject]@{ Name = "FILE-02";     IpAddress = "10.36.10.73"; Role="FILE"   } # File and Storage Server (Storage Replica / Passive DFS-R)

    [PSCustomObject]@{ Name = "AAGW-01";     IpAddress = "10.36.10.81"; Role="AAGW"   } # Entra Application Gateway
    [PSCustomObject]@{ Name = "AAGW-02";     IpAddress = "10.36.10.82"; Role="AAGW"   } # Entra Application Gateway

    [PSCustomObject]@{ Name = "NPAS-01";     IpAddress = "10.36.10.31"; Role="NPS"    } # Radius Server for network devices
    [PSCustomObject]@{ Name = "NPAS-02";     IpAddress = "10.36.10.32"; Role="NPS"    } # Radius Server for network devices
)

### OU=MGMT,OU=Servers,DC=lab,DC=local


# Create PDC first, and get the Domain UP
# ------------------------------------------------------------
& "$ScriptPath\Proxmox-New-Server.ps1" -NewVMFQDN "ADDS-01.$DomainName" -NewVmIp "10.36.10.11" -LocalAdminPassword $DefaultPassword -VMMemory 8 -VMCores 4 -OSDisk 50Gb -DefaultStorage $DefaultStorage -DefaultSwitch $DefaultSwitch -ProductKey $ProductKey -Start -verbose


# Create all other Servers.
# ------------------------------------------------------------
$FabServerInfo | Where {$_.Name -ne "ADDS-01" -and $_.Role -ne "HA"} | foreach {
    switch ($_.Role) {
        "DC"   { $OU = "" }
        "CA"   { $OU = "OU=CertificateAuthorityServers,OU=Servers,OU=Tier0,OU=Admin" }
        "CS"   { $OU = "OU=SyncServers,OU=Servers,OU=Tier0,OU=Admin" }
        "MGMT" { $OU = "OU=JumpStations,OU=Tier0,OU=Admin" }
        "RDGW" { $OU = "OU=RemoteDesktopBackendServers,OU=Servers,OU=Tier1,OU=Admin" }
        "MFA"  { $OU = "OU=RemoteDesktopBackendServers,OU=Servers,OU=Tier1,OU=Admin" }
        "FILE" { $OU = "OU=FileServers,OU=Servers,OU=Tier1,OU=Admin" }
        "AAGW" { $OU = "OU=AzureGatewayServers,OU=Servers,OU=Tier1,OU=Admin" }
        "NPS"  { $OU = "OU=NetworkPolicyServers,OU=Servers,OU=Tier1,OU=Admin" }
    }
    Write-Host "$($_.Name) - $OU"
    300
    & "$ScriptPath\Proxmox-New-Server.ps1" -NewVMFQDN "$($_.Name).$DomainName" -NewVmIp $($_.IpAddress) -LocalAdminPassword $DefaultPassword -VMMemory 4 -VMCores 4 -OSDisk 50Gb -DefaultStorage $DefaultStorage -DefaultSwitch $DefaultSwitch -ProductKey $ProductKey -MachineOU $OU -verbose
}
