# To prevent execution
# ------------------------------------------------------------
break

# You know why.
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force


# Configure Defaults.
# ------------------------------------------------------------
$ScriptPath = "D:\LAB Scripts"
$DefaultPassword = "Dharma05052023.!!"
$DefaultStorage = "VMData"
$DefaultSwitch = "vmbr10"
#$ServerProductKey = "xxxxx-xxxxx-xxxxx-xxxxx-xxxxx" # Server 2022
$ServerProductKey = "6BNHF-JJK28-KBQYX-324MR-Q9RHQ" # Server 2025
#$WorkstationProductKey = "xxxxx-xxxxx-xxxxx-xxxxx-xxxxx" # Windows 10
$WorkstationProductKey = "xxxxx-xxxxx-xxxxx-xxxxx-xxxxx" # Windows 11
$DomainName = "PROD.SecInfra.Dk"


# List of servers for the PROD Domain
# ------------------------------------------------------------
$ProdServerInfo = @(
    [PSCustomObject]@{ Name = "ADDS-01";     IpAddress = "10.36.8.11"; Role="DC"     } # Active Directory Domain Controller (FMSO)
    [PSCustomObject]@{ Name = "ADDS-02";     IpAddress = "10.36.8.12"; Role="DC"     } # Active Directory Domain Controller (DC)
    [PSCustomObject]@{ Name = "ADDS-03";     IpAddress = "10.36.8.13"; Role="DC"     } # Active Directory Domain Controller (DC)
    # 14, 15
#   [PSCustomObject]@{ Name = "CA-ROOT";     IpAddress = "127.0.0.1";  Role="CA"     } # Active Directory Certificate Authority (ROOT)
    [PSCustomObject]@{ Name = "ADCA-01";     IpAddress = "10.36.8.16"; Role="CA"     } # Active Directory Certificate Authority (Issuing / Standalone)
    [PSCustomObject]@{ Name = "ADCA-02";     IpAddress = "10.36.8.17"; Role="CA"     } # Active Directory Certificate Authority (Issuing)
    #18
    [PSCustomObject]@{ Name = "TASK-01";     IpAddress = "10.36.8.19"; Role="RPA"    } # Tier 0 Automation server (Scheduled Tasks)
    #20
    [PSCustomObject]@{ Name = "AADC-01";     IpAddress = "10.36.8.21"; Role="AADC"   } # Azure Active Directory (AD) Connect / Microsoft Entra Connect Sync
    [PSCustomObject]@{ Name = "AADC-02";     IpAddress = "10.36.8.22"; Role="AADC"   } # Azure Active Directory (AD) Connect / Microsoft Entra Connect Sync
    [PSCustomObject]@{ Name = "MECS-01";     IpAddress = "10.36.8.23"; Role="AADC"   } # Entra ID Connect / Azure Active Directory Connect (Active)
    [PSCustomObject]@{ Name = "MECS-02";     IpAddress = "10.36.8.24"; Role="AADC"   } # Entra ID Connect / Azure Active Directory Connect (Staging)
    [PSCustomObject]@{ Name = "MEPS-01";     IpAddress = "10.36.8.25"; Role="AADP"   } # Tier 0 Entra ID Provisioning service
    [PSCustomObject]@{ Name = "MEPS-02";     IpAddress = "10.36.8.26"; Role="AADP"   } # Tier 0 Entra ID Provisioning service
    #27..30
    [PSCustomObject]@{ Name = "MGMT-01";     IpAddress = "10.36.8.31"; Role="MGMT"   } # Management Server Tier 0
    [PSCustomObject]@{ Name = "MGMT-02";     IpAddress = "10.36.8.32"; Role="MGMT"   } # Management Server Tier 0
    [PSCustomObject]@{ Name = "MGMT-11";     IpAddress = "10.36.8.33"; Role="MGMT"   } # Management Server Tier 1
    [PSCustomObject]@{ Name = "MGMT-12";     IpAddress = "10.36.8.34"; Role="MGMT"   } # Management Server Tier 1
    [PSCustomObject]@{ Name = "MGMT-11L";    IpAddress = "10.36.8.35"; Role="MGMT"   } # Management Server Tier 1 Limited
    [PSCustomObject]@{ Name = "MGMT-12L";    IpAddress = "10.36.8.36"; Role="MGMT"   } # Management Server Tier 1 Limited
    [PSCustomObject]@{ Name = "MGMT-21";     IpAddress = "10.36.8.37"; Role="MGMT"   } # Management Server Tier 2
    [PSCustomObject]@{ Name = "MGMT-22";     IpAddress = "10.36.8.38"; Role="MGMT"   } # Management Server Tier 2
    [PSCustomObject]@{ Name = "MGMT-21L";    IpAddress = "10.36.8.39"; Role="MGMT"   } # Management Server Tier 2 Limited
    [PSCustomObject]@{ Name = "MGMT-22L";    IpAddress = "10.36.8.40"; Role="MGMT"   } # Management Server Tier 2 Limited
    [PSCustomObject]@{ Name = "MGMT-91";     IpAddress = "10.36.8.41"; Role="MGMT"   } # Management Server Tier E
    [PSCustomObject]@{ Name = "MGMT-92";     IpAddress = "10.36.8.42"; Role="MGMT"   } # Management Server Tier E
    [PSCustomObject]@{ Name = "MGMT-91L";    IpAddress = "10.36.8.43"; Role="MGMT"   } # Management Server Tier E
    [PSCustomObject]@{ Name = "MGMT-92L";    IpAddress = "10.36.8.44"; Role="MGMT"   } # Management Server Tier E
    #45, 46
    [PSCustomObject]@{ Name = "WACS-01";     IpAddress = "10.36.8.47"; Role="MGMT"   } # Windows Admin Center (Active)
    [PSCustomObject]@{ Name = "WACS-02";     IpAddress = "10.36.8.48"; Role="MGMT"   } # Windows Admin Center (Passive)
    #49
    [PSCustomObject]@{ Name = "Tx-RDGW";     IpAddress = "10.36.8.50"; Role="HA"     } # Remote Desktop Gateway Cluster name Tier x (Shared)
    [PSCustomObject]@{ Name = "RDGW-01";     IpAddress = "10.36.8.51"; Role="RDGW"   } # Remote Desktop Gateway server Tier x (Shared/Split)
    [PSCustomObject]@{ Name = "RDGW-02";     IpAddress = "10.36.8.52"; Role="RDGW"   } # Remote Desktop Gateway server Tier x (Shared/Split)
    [PSCustomObject]@{ Name = "AMFA-01";     IpAddress = "10.36.8.53"; Role="MFA"    } # Azure Multifactor Authentication (Radius)
    [PSCustomObject]@{ Name = "AMFA-02";     IpAddress = "10.36.8.54"; Role="MFA"    } # Azure Multifactor Authentication (Radius)
    [PSCustomObject]@{ Name = "RDDB-CLU";    IpAddress = "10.36.8.55"; Role="CLU"    } # Remote Desktop Connection Broker Database Server (Cluster Address)
    [PSCustomObject]@{ Name = "RDDB-AG";     IpAddress = "10.36.8.56"; Role="CLU"    } # Remote Desktop Connection Broker Database Server (MSSQL Avalibility Group)
    #57
    [PSCustomObject]@{ Name = "RDDB-01";     IpAddress = "10.36.8.58"; Role="RDDB"   } # Remote Desktop Connection Broker Database Server (MSSQL, Always On)
    [PSCustomObject]@{ Name = "RDDB-02";     IpAddress = "10.36.8.59"; Role="RDDB"   } # Remote Desktop Connection Broker Database Server (MSSQL, Always On)
    [PSCustomObject]@{ Name = "RDCB";        IpAddress = "10.36.8.60"; Role="CLU"    } # Remote Desktop Connection Broker Server (Cluster Address)
    [PSCustomObject]@{ Name = "RDCB-01";     IpAddress = "10.36.8.61"; Role="RDCB"   } # Remote Desktop Connection Broker Server
    [PSCustomObject]@{ Name = "RDCB-02";     IpAddress = "10.36.8.62"; Role="RDCB"   } # Remote Desktop Connection Broker Server
    [PSCustomObject]@{ Name = "RDLI-01";     IpAddress = "10.36.8.65"; Role="RDLI"   } # Remote Desktop Licensing server
    [PSCustomObject]@{ Name = "RDLI-02";     IpAddress = "10.36.8.66"; Role="RDLI"   } # Remote Desktop Licensing server
    #67..69
    [PSCustomObject]@{ Name = "TE-RRAS";     IpAddress = "10.36.8.70"; Role="HA"     } # Routing and Remote Access (Cluster Address)
    [PSCustomObject]@{ Name = "RRAS-01";     IpAddress = "10.36.8.71"; Role="RAS"    } # Routing and Remote Access for AOVPN
    [PSCustomObject]@{ Name = "RRAS-02";     IpAddress = "10.36.8.72"; Role="RAS"    } # Routing and Remote Access for AOVPN
    [PSCustomObject]@{ Name = "NPAS-01";     IpAddress = "10.36.8.73"; Role="NPS"    } # Radius server for AOVPN
    [PSCustomObject]@{ Name = "NPAS-02";     IpAddress = "10.36.8.74"; Role="NPS"    } # Radius server for AOVPN 
    #75, 76
    [PSCustomObject]@{ Name = "DFSN-01";     IpAddress = "10.36.8.77"; Role="DFS"    } # Distributed File System Namespace Server
    [PSCustomObject]@{ Name = "FILE-01";     IpAddress = "10.36.8.78"; Role="FILE"   } # File and Storage Server (Active DFS-R)
    [PSCustomObject]@{ Name = "FILE-02";     IpAddress = "10.36.8.79"; Role="FILE"   } # File and Storage Server (Passive DFS-R)
    [PSCustomObject]@{ Name = "WEB";         IpAddress = "10.36.8.80"; Role="HA"     } # Windows Internet Information Services (Cluster Address)
    [PSCustomObject]@{ Name = "WEB-01";      IpAddress = "10.36.8.81"; Role="WEB"    } # Windows Internet Information Services (CRL, PingCastle) (Active)
    [PSCustomObject]@{ Name = "WEB-02";      IpAddress = "10.36.8.82"; Role="WEB"    } # Windows Internet Information Services (CRL, PingCastle) (Passive)
    #83
    [PSCustomObject]@{ Name = "MPNC-01";     IpAddress = "10.36.8.84"; Role="AAGW"   } # Microsoft Entra Private Network Connector (Application Gateway)
    [PSCustomObject]@{ Name = "MPNC-02";     IpAddress = "10.36.8.85"; Role="AAGW"   } # Microsoft Entra Private Network Connector (Application Gateway)
    [PSCustomObject]@{ Name = "MPNC-03";     IpAddress = "10.36.8.86"; Role="AAGW"   } # Microsoft Entra Private Network Connector (Application Gateway)
    #87..100    
    [PSCustomObject]@{ Name = "DHCP-01";     IpAddress = "10.36.8.101"; Role="DHCP"  } # Dynamic Host Configuration Protocol Server (Active)
    [PSCustomObject]@{ Name = "DHCP-02";     IpAddress = "10.36.8.102"; Role="DHCP"  } # Dynamic Host Configuration Protocol Server (Passive)
    #103..110
    [PSCustomObject]@{ Name = "PAW-01";      IpAddress = "10.36.8.111"; Role="PAW"   } # Tier0 PAW
    [PSCustomObject]@{ Name = "PAW-11";      IpAddress = "10.36.8.112"; Role="PAW"   } # Tier1 PAW
    [PSCustomObject]@{ Name = "PAW-21";      IpAddress = "10.36.8.113"; Role="PAW"   } # Tier2 PAW
)


# Create PDC first, and get the Domain UP
# ------------------------------------------------------------
& "$ScriptPath\Proxmox-New-Server.ps1" -NewVMFQDN "ADDS-01.$DomainName" -NewVmIp "10.36.10.11" -LocalAdminPassword $DefaultPassword -VMMemory 8 -VMCores 4 -OSDisk 50Gb -DefaultStorage $DefaultStorage -DefaultSwitch $DefaultSwitch -ProductKey $ServerProductKey -Start -verbose


# Create all other Servers.
# ------------------------------------------------------------
$ProdServerInfo | Where {$_.Name -ne "ADDS-01" -and $_.role -ne "HA"} | foreach {
    $_.Name
    & "$ScriptPath\Proxmox-New-Server.ps1" -NewVMFQDN "$($_.Name).$DomainName" -NewVmIp $($_.IpAddress) -LocalAdminPassword $DefaultPassword -VMMemory 4 -VMCores 4 -OSDisk 50Gb -DefaultStorage $DefaultStorage -DefaultSwitch $DefaultSwitch -ProductKey $ServerProductKey -verbose
}


# Create the PAWs if needed....
# ------------------------------------------------------------
Break
$ProdServerInfo | where {$_.Role -eq "PAW"} | foreach {
    $_.Name
    & "$ScriptPath\Proxmox-New-Client.ps1" -NewVMFQDN "$($_.Name).$DomainName" -NewVmIp $($_.IpAddress) -LocalAdminPassword $DefaultPassword -VMMemory 4 -VMCores 4 -OSDisk 50Gb -DefaultStorage $DefaultStorage -DefaultSwitch $DefaultSwitch -ProductKey $WorkstationProductKey -verbose
}
