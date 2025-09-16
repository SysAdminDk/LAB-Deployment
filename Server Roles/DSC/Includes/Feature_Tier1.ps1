<#

    Featuers and Roles default on Tier1 Management Server / Jump Station

#>

function Feature_MGMT_Tier1 {
    # Ensure Feature Feature Administration Tools are installed
    WindowsFeature RSAT-Feature-Tools {
        Name   = "RSAT-Feature-Tools"
        Ensure = "Present"
    }

    # Ensure Feature BitLocker Drive Encryption Administration Utilities are installed
    WindowsFeature RSAT-Feature-Tools-BitLocker {
        Name   = "RSAT-Feature-Tools-BitLocker"
        Ensure = "Present"
    }

    # Ensure Feature BitLocker Drive Encryption Tools are installed
    WindowsFeature RSAT-Feature-Tools-BitLocker-RemoteAdminTool {
        Name   = "RSAT-Feature-Tools-BitLocker-RemoteAdminTool"
        Ensure = "Present"
    }

    # Ensure Feature BitLocker Recovery Password Viewer are installed
    WindowsFeature RSAT-Feature-Tools-BitLocker-BdeAducExt {
        Name   = "RSAT-Feature-Tools-BitLocker-BdeAducExt"
        Ensure = "Present"
    }

    # Ensure Feature BITS Server Extensions Tools are installed
    WindowsFeature RSAT-Bits-Server {
        Name   = "RSAT-Bits-Server"
        Ensure = "Present"
    }

    # Ensure Feature Failover Clustering Tools are installed
    WindowsFeature RSAT-Clustering {
        Name   = "RSAT-Clustering"
        Ensure = "Present"
    }

    # Ensure Feature Failover Cluster Management Tools are installed
    WindowsFeature RSAT-Clustering-Mgmt {
        Name   = "RSAT-Clustering-Mgmt"
        Ensure = "Present"
    }

    # Ensure Feature Failover Cluster Module for Windows PowerShell are installed
    WindowsFeature RSAT-Clustering-PowerShell {
        Name   = "RSAT-Clustering-PowerShell"
        Ensure = "Present"
    }

    # Ensure Feature Failover Cluster Automation Server are installed
    WindowsFeature RSAT-Clustering-AutomationServer {
        Name   = "RSAT-Clustering-AutomationServer"
        Ensure = "Present"
    }

    # Ensure Feature Failover Cluster Command Interface are installed
    WindowsFeature RSAT-Clustering-CmdInterface {
        Name   = "RSAT-Clustering-CmdInterface"
        Ensure = "Present"
    }

    # Ensure Feature Network Load Balancing Tools are installed
    WindowsFeature RSAT-NLB {
        Name   = "RSAT-NLB"
        Ensure = "Present"
    }

    # Ensure Feature SNMP Tools are installed
    WindowsFeature RSAT-SNMP {
        Name   = "RSAT-SNMP"
        Ensure = "Present"
    }

    # Ensure Feature Storage Replica Module for Windows PowerShell are installed
    WindowsFeature RSAT-Storage-Replica {
        Name   = "RSAT-Storage-Replica"
        Ensure = "Present"
    }

    # Ensure Feature System Insights Module for Windows PowerShell are installed
    WindowsFeature RSAT-System-Insights {
        Name   = "RSAT-System-Insights"
        Ensure = "Present"
    }

    # Ensure Feature Role Administration Tools are installed
    WindowsFeature RSAT-Role-Tools {
        Name   = "RSAT-Role-Tools"
        Ensure = "Present"
    }

    # Ensure Feature AD DS and AD LDS Tools are installed
    WindowsFeature RSAT-AD-Tools {
        Name   = "RSAT-AD-Tools"
        Ensure = "Present"
    }

    # Ensure Feature Active Directory module for Windows PowerShell are installed
    WindowsFeature RSAT-AD-PowerShell {
        Name   = "RSAT-AD-PowerShell"
        Ensure = "Present"
    }

    # Ensure Feature AD DS Tools are installed
    WindowsFeature RSAT-ADDS {
        Name   = "RSAT-ADDS"
        Ensure = "Present"
    }

    # Ensure Feature Active Directory Administrative Center are installed
    WindowsFeature RSAT-AD-AdminCenter {
        Name   = "RSAT-AD-AdminCenter"
        Ensure = "Present"
    }

    # Ensure Feature AD DS Snap-Ins and Command-Line Tools are installed
    WindowsFeature RSAT-ADDS-Tools {
        Name   = "RSAT-ADDS-Tools"
        Ensure = "Present"
    }

    # Ensure Feature AD LDS Snap-Ins and Command-Line Tools are installed
    WindowsFeature RSAT-ADLDS {
        Name   = "RSAT-ADLDS"
        Ensure = "Present"
    }

    # Ensure Feature Remote Desktop Services Tools are installed
    WindowsFeature RSAT-RDS-Tools {
        Name   = "RSAT-RDS-Tools"
        Ensure = "Present"
    }

    # Ensure Feature Remote Desktop Gateway Tools are installed
    WindowsFeature RSAT-RDS-Gateway {
        Name   = "RSAT-RDS-Gateway"
        Ensure = "Present"
    }

    # Ensure Feature Remote Desktop Licensing Diagnoser Tools are installed
    WindowsFeature RSAT-RDS-Licensing-Diagnosis-UI {
        Name   = "RSAT-RDS-Licensing-Diagnosis-UI"
        Ensure = "Present"
    }

    # Ensure Feature Active Directory Rights Management Services Tools are installed
    WindowsFeature RSAT-ADRMS {
        Name   = "RSAT-ADRMS"
        Ensure = "Present"
    }

    # Ensure Feature DHCP Server Tools are installed
    WindowsFeature RSAT-DHCP {
        Name   = "RSAT-DHCP"
        Ensure = "Present"
    }

    # Ensure Feature DNS Server Tools are installed
    WindowsFeature RSAT-DNS-Server {
        Name   = "RSAT-DNS-Server"
        Ensure = "Present"
    }

    # Ensure Feature File Services Tools are installed
    WindowsFeature RSAT-File-Services {
        Name   = "RSAT-File-Services"
        Ensure = "Present"
    }

    # Ensure Feature DFS Management Tools are installed
    WindowsFeature RSAT-DFS-Mgmt-Con {
        Name   = "RSAT-DFS-Mgmt-Con"
        Ensure = "Present"
    }

    # Ensure Feature File Server Resource Manager Tools are installed
    WindowsFeature RSAT-FSRM-Mgmt {
        Name   = "RSAT-FSRM-Mgmt"
        Ensure = "Present"
    }

    # Ensure Feature Services for Network File System Management Tools are installed
    WindowsFeature RSAT-NFS-Admin {
        Name   = "RSAT-NFS-Admin"
        Ensure = "Present"
    }

    # Ensure Feature Network Controller Management Tools are installed
    WindowsFeature RSAT-NetworkController {
        Name   = "RSAT-NetworkController"
        Ensure = "Present"
    }

    # Ensure Feature Network Policy and Access Services Tools are installed
    WindowsFeature RSAT-NPAS {
        Name   = "RSAT-NPAS"
        Ensure = "Present"
    }

    # Ensure Feature Print and Document Services Tools are installed
    WindowsFeature RSAT-Print-Services {
        Name   = "RSAT-Print-Services"
        Ensure = "Present"
    }

    # Ensure Feature Remote Access Management Tools are installed
    WindowsFeature RSAT-RemoteAccess {
        Name   = "RSAT-RemoteAccess"
        Ensure = "Present"
    }

    # Ensure Feature Remote Access GUI and Command-Line Tools are installed
    WindowsFeature RSAT-RemoteAccess-Mgmt {
        Name   = "RSAT-RemoteAccess-Mgmt"
        Ensure = "Present"
    }

    # Ensure Feature Remote Access module for Windows PowerShell are installed
    WindowsFeature RSAT-RemoteAccess-PowerShell {
        Name   = "RSAT-RemoteAccess-PowerShell"
        Ensure = "Present"
    }

}