<#

    Featuers and Roles default on Tier0 Management Server / Jump Station

#>

function Feature_MGMT_Tier0 {

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

    # Ensure Feature Active Directory Certificate Services Tools are installed
    WindowsFeature RSAT-ADCS {
        Name   = "RSAT-ADCS"
        Ensure = "Present"
    }

    # Ensure Feature Certification Authority Management Tools are installed
    WindowsFeature RSAT-ADCS-Mgmt {
        Name   = "RSAT-ADCS-Mgmt"
        Ensure = "Present"
    }

    # Ensure Feature Online Responder Tools are installed
    WindowsFeature RSAT-Online-Responder {
        Name   = "RSAT-Online-Responder"
        Ensure = "Present"
    }

    # Ensure Feature Active Directory Rights Management Services Tools are installed
    WindowsFeature RSAT-ADRMS {
        Name   = "RSAT-ADRMS"
        Ensure = "Present"
    }

    # Ensure Feature DNS Server Tools are installed
    WindowsFeature RSAT-DNS-Server {
        Name   = "RSAT-DNS-Server"
        Ensure = "Present"
    }

    # Ensure Feature DFS Management Tools are installed
    WindowsFeature RSAT-DFS-Mgmt-Con {
        Name   = "RSAT-DFS-Mgmt-Con"
        Ensure = "Present"
    }

    # Ensure Feature Volume Activation Tools are installed
    WindowsFeature RSAT-VA-Tools {
        Name   = "RSAT-VA-Tools"
        Ensure = "Present"
    }

}