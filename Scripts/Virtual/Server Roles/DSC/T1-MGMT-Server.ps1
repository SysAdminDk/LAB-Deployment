<#

    Default Configuration used on Tier1 Management Server / Jump Station

#>

Configuration MGMTServer {
    param (
        [string[]]$NodeName = "localhost"
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $NodeName {

        Feature_MGMT_Tier1

        # Install RDSH
        WindowsFeature RDSH {
            Name   = "RDS-RD-Server"
            Ensure = "Present"
        }

        Feature_Chocolatey

        Choco_RemoteDesktopManager

    }
}
