<#

    Default Configuration used on Tier0 Management Server / Jump Station

#>

Configuration Feature_MGMT_Tier0 {
    param (
        [string[]]$NodeName = "localhost"
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $NodeName {

        Feature_MGMT_T0

        # Install RDSH
        WindowsFeature RDSH {
            Name   = "RDS-RD-Server"
            Ensure = "Present"
        }

        Feature_Chocolatey

        Choco_RemoteDesktopManager

    }
}
