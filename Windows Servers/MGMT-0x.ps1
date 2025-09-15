<#
    ___  ___                                                  _     _____                              
    |  \/  |                                                 | |   /  ___|                             
    | .  . | __ _ _ __   __ _  __ _  ___ _ __ ___   ___ _ __ | |_  \ `--.  ___ _ ____   _____ _ __ ___ 
    | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '_ ` _ \ / _ \ '_ \| __|  `--. \/ _ \ '__\ \ / / _ \ '__/ __|
    | |  | | (_| | | | | (_| | (_| |  __/ | | | | |  __/ | | | |_  /\__/ /  __/ |   \ V /  __/ |  \__ \
    \_|  |_/\__,_|_| |_|\__,_|\__, |\___|_| |_| |_|\___|_| |_|\__| \____/ \___|_|    \_/ \___|_|  |___/
                               __/ |                                                                   
                              |___/                                                                    
#>

<#

    Install & Configure Tier 0 Management Servers

#>

if ((gwmi win32_computersystem).partofdomain) {

    # Add to Silo !!!
    # ------------------------------------------------------------
    #Set-TSxAdminADAuthenticationPolicySiloForComputer -ADComputerIdentity $($_.Name) -Tier T0


    # Selected RSAT tools
    # ------------------------------------------------------------
    $ToolsToInstall = @(
	    "RSAT-*",
        "GPMC"
	    )
    Get-WindowsFeature -Name $ToolsToInstall | Where {$_.InstallState -eq "Available"} | Install-WindowsFeature -Verbose -ErrorAction SilentlyContinue

    & Gpupdate /force
    & Gpupdate /force


    $ServerQuery = Get-ADComputer -Identity $env:COMPUTERNAME
    If ($($ServerQuery.DistinguishedName) -NotLike "*OU=JumpStations,OU=Tier0*") {
        Move-ADObject -Identity $($_.DistinguishedName) -TargetPath $(Get-ADOrganizationalUnit -Filter "Name -eq 'JumpStations'" -SearchBase "OU=Tier0,$TierSearchBase").DistinguishedName
    }


    # Install RDM
    # ------------------------------------------------------------
    #Start-Process -FilePath "$($ENV:PUBLIC)\downloads\windowsdesktop-runtime-8.0.6-win-x64.exe" -ArgumentList "/quiet /qn /norestart" -wait
    #Start-Process -FilePath "$($ENV:PUBLIC)\downloads\Setup.RemoteDesktopManager.exe" -ArgumentList "/quiet /qn /norestart" -wait


    # Reboot to activate all changes.
    # ------------------------------------------------------------
    & shutdown -r -t 10

}
