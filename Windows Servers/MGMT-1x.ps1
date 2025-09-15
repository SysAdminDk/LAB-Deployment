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

    Install & Configure Tier 1 Management Servers

#>

if ((gwmi win32_computersystem).partofdomain) {

    # Selected RSAT tools
    # ------------------------------------------------------------
    $ToolsToInstall = @("RSAT-*","GPMC")
    Get-WindowsFeature -Name $ToolsToInstall | Where {$_.InstallState -eq "Available"} | Install-WindowsFeature -Verbose -ErrorAction SilentlyContinue


    $ServerQuery = Get-ADComputer -Identity $env:COMPUTERNAME
    $TierSearchBase = Get-ADOrganizationalUnit -Identity "OU=Admin,$((Get-ADDomain).DistinguishedName)"

    If ($($ServerQuery.DistinguishedName) -NotLike "*OU=JumpStations,OU=Tier1*") {
        Move-ADObject -Identity $($ServerQuery.DistinguishedName) -TargetPath $(Get-ADOrganizationalUnit -Filter "Name -eq 'JumpStations'" -SearchBase "OU=Tier1,$TierSearchBase").DistinguishedName
    }


    & Gpupdate /force


    # Reboot to activate all changes.
    # ------------------------------------------------------------
    & shutdown -r -t 10

}
