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

    Install & Configure Tier 2 Management Servers

#>

# Select management servers for tier 2
# ------------------------------------------------------------
$Tier2JumpStations = $($ServerInfo | Where {$_.Role -eq "MGMT"}) | Out-GridView -Title "Select the Tier 2 Jump / Management Servers" -OutputMode Multiple


# Install RSAT tools on Tier 2
# ------------------------------------------------------------
$($Tier2JumpStations).Name | Get-ADComputer -ErrorAction SilentlyContinue | Foreach {

    If ( ($Null -ne $TargetPath) -and ($($_.DistinguishedName) -NotLike "*OU=JumpStations,OU=Tier2*") ) {
        Move-ADObject -Identity $($_.DistinguishedName) -TargetPath $(Get-ADOrganizationalUnit -Filter "Name -eq 'JumpStations'" -SearchBase "OU=Tier2,$TierSearchBase").DistinguishedName
    }
    
    
    # Add to Silo.
    # ------------------------------------------------------------
    Set-TSxAdminADAuthenticationPolicySiloForComputer -ADComputerIdentity $($_.Name) -Tier T2


    # Connect to the server.
    # ------------------------------------------------------------
    $Session = New-PSSession -ComputerName "$($_.DNSHostName)"


    # Copy required installers to target server
    # ------------------------------------------------------------
    $FilesToCopy = @(
        "AzureConnectedMachineAgent.msi",
        "Setup.RemoteDesktopManager.exe",
        "windowsdesktop-runtime-8.0.6-win-x64.exe"
    )

    $FilesToCopy | Foreach {
        Get-ChildItem -Path $TxScriptPath -Filter $_ -Recurse | Copy-Item -Destination "$($ENV:PUBLIC)\downloads\$_" -ToSession $Session -Force
    }


    # Execute commands.
    # ------------------------------------------------------------
    Invoke-Command -Session $Session -ScriptBlock {


        # Install Azure Arc Agent
        # ------------------------------------------------------------
        if (Test-Path -Path "$($ENV:PUBLIC)\downloads\AzureConnectedMachineAgent.msi") {
            Start-Process -FilePath "$($ENV:PUBLIC)\downloads\AzureConnectedMachineAgent.msi" -ArgumentList "/quiet /qn /norestart" -wait
        }


        # Selected RSAT tools
        # ------------------------------------------------------------
        $ToolsToInstall = @(
	        "RSAT-*",
            "GPMC"
	        )
        Get-WindowsFeature -Name $ToolsToInstall | Where {$_.InstallState -eq "Available"} | Install-WindowsFeature -Verbose -ErrorAction SilentlyContinue
        
        & Gpupdate /force

        & Gpupdate /force


        # Install RDM
        # ------------------------------------------------------------
        if (Test-Path -Path "$($ENV:PUBLIC)\downloads\Setup.RemoteDesktopManager.exe") {
            Start-Process -FilePath "$($ENV:PUBLIC)\downloads\Setup.RemoteDesktopManager.exe" -ArgumentList "/quiet /qn /norestart" -wait
        }
        if (Test-Path -Path "$($ENV:PUBLIC)\downloads\windowsdesktop-runtime-8.0.6-win-x64.exe") {
            Start-Process -FilePath "$($ENV:PUBLIC)\downloads\windowsdesktop-runtime-8.0.6-win-x64.exe" -ArgumentList "/quiet /qn /norestart" -wait
        }


        # Cleanup files.
        # ------------------------------------------------------------
        Get-ChildItem -Path "$($ENV:PUBLIC)\downloads" -Recurse | Remove-Item


        # Reboot to activate all changes.
        # ------------------------------------------------------------
        & shutdown -r -t 10
    }
}
