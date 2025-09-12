<#
    ______ _   _ _____ ______   _____                          
    |  _  \ | | /  __ \| ___ \ /  ___|                         
    | | | | |_| | /  \/| |_/ / \ `--.  ___ _ ____   _____ _ __ 
    | | | |  _  | |    |  __/   `--. \/ _ \ '__\ \ / / _ \ '__|
    | |/ /| | | | \__/\| |     /\__/ /  __/ |   \ V /  __/ |   
    |___/ \_| |_/\____/\_|     \____/ \___|_|    \_/ \___|_|   

    
    "Script" actions
    1. Install DHCP role.
    2. Example script to migrate DHCP scopes.
#>


#region DHCP Server
<#
    If DHCP is installed on old Domain Controller(s), install new DHCP and migrate Scopes.

    ! Move to Tier 1, efter tiering !
#>

# Select Destination OU
# ------------------------------------------------------------
$TargetPath = (Get-ADOrganizationalUnit -Filter * -SearchBase $TierSearchBase | `
    Where {$_.DistinguishedName -like "OU=*OU=Servers,OU=Tier1,$TierSearchBase"}) |`
        Select-Object Name,DistinguishedName | Out-GridView -Title "Select Destination OU" -OutputMode Single


# Install & Configure DHCP Server (Only One)
# ------------------------------------------------------------
($($ServerInfo | Where {$_.Role -eq "DHCP"}).Name | Get-ADComputer -ErrorAction SilentlyContinue)[0] | Foreach {


    # Move the DHCP server to Tier 1
    # ------------------------------------------------------------
    If ( ($NUll -ne $TargetPath) -and ($($_.DistinguishedName) -NotLike "*OU=Servers,OU=Tier1,$TierSearchBase") ) {
        Move-ADObject -Identity $($_.DistinguishedName) -TargetPath $TargetPath.DistinguishedName
    }


    # Connect to the server.
    # ------------------------------------------------------------
    $Session = New-PSSession -ComputerName "$($_.DNSHostName)"


    # Make TS-Data folder on target server
    Invoke-Command -Session $Session -ScriptBlock {
        If (!(Test-Path -Path "C:\TS-Data")) {
            New-Item -Path "C:\TS-Data" -ItemType Directory | Out-Null
        }
    }


    # Copy required installers to target server
    # ------------------------------------------------------------
    $FilesToCopy = @(
        "AzureConnectedMachineAgent.msi"
    )
    $FilesToCopy | Foreach {
        Get-ChildItem -Path $TxScriptPath -Filter $_ -Recurse | Copy-Item -Destination "$($ENV:PUBLIC)\downloads\$_" -ToSession $Session -Force
    }

    if (Test-Path -Path "$TxScriptPath\Scripts\DHCP\Backup-Dhcp-Server.ps1") {
        Copy-Item -Path "$TxScriptPath\Scripts\DHCP\Backup-Dhcp-Server.ps1" -Destination "C:\TS-Data\Backup-Dhcp-Server.ps1" -ToSession $session -Force
    }
    if (Test-Path -Path "$TxScriptPath\Scripts\DHCP\Restore-Dhcp-Server.ps1") {
        Copy-Item -Path "$TxScriptPath\Scripts\DHCP\Restore-Dhcp-Server.ps1" -Destination "C:\TS-Data\Restore-Dhcp-Server.ps1" -ToSession $session -Force
    }
    if (Test-Path -Path "$TxScriptPath\Scripts\DHCP\Setup-Dhcp-Server.ps1") {
        Copy-Item -Path "$TxScriptPath\Scripts\DHCP\Setup-Dhcp-Server.ps1" -Destination "C:\TS-Data\Setup-Dhcp-Server.ps1" -ToSession $session -Force
    }


    # Execute commands.
    # ------------------------------------------------------------
    Invoke-Command -Session $Session -ScriptBlock {


        # Install Azure Arc Agent
        # ------------------------------------------------------------
        if (Test-Path -Path "$($ENV:PUBLIC)\downloads\AzureConnectedMachineAgent.msi") {
            Start-Process -FilePath "$($ENV:PUBLIC)\downloads\AzureConnectedMachineAgent.msi" -ArgumentList "/quiet /qn /norestart" -wait
        }


        # Install required features.
        # ------------------------------------------------------------
        Install-WindowsFeature -Name DHCP -IncludeManagementTools


        # Run GPUpdate and restart
        # ------------------------------------------------------------
        Invoke-GPUpdate -Force
        & Shutdown -r -t 10
    }
}

# Open DHCP migrate script.
# ------------------------------------------------------------
if (Test-Path -Path "$TxScriptPath\Scripts\Migrate-DHCP.ps1") {
    ISE "$TxScriptPath\Scripts\Migrate-DHCP.ps1"
}
#endregion
