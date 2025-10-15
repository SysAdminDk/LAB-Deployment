<#
    ______                      _         _____             _             _ _               
    |  _  \                    (_)       /  __ \           | |           | | |          
    | | | |___  _ __ ___   __ _ _ _ __   | /  \/ ___  _ __ | |_ _ __ ___ | | | ___ _ __ 
    | | | / _ \| '_ ` _ \ / _` | | '_ \  | |    / _ \| '_ \| __| '__/ _ \| | |/ _ \ '__|
    | |/ / (_) | | | | | | (_| | | | | | | \__/\ (_) | | | | |_| | | (_) | | |  __/ |   
    |___/ \___/|_| |_| |_|\__,_|_|_| |_|  \____/\___/|_| |_|\__|_|  \___/|_|_|\___|_| 


    Install & Configure FIRST Domain Controller.

#>


<#

    Gather required data from Cloud Init

#>
# Find Media Drive.
# ------------------------------------------------------------
$MediaDrives = Get-WmiObject -Class Win32_volume -Filter "DriveType = '5'"
foreach ($MediaDrive in $MediaDrives) {

    # Get content from User Data 
    # ------------------------------------------------------------
    $HostConfigFile = Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "USER_DATA" -ErrorAction SilentlyContinue
    if ($HostConfigFile) {
        $HostConfig = Get-Content -Path $HostConfigFile.FullName

        # Host Config
        # ------------------------------------------------------------
        if ($HostConfig) {

            # Extract values from User Data
            # ------------------------------------------------------------
            $DomainName = (($HostConfig | Where {$_ -like "*fqdn*"})     -Replace("^(?:\w+):\s","") -split("\.", 2))[1]
            $Username =   (($HostConfig | Where {$_ -like "*user*"})[0]) -Replace("^(?:\w+):\s","")
            $Password =   ($HostConfig  | Where {$_ -like "*password*"}) -Replace("^(?:\w+):\s","")
        }
    }


    # Locate TS AD Tiering tools
    # ------------------------------------------------------------
    $ADTieringFile = Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "ADTiering.zip" -ErrorAction SilentlyContinue


    # Locate AD Users list
    # ------------------------------------------------------------
    $ADUsersFile = Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "Users.txt" -ErrorAction SilentlyContinue
    if ($ADUsersFile) {
        $UserList = Get-Content -Path $ADUsersFile.FullName
    }
}


<#

    Workgroup taks.
    1. Enable Autologin if not already.
    2. Add RunOnce if not already
    3. Install ADDS.
    4. Create Domain.

#>

if (!((gwmi win32_computersystem).partofdomain)) {

    # Get Domain Name from DNS Suffix
    # --------------------------------------------------------------------------------------------------
    $Netbios = $(($DomainName -split("\."))[0]).ToUpper()


    # Enabled Autologin
    # --------------------------------------------------------------------------------------------------
    $AutoLoginData = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    if ($AutoLoginData.AutoLogonCount -le 2) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoLogonCount" -value 3
    }
    if ($AutoLoginData.AutoAdminLogon -eq 0) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoAdminLogon" -value 1
    }
    if (!($AutoLoginData.DefaultUserName)) {
        Write-Error "Missing Auto Logon Username"
    }
    if (!($AutoLoginData.DefaultPassword)) {
        Write-Error "Missing Auto Logon Password"
    }


    # Registry Run
    # --------------------------------------------------------------------------------------------------
    if (!(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Resume BootStrap" -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Install Domain" -Value "Powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$($MyInvocation.MyCommand.Definition)`"" -Force | Out-Null
    }


    # Install ADDS & DNS
    # --------------------------------------------------------------------------------------------------
    if ((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Available") {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }


    # Create Active Directory Domain
    # --------------------------------------------------------------------------------------------------
    try {
        $tempDomain = (Get-ADDomain).NetBIOSName
    }
    Catch {

        # Setup Domain, with Random restore mode password, will be handled with Windows Laps later.
        # --------------------------------------------------------------------------------------------------
        $PWString = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 25 | ForEach-Object {[char]$_})
        $SecurePassword = ConvertTo-SecureString -string $PWString -AsPlainText -Force
        Install-ADDSForest -DomainName $DomainName -SafeModeAdministratorPassword $SecurePassword -force -InstallDNS -DomainNetbiosName $Netbios


        # Wait for Restart
        # --------------------------------------------------------------------------------------------------
        Start-Sleep -Seconds 300
    }

}


<#

    PDC Tasks.
    1. Create DNS Zone
    2. Create Reverse Zone
    3. Create Truesec Active Directory Tiering
    4. GPOs
    5. Add LAPS to DCs
    6. Copy PolicyDefinitions to Central Store
    7. Copy Desired State Configurations to Central Store
    8. Install and Configure Windows Backup, System State

#>
# Run after Domain have been created.
# --------------------------------------------------------------------------------------------------
if ((gwmi win32_computersystem).DomainRole -eq 5) {

    $DownloadFolder = "$($ENV:USERPROFILE)\Downloads"


    # Get current network configuration
    # --------------------------------------------------------------------------------------------------
    $NetAdapter = Get-NetAdapter | Where {$_.Status -eq "UP"} | Select-Object -First 1
    $CurrentIP = $NetAdapter | Get-NetIPAddress -AddressFamily IPv4


    # Add Reverse lookup DNS Zone
    # --------------------------------------------------------------------------------------------------
    $DNSZone = (($CurrentIP.IPAddress -split("\.")) | Select-Object -SkipLast 1) -join(".")
    $DNSZoneArray = $DNSZone -split("\.")
    [array]::Reverse($DNSZoneArray)
    $DNSZoneArray += "in-addr.arpa"

    if (!(Get-DnsServerZone -Name $($DNSZoneArray -Join(".")) -ErrorAction SilentlyContinue)) {
        $IPSubnet = "$DNSZone.0/24"
        Add-DnsServerPrimaryZone -NetworkID $IPSubnet -ReplicationScope "Forest"
    }


    # Create DNS Subnet
    # --------------------------------------------------------------------------------------------------
    $SiteName = (Get-ADReplicationSite).Name
    if (!(Get-ADReplicationSubnet -Filter "Name -like '*$IPSubnet*'")) {
        New-ADReplicationSubnet -Name $IPSubnet -Site $SiteName
    }


    # Setup Active Directory Tiering.
    # --------------------------------------------------------------------------------------------------
    if ($ADTieringFile) { 
        if (Test-Path -Path "$($ENV:USERPROFILE)\Downloads") {
            Expand-Archive -Path $ADTieringFile -DestinationPath "$($ENV:USERPROFILE)\Downloads"
        }

        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:0


        # Update the ExtraOrganizationalUnits file
        # --------------------------------------------------------------------------------------------------
        $ExtraOrganizationalUnits = @()
        $ExtraOrganizationalUnits += "Name, Tier, Description"
        $ExtraOrganizationalUnits += "GenericServers,T0,Tier0 Generic Servers"
        $ExtraOrganizationalUnits += "DeployentServers,T0,Tier0 Deployment Servers"
        $ExtraOrganizationalUnits += "AzureLocalServers,T0,Tier0 Azure Local Servers"
        $ExtraOrganizationalUnits += "GenericServers,T1,Tier1 Generic Servers"
        $ExtraOrganizationalUnits += "RemoteDesktopGatewayServers,T1,Tier1 Remote Desktop Gateway Servers"
        $ExtraOrganizationalUnits += "RemoteDesktopNPASServers,T1,Tier1 Remote Desktop NPAS Servers (MFA)"
        $ExtraOrganizationalUnits += "RadiusBackendServers,T1,Tier1 - Radius Authentication Servers"
        $ExtraOrganizationalUnits += "FileServers,T1,Tier0 File Servers"
        
        $ExtraOrganizationalUnits | Out-File (Get-ChildItem -Path "$($ENV:USERPROFILE)\Downloads\ADTiering" -Filter "*.csv").fullname -Encoding utf8 -Force


        # Setup TS AD Tiering
        # --------------------------------------------------------------------------------------------------
        & "$($ENV:USERPROFILE)\Downloads\ADTiering\Deploy-TSxADTiering.ps1" -CompanyName MyCompany -TierOUName Admin -NoOfTiers 1 -SkipTierEndpointsPAW -SkipTierEndpoints -SkipComputerRedirect -WindowsLAPSOnly


        # Get MY Install MSFT Baselines script.
        # --------------------------------------------------------------------------------------------------
        $Uri = "https://api.github.com/repos/SysAdminDk/MS-Infrastructure/contents/ADDS%20Scripts/Security%20Baselines/MSFT%20Baseline?ref=$Branch"
        $Files = Invoke-RestMethod -Uri $Uri -Headers @{ "User-Agent" = "Powershell" }

        $Files | % { Invoke-WebRequest -Uri $_.download_url -OutFile "$DownloadFolder\$($_.Name)" }


        # Get MY Add WMI Filters script.
        # --------------------------------------------------------------------------------------------------
        $Uri = "https://api.github.com/repos/SysAdminDk/MS-Infrastructure/contents/ADDS%20Scripts/Security%20Baselines/WMI-Filters?ref=$Branch"
        $Files = Invoke-RestMethod -Uri $Uri -Headers @{ "User-Agent" = "Powershell" }

        $Files | % { Invoke-WebRequest -Uri $_.download_url -OutFile "$DownloadFolder\$($_.Name)" }


        # Get and install MSFT Baselines
        # --------------------------------------------------------------------------------------------------
        & "$DownloadFolder\Import-MSFT-Baselines.ps1" -Path $DownloadFolder -Action AutoInstall
        & "$DownloadFolder\Create-Overrides.ps1"
        & "$DownloadFolder\Update-MSFT-AuditPolicy.ps1"


        # Create WMI Filters
        # --------------------------------------------------------------------------------------------------
        & "$DownloadFolder\Create-WMIfilters.ps1"
        & "$DownloadFolder\Set-VMIFilters.ps1"


        # Link MSFT Domain Controller Baselines to Domain Controllers OU
        # --------------------------------------------------------------------------------------------------
        Get-GPO -All | Where {$_.DisplayName -like "MSFT*Domain Controller"} | Sort-Object -Property DisplayName -Descending | New-GPLink -Target $(Get-ADDomain).DomainControllersContainer


        # Link MSFT Baselines to Servers and JumpStations OUs
        $SearchBase = (Get-ADOrganizationalUnit -Filter "Name -like '*Admin*'" -SearchScope OneLevel).DistinguishedName

        $GPOTargets = @()
        $GPOTargets += (Get-ADOrganizationalUnit -Filter "Name -like 'JumpStations*'" -SearchBase $SearchBase).DistinguishedName
        $GPOTargets += (Get-ADOrganizationalUnit -Filter "Name -eq 'Servers'" -SearchBase $SearchBase).DistinguishedName

        $GPOTargets | % { Get-GPO -All | Where {$_.DisplayName -like "MSFT*Member Server" -or $_.DisplayName -like "MSFT*Member Server*Overrides*"} | Sort-Object -Property DisplayName -Descending | New-GPLink -Target $_ }


        # Create users, if list exists.
        # --------------------------------------------------------------------------------------------------
        if ($UserList) {
            $CreatedUsers = @()
            $UserList | ForEach-Object {
                $Username = $_ -split(" ")
                $CreatedUsers += New-TSxAdminAccount -FirstName $Username[0] -LastName $Username[1] -AccountType T0 -Prefix "Adm" -Suffix "FTE" -AddToSilo $false -Verbose
                $CreatedUsers += New-TSxAdminAccount -FirstName $Username[0] -LastName $Username[1] -AccountType T1 -Prefix "Adm" -Suffix "FTE" -AddToSilo $false -Verbose
                $CreatedUsers += New-TSxAdminAccount -FirstName $Username[0] -LastName $Username[1] -AccountType CON -Prefix "Adm" -Suffix "FTE" -AddToSilo $false -Verbose
            }
            $CreatedUsers | Out-File "$($ENV:USERPROFILE)\Documents\CreatedUsers.txt" -Append
        }
    }


    # Create GPO - Disable Server Manager
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "Admin - Disable Server Manager"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -LinkEnabled Yes | Out-Null
    if ($GPOTargets) {
        $GPOTargets | % { Get-GPO -Name $GPO.DisplayName | New-GPLink -Target $_ }
    }
    (Get-GPO -Name $GPO.DisplayName).GpoStatus = "UserSettingsDisabled"

    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\Server\ServerManager" -ValueName DoNotOpenAtLogon -Value 1 -Type DWord | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\ServerManager" -ValueName "DoNotOpenServerManagerAtLogon" -Value 1 -Type DWord -Context Computer -Action Update | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\ServerManager" -ValueName "DoNotPopWACConsoleAtSMLaunch" -Value 1 -Type DWord -Context Computer -Action Update | Out-Null


    # Create GPO - Enable Remote Desktop
    # --------------------------------------------------------------------------------------------------
    if (!((Get-GPInheritance -Target (Get-ADDomain).DomainControllersContainer).gpolinks | Where {$_.displayname -like "*Enable Remote Desktop*"})) {
        
        # Tiering not executed, make sure we can RDP to the servers.
        # --------------------------------------------------------------------------------------------------
        $GPO = New-GPO -Name "Admin - Enable Remote Desktop"
        Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -LinkEnabled Yes | Out-Null
        Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DistinguishedName -LinkEnabled Yes | Out-Null
        (Get-GPO -Name $GPO.DisplayName).GpoStatus = "UserSettingsDisabled"

        Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -Value 0 -Type DWord | Out-Null
        Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "RemoteDesktop-UserMode-In-UDP" -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%SystemRoot%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|" -Type String | Out-Null
        Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "RemoteDesktop-UserMode-In-TCP" -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|" -Type String | Out-Null
        Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "RemoteDesktop-Shadow-In-TCP" -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=%SystemRoot%\system32\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|" -Type String | Out-Null
    }


    # Create GPO - Cleanup Server Desktop
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "User - Cleanup Server Desktop"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -LinkEnabled Yes | Out-Null
    (Get-GPO -Name $GPO.DisplayName).GpoStatus = "ComputerSettingsDisabled"

    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName HideFileExt -Value 0 -Type DWord -Action Update -Context User | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName ShowTaskViewButton -Value 0 -Type DWord -Action Update -Context User | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -ValueName SearchboxTaskbarMode -Value 0 -Type DWord -Action Update -Context User | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKCU\Control Panel\Desktop" -ValueName UserPreferencesMask -Value ([byte[]](0x90,0x32,0x07,0x80,0x10,0x00,0x00,0x00)) -Type Binary -Context User -Action Update | Out-Null


    # Create GPO - Disable Cortana
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "Computer - Disable Cortana"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DistinguishedName -LinkEnabled Yes | Out-Null
    (Get-GPO -Name $GPO.DisplayName).GpoStatus = "UserSettingsDisabled"

    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName AllowCortana -Value 0 -Type DWord | Out-Null


    # Update Schema with Windows Laps.
    # --------------------------------------------------------------------------------------------------
    Update-LapsADSchema -Verbose -confirm:0


    # Create Windows Laps Policy
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "[MDFT] - Windows LAPS Domain Controller"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -LinkEnabled Yes | Out-Null
    (Get-GPO -Name $GPO.DisplayName).GpoStatus = "UserSettingsDisabled"

    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName ADBackupDSRMPassword -Value 1 -Type DWord | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName ADPasswordEncryptionEnabled -Value 1 -Type DWord | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName BackupDirectory -Value 2 -Type DWord | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName PasswordComplexity -Value 4 -Type DWord | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName PasswordLength -Value 25 -Type DWord | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName PasswordAgeDays -Value 90 -Type DWord | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName PassphraseLength -Value 6 -Type DWord | Out-Null


    # Make PolicyDefinitions folder
    # --------------------------------------------------------------------------------------------------
    if (!(Test-Path -Path "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions")) {
         Copy-Item -Path "C:\Windows\PolicyDefinitions" -Destination "C:\Windows\SYSVOL\domain\Policies" -Recurse
    }


    # Copy all DSC files to \Netlogon
    # --------------------------------------------------------------------------------------------------
    $MediaDrives = Get-WmiObject -Class Win32_volume -Filter "DriveType = '5'"
    foreach ($MediaDrive in $MediaDrives) {
        if (Test-Path -Path "$MediaDrive\Windows DSC") {

            # Make DSC folders in Netlogon
            # --------------------------------------------------------------------------------------------------
            if (!(Test-Path -Path "$($env:SystemRoot)\SYSVOL\domain\scripts\Windows DSC")) {
                New-Item -Path "$($env:SystemRoot)\SYSVOL\domain\scripts\Windows DSC" -ItemType Directory | Out-Null
            }


            # Find all mof files.
            # --------------------------------------------------------------------------------------------------
            $DSCFiles = (Get-ChildItem -Path "$MediaDrive\Windows DSC" -Recurse -Filter "*.mof")
            $DSCFiles | ForEach-Object {
                Copy-Item $_.FullName -Destination "$($env:SystemRoot)\SYSVOL\domain\scripts\Windows DSC"
            }
        }
    }


    <#

        System State - AD Backup

    #>
    if ((Get-Disk).count -gt 1) {

        # Ensure Windows Server Backup is installed
        # ------------------------------------------------------------
        if (!(Get-Command Start-WBBackup -ErrorAction SilentlyContinue)) {
            Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools
        }

        # Setup Scheduled backup
        # ------------------------------------------------------------
        $Disk = Get-WBDisk | Where { $_.TotalSpace -gt (Get-Partition | Where {$_.DriveLetter -eq "C"} | Get-Disk).Size }
        if ($Disk.count -gt 1) {
            throw "Multiple disks found, please ensure there is only one"
            break
        }
        $DiskInfo = Get-Disk -Number $Disk.DiskNumber

        if ($DiskInfo.OperationalStatus -ne "Online") {
            Get-Disk -Number $Disk.DiskNumber | Set-Disk -IsOffline:$False
            $DiskInfo | Initialize-Disk
            $DiskInfo | Clear-Disk -Confirm:0
        }

        if ($null -ne $Disk) {
                
            if (!(Get-WBPolicy)) {
                & wbadmin enable backup -addtarget:"{$($Disk.DiskId.Guid)}" -Schedule:22:00 -allCritical -quiet
            } else {
                Write-Warning "Backup already configured, please check configuration."
                Get-WBPolicy
            }

        } else {
            Write-Warning "No AD Backup configured"
        }
    }


    # Script done, close console connection.
    # --------------------------------------------------------------------------------------------------
    Logoff
}
