<#
    ______                      _         _____             _             _ _               
    |  _  \                    (_)       /  __ \           | |           | | |          
    | | | |___  _ __ ___   __ _ _ _ __   | /  \/ ___  _ __ | |_ _ __ ___ | | | ___ _ __ 
    | | | / _ \| '_ ` _ \ / _` | | '_ \  | |    / _ \| '_ \| __| '__/ _ \| | |/ _ \ '__|
    | |/ / (_) | | | | | | (_| | | | | | | \__/\ (_) | | | | |_| | | (_) | | |  __/ |   
    |___/ \___/|_| |_| |_|\__,_|_|_| |_|  \____/\___/|_| |_|\__|_|  \___/|_|_|\___|_| 


    Install & Configure FIRST Domain Controller.

#>

# Restart the script as Admin, if needed.
# ------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {

    Write-Output ""
    Write-Warning "Restarting script as Administrator"

    if (!(Test-Path -Path "$($ENV:PUBLIC)\Downloads\$($MyInvocation.MyCommand.name)")) {
        Copy-item -Path $PSCommandPath -Destination "$($ENV:PUBLIC)\Downloads\$($MyInvocation.MyCommand.name)" | Out-Null
    }

    $PSHost = If ($PSVersionTable.PSVersion.Major -le 5) {'PowerShell'} Else {'PwSh'}
    Start-Process -Verb RunAs $PSHost (" -File `"$($ENV:PUBLIC)\Downloads\$($MyInvocation.MyCommand.name)`"")

    Start-Sleep -Seconds 5
    break
}


# Required parameters.
# --------------------------------------------------------------------------------------------------
$UserPassword = "DefaultPasswordReplace"
$DomainName = "DefaultDomainNameReplace"


# Cleanup if Domain is up and running.
# --------------------------------------------------------------------------------------------------
Try {
    $DomainQuery = Get-ADDomain -Identity $DomainName -ErrorAction SilentlyContinue
}
Catch {
    Write-Host "Domain not created yet, continue script"
}

if ( ((gwmi win32_computersystem).partofdomain) -and ($null -ne $DomainQuery) ) {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -name "AutoAdminLogon" -value 0
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -name "AutoLogonCount" -value 0
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -name "DefaultUserName " -value ""
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -name "DefaultDomainName" -value ""
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Install Domain" -Force -ErrorAction SilentlyContinue
    Break
}


# Needed information about the servers network
# --------------------------------------------------------------------------------------------------
$NetAdapter = Get-NetAdapter | Where {$_.Status -eq "UP"}
$CurrentIP = $NetAdapter | Get-NetIPAddress -AddressFamily IPv4


# Run when in WorkGroup
# --------------------------------------------------------------------------------------------------
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
    if ($AutoLoginData.DefaultUserName -ne $env:USERNAME) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultUserName" -value $env:USERNAME -Force
    }
    if ( (!($AutoLoginData.DefaultPassword)) -or ($AutoLoginData.DefaultPassword -ne $UserPassword) ) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $UserPassword -Force
    }
    if ($AutoLoginData.DefaultDomainName -ne $Netbios) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $Netbios -Force
    }


    # Registry Run
    # --------------------------------------------------------------------------------------------------
    if (!(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Install Domain" -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Install Domain" -Value "Powershell.exe -ExecutionPolicy Bypass -File `"C:\TS-Data\Create-Domain.ps1`"" | Out-Null
    }


    # Configure IP Address
    # --------------------------------------------------------------------------------------------------
    $CurrentIPAddress = ($CurrentIP.IPAddress -split("\."))[-1]
    $CurrentSubnet = ($CurrentIP.IPAddress -split("\."))[0..2] -join(".")
    $CurrentGateway = (Get-NetIPConfiguration -InterfaceIndex $NetAdapter.ifIndex).IPv4DefaultGateway.NextHop

    If ($CurrentIPAddress -ne "11") {
        Get-NetAdapter | New-NetIPAddress -IPAddress "$CurrentSubnet.11" -PrefixLength $CurrentIP.PrefixLength -DefaultGateway $CurrentGateway | Out-Null
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses ("8.8.8.8", "8.8.4.4") | Out-Null
    }


    # Rename computer (If wrong name)
    # --------------------------------------------------------------------------------------------------
    if ($env:computername -ne "ADDS-01") {
        Write-Output "Renaming server"
    
	    Rename-Computer -NewName "ADDS-01" -Restart
    
        Write-Host "Wait for Server Rename"
        for ($i=0; $i -le 300; $i++) {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }    
        break
    }


    # Wait for Restart & Login with Administrator
    # --------------------------------------------------------------------------------------------------



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
        Write-Host "Wait for Domain Reboot"
        for ($i=0; $i -le 300; $i++) {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }    
        break
    }

}


# Run after Domain have been created.
# --------------------------------------------------------------------------------------------------
if ((gwmi win32_computersystem).partofdomain) {

    # Add Reverse lookup DNS Zone
    # --------------------------------------------------------------------------------------------------
    $DNSZone = (($CurrentIP.IPAddress -split("\.")) | Select-Object -SkipLast 1) -join(".")

    if (!(Get-DnsServerZone -Name "$DNSZone.in-addr.arpa" -ErrorAction SilentlyContinue)) {
        $IPSubnet = "$DNSZone.0/24"
        Add-DnsServerPrimaryZone -NetworkID $IPSubnet -ReplicationScope "Forest"
    }


    # Create DNS Subnet
    # --------------------------------------------------------------------------------------------------
    $SiteName = (Get-ADReplicationSite).Name
    if (!(Get-ADReplicationSubnet -Filter "Name -like '*$IPSubnet*'")) {
        New-ADReplicationSubnet -Name $IPSubnet -Site $SiteName
    }


    # Create Simple Tiering OU structure
    # --------------------------------------------------------------------------------------------------
    New-ADOrganizationalUnit -Name "Admin" -Path $($DomainQuery.DistinguishedName)
    $AdminPath = Get-ADOrganizationalUnit -Identity "OU=Admin,$($DomainQuery.DistinguishedName)"

#    New-ADOrganizationalUnit -Name "ConnectionAccounts" -Path $($AdminPath.DistinguishedName)

    New-ADOrganizationalUnit -Name "Tier0" -Path $($AdminPath.DistinguishedName)
    $Tier0Path = Get-ADOrganizationalUnit -Identity "OU=Tier0,$($AdminPath.DistinguishedName)"

    New-ADOrganizationalUnit -Name "AdminAccounts" -Path $($Tier0Path.DistinguishedName)
    New-ADOrganizationalUnit -Name "Groups" -Path $($Tier0Path.DistinguishedName)
    New-ADOrganizationalUnit -Name "JumpStations" -Path $($Tier0Path.DistinguishedName)
    New-ADOrganizationalUnit -Name "Servers" -Path $($Tier0Path.DistinguishedName)
    $Tier0Servers = Get-ADOrganizationalUnit -Identity "OU=Servers,$($Tier0Path.DistinguishedName)"

    New-ADOrganizationalUnit -Name "CertificateAuthorityServers" -Path $($Tier0Servers.DistinguishedName)
    New-ADOrganizationalUnit -Name "SyncServers" -Path $($Tier0Servers.DistinguishedName)

    New-ADOrganizationalUnit -Name "Tier1" -Path $($AdminPath.DistinguishedName)
    $Tier1Path = Get-ADOrganizationalUnit -Identity "OU=Tier1,$($AdminPath.DistinguishedName)"

    New-ADOrganizationalUnit -Name "AdminAccounts" -Path $($Tier1Path.DistinguishedName)
    New-ADOrganizationalUnit -Name "Groups" -Path $($Tier1Path.DistinguishedName)
    New-ADOrganizationalUnit -Name "JumpStations" -Path $($Tier1Path.DistinguishedName)
    New-ADOrganizationalUnit -Name "Servers" -Path $($Tier1Path.DistinguishedName)
    $Tier1Servers = Get-ADOrganizationalUnit -Identity "OU=Servers,$($Tier1Path.DistinguishedName)"
    
    New-ADOrganizationalUnit -Name "RemoteDesktopBackendServers" -Path $($Tier1Servers.DistinguishedName)
    New-ADOrganizationalUnit -Name "FileServers" -Path $($Tier1Servers.DistinguishedName)
    New-ADOrganizationalUnit -Name "AzureGatewayServers" -Path $($Tier1Servers.DistinguishedName)
    New-ADOrganizationalUnit -Name "NetworkPolicyServers" -Path $($Tier1Servers.DistinguishedName)


    # Create inital users
    # --------------------------------------------------------------------------------------------------
    $SecurePassword = ConvertTo-SecureString -string $UserPassword -AsPlainText -Force
    New-ADUser -AccountPassword $SecurePassword -ChangePasswordAtLogon $false -DisplayName "T0-Admin" -Enabled $true -Name "T0-ADMIN" -SamAccountName "T0-Admin" -UserPrincipalName "T0-Admin@$($ENV:USERDNSDOMAIN)" -PasswordNeverExpires $True -Path "OU=AdminAccounts,$($Tier0Path.DistinguishedName)"
#    New-ADUser -AccountPassword $SecurePassword -ChangePasswordAtLogon $false -DisplayName "Con-User" -Enabled $true -Name "Con-User" -SamAccountName "Con-User" -UserPrincipalName "Con-User@$($ENV:USERDNSDOMAIN)" -PasswordNeverExpires $True -Path "OU=ConnectionAccounts,$($AdminPath.DistinguishedName)"

    # Create inital Group and add members
    # --------------------------------------------------------------------------------------------------
#    New-ADGroup -Name "Domain ConnectionAccounts" -Path "OU=ConnectionAccounts,$($AdminPath.DistinguishedName)" -GroupScope Global
    Add-ADGroupMember -Identity "Domain Admins" -Members @($(Get-ADUser -Identity "T0-Admin"))
#    Add-ADGroupMember -Identity "Domain ConnectionAccounts" -Members @($(Get-ADUser -Identity "Con-User"))


    # Create GPO - Disable Server Manager
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "Admin - Disable Server Manager"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -Server $(Get-ADDomain).PDCEmulator -LinkEnabled Yes | Out-Null
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DistinguishedName -Server $(Get-ADDomain).PDCEmulator -LinkEnabled Yes | Out-Null
    (Get-GPO -Name $GPO.DisplayName).GpoStatus = "UserSettingsDisabled"

    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\Server\ServerManager" -ValueName DoNotOpenAtLogon -Value 1 -Type DWord | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\ServerManager" -ValueName "DoNotOpenServerManagerAtLogon" -Value 1 -Type DWord -Context Computer -Action Update | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\ServerManager" -ValueName "DoNotPopWACConsoleAtSMLaunch" -Value 1 -Type DWord -Context Computer -Action Update | Out-Null


    # Create GPO - Enable Remote Desktop
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "Admin - Enable Remote Desktop"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -Server $(Get-ADDomain).PDCEmulator -LinkEnabled Yes | Out-Null
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DistinguishedName -Server $(Get-ADDomain).PDCEmulator -LinkEnabled Yes | Out-Null
    (Get-GPO -Name $GPO.DisplayName).GpoStatus = "UserSettingsDisabled"

    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -Value 0 -Type DWord | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "RemoteDesktop-UserMode-In-UDP" -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%SystemRoot%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|" -Type String | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "RemoteDesktop-UserMode-In-TCP" -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|" -Type String | Out-Null
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "RemoteDesktop-Shadow-In-TCP" -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=%SystemRoot%\system32\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|" -Type String | Out-Null


    # Create GPO - Cleanup Server Desktop
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "User - Cleanup Server Desktop"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -Server $(Get-ADDomain).PDCEmulator -LinkEnabled Yes | Out-Null
    (Get-GPO -Name $GPO.DisplayName).GpoStatus = "ComputerSettingsDisabled"

    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName HideFileExt -Value 0 -Type DWord -Action Update -Context User | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ValueName ShowTaskViewButton -Value 0 -Type DWord -Action Update -Context User | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -ValueName SearchboxTaskbarMode -Value 0 -Type DWord -Action Update -Context User | Out-Null
    Set-GPPrefRegistryValue -Name $GPO.DisplayName -Key "HKCU\Control Panel\Desktop" -ValueName UserPreferencesMask -Value ([byte[]](0x90,0x32,0x07,0x80,0x10,0x00,0x00,0x00)) -Type Binary -Context User -Action Update | Out-Null


    # Create GPO - Disable Cortana
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "Computer - Disable Cortana"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -Server $(Get-ADDomain).PDCEmulator -LinkEnabled Yes | Out-Null
    (Get-GPO -Name $GPO.DisplayName).GpoStatus = "UserSettingsDisabled"

    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName AllowCortana -Value 0 -Type DWord | Out-Null


    # Update Schema with Windows Laps.
    # --------------------------------------------------------------------------------------------------
    Update-LapsADSchema -Verbose -confirm:0


    # Create Windows Laps Policy
    # --------------------------------------------------------------------------------------------------
    $GPO = New-GPO -Name "[MDFT] - Windows LAPS Domain Controller"
    Get-GPO -Name $GPO.DisplayName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -Server $(Get-ADDomain).PDCEmulator -LinkEnabled Yes | Out-Null
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


    # Make DSC folders in Netlogon
    # --------------------------------------------------------------------------------------------------
    $DSCFiles = (Get-ChildItem -Path "$($ENV:SystemDrive)\Scripts\" -Recurse -Filter "*.mof")
    if ( (!(Test-Path -Path "C:\Windows\SYSVOL\domain\scripts\DSC-Files")) -and ($null -ne $DSCFiles) ) {
        New-Item -Path "C:\Windows\SYSVOL\domain\scripts\DSC-Files" -ItemType Directory | Out-Null
        $DSCFiles | ForEach-Object { Copy-Item $_.FullName -Destination "$VHDXVolume3\Scripts\MOF\" }
    }


<#

    AD Backup Section

#>

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
        Get-Disk -Number $Drives.DiskNumber | Set-Disk -IsOffline:$False
        $DiskInfo | Initialize-Disk
        $DiskInfo | Clear-Disk
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



<#

    NTDS move Section

#>

    $CurrentPath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DSA Working Directory")."DSA Working Directory"
    If ($CurrentPath -like "*Windows*") {

        # If any MEDIA on D, Move the drive letter
        $MediaDrive = Get-WmiObject -Class Win32_volume -Filter "DriveType = '5' and DriveLetter != 'X:'"
        if ($null -ne $MediaDrive) {
            Set-WmiInstance -InputObject $MediaDrive -Arguments @{DriveLetter='X:'} | Out-Null
        }

        # Prep the drive.
        $Disk = Get-Disk | Where {$_.PartitionStyle -eq "RAW"} | Initialize-Disk -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "NTDS Disk" -Confirm:$false
        if ($Disk.count -gt 1) {
            throw "Multiple disks found, please ensure there is only one"
            break
        }
        if ($null -eq $Disk) {
            Write-Warning "No disk suitable for NTDS"
            break
        }

        # Create Folder
        if (!(Test-Path -Path "$($Disk.DriveLetter):\NTDS")) {
            New-Item -Path "$($Disk.DriveLetter):\NTDS\" -ItemType Directory | Out-Null
        }

        # Stop AD
        Get-Service -Name NTDS | Stop-Service -Force

        $Commands = @()
        $Commands += "activate instance ntds"
        $Commands += "files"
        $Commands += "move db to $($Disk.DriveLetter):\NTDS"
        $Commands += "move logs to $($Disk.DriveLetter):\NTDS"
        $Commands += "quit"
        $Commands += "quit"

        & ntdsutil $commands

        # Start AD
        Get-Service -Name NTDS | Start-Service

        Start-Sleep -Seconds 30

    }

    # Script done, close console connection.
    # --------------------------------------------------------------------------------------------------
    Logoff
}
