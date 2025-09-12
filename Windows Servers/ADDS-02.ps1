<#
    ______                      _         _____             _             _ _               
    |  _  \                    (_)       /  __ \           | |           | | |              
    | | | |___  _ __ ___   __ _ _ _ __   | /  \/ ___  _ __ | |_ _ __ ___ | | | ___ _ __ ___ 
    | | | / _ \| '_ ` _ \ / _` | | '_ \  | |    / _ \| '_ \| __| '__/ _ \| | |/ _ \ '__/ __|
    | |/ / (_) | | | | | | (_| | | | | | | \__/\ (_) | | | | |_| | | (_) | | |  __/ |  \__ \
    |___/ \___/|_| |_| |_|\__,_|_|_| |_|  \____/\___/|_| |_|\__|_|  \___/|_|_|\___|_|  |___/


#>


# Install & Configure Domain Controller.
# ------------------------------------------------------------
if (!((gwmi win32_computersystem).partofdomain)) {
    
    Throw "Domain join have failed"

}


if ((gwmi win32_computersystem).partofdomain) {

    # Install ADDS & DNS
    # --------------------------------------------------------------------------------------------------
    if ((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Available") {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }


    # Gennerate Safe Mode Password.
    # ------------------------------------------------------------
    $PWString = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 25 | ForEach-Object {[char]$_})
    $SecurePassword = ConvertTo-SecureString -string $PWString -AsPlainText -Force


    # Promote domain controller
    # ------------------------------------------------------------
    Install-ADDSDomainController -DomainName $ENV:USERDNSDOMAIN -SafeModeAdministratorPassword $SecurePassword -NoRebootOnCompletion -Confirm:$false -Credential $Credentials



<#

    Backup Section

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

    NTDS Move Section

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

}

