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
