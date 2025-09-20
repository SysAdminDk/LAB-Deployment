Function Get-PVENextDiskID {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ProxmoxAPI,
        [Parameter(Mandatory)][object]$Headers,
        [Parameter(Mandatory)][string]$Node,
        [Parameter(Mandatory)][int]$VMID
    )

    # Get VM Status
    # ------------------------------------------------------------
    $VMStatus = (Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$Node/qemu/$VMID/config" -Headers $Headers -Verbose:$false).data


    # Get first boot device from list.
    # ------------------------------------------------------------
    $BootDrive = ((($VMStatus.boot -split("="))[-1] -split(";"))[0])


    # Exclude IDE.
    # ------------------------------------------------------------
    if ($BootDrive -like "IDE*") { $BootDrive = "virtio" }


    # Get name of storage controller
    # ------------------------------------------------------------
    $StorageController = $bootdrive -replace("\d+$","")

    
    # Find LAST drive attached to the selected Storage Controller
    # ------------------------------------------------------------
    $LastVMDisk = $VMStatus.PSObject.Properties | Where-Object { $_.Name -match "^$StorageController\d+$" } | Sort-Object Name | Select-Object -Last 1


    # Controller ID ++
    # ------------------------------------------------------------
    if ($LastVMDisk) {
        if ($LastVMDisk.Name -match '\d+$') {
            $VMDiskCount = [int]$matches[0] + 1
        }
    }

    return "$StorageController$VMDiskCount"
}
