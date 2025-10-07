<#

    Get required PROXMOX data

#>


$RootPath = "D:\PVE Scripts"


# Import PVE modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false
Get-ChildItem -Path "$RootPath\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


# Connect to PVE Cluster
# ------------------------------------------------------------
$PVESecret = Get-Content "$RootPath\PVE-Secret.json" | Convertfrom-Json
$PVEConnect = PVE-Connect -Authkey "$($PVESecret.User)!$($PVESecret.TokenID)=$($PVESecret.Token)" -Hostaddr $($PVESecret.Host)


# Get Id of Deployment server....
# ------------------------------------------------------------
$MasterID = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "LAB-Deploy"


# Get information required to create the template (VM)
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -IncludeNode $MasterID.Node


<#

    Now the connection and required information is ready, time to create the template.

#>


# Info of the VM created.
# ------------------------------------------------------------
$VMName = "2025-Template"
$Memory = 8*1024
$Cores = 4
$OSDisk = 50
$TemplateID = Get-PVENextID -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $($PVEConnect.Headers)



# Default Template Configuration
# ------------------------------------------------------------
$Body = "node=$($MasterID.Node)"
$Body += "&vmid=$TemplateID"
$Body += "&name=$(($VMName -split("\."))[0])"
$Body += "&bios=ovmf"
$Body += "&cpu=host"
$Body += "&ostype=win11"
$Body += "&machine=pc-q35-9.0"
$Body += "&tpmstate0=$([uri]::EscapeDataString("$($PVELocation.storage):1,size=4M,version=v2.0"))"
$Body += "&efidisk0=$([uri]::EscapeDataString("$($PVELocation.storage):1,efitype=4m,format=raw,pre-enrolled-keys=1"))"
$Body += "&net0=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1"))"
$Body += "&boot=$([uri]::EscapeDataString("order=net0"))"
$Body += "&scsihw=virtio-scsi-single"
$Body += "&memory=$Memory"
$Body += "&balloon=2048"
$Body += "&cores=$Cores"
$Body += "&scsi0=$([uri]::EscapeDataString("$($PVELocation.storage):$($OSDisk),format=raw"))"
$Body += "&ide2=$([uri]::EscapeDataString("none,media=cdrom"))"


# Create the Template VM
# ------------------------------------------------------------
$VMCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($MasterID.Node)/qemu/" -Body $Body -Method POST -Headers $($PVEConnect.Headers) -Verbose:$false
Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($MasterID.Node) -taskid $VMCreate.data


<#

    To apply Windows install wim, move the template OS disk to this server, partition disk and apply wim.

#>


# Move OS disk to THIS server.
# ------------------------------------------------------------
$TmpDiskID = Reassign-PVEOwner -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -SourceNode $MasterID.Node -SourceVM $TemplateID -TargetVM $MasterID.VmID -Wait


# Pause 5 sec, need PnP to work
# ------------------------------------------------------------
Start-Sleep -Seconds 5


# Initialize disk, and create UEFI partions
# ------------------------------------------------------------
$VHDDrive = Get-Disk | Where {$_.partitionstyle -eq 'RAW' -and $_.Size -eq 50Gb }
if ($null -eq $VHDDrive) {

    throw "Unable to locate any avalible disk"

} else {

    Initialize-Disk -Number $VHDDrive.number -PartitionStyle GPT

    Get-Partition -DiskNumber $VHDDrive.number | Remove-Partition -Confirm:$false

    $VHDXDrive1 = New-Partition -DiskNumber $VHDDrive.number -GptType  "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" -AssignDriveLetter -Size 100Mb
    $VHDXDrive1 | Format-Volume -FileSystem FAT32 -NewFileSystemLabel System -Confirm:$false | Out-null

    $VHDXDrive2 = New-Partition -DiskNumber $VHDDrive.number -GptType "{e3c9e316-0b5c-4db8-817d-f92df00215ae}" -Size 16Mb

    $VHDXDrive3 = New-Partition -DiskNumber $VHDDrive.number -UseMaximumSize -AssignDriveLetter
    $VHDXDrive3 | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false | Out-null


    # Add Drive letters
    # ------------------------------------------------------------
    $VHDXDrive1 = Get-Partition -DiskNumber $VHDDrive.number -PartitionNumber $VHDXDrive1.PartitionNumber
    $VHDXVolume1 = [string]$VHDXDrive1.DriveLetter+":"

    $VHDXDrive3 = Get-Partition -DiskNumber $VHDDrive.number -PartitionNumber $VHDXDrive3.PartitionNumber
    $VHDXVolume3 = [string]$VHDXDrive3.DriveLetter+":"


    # Find all instances of Install.Wim om THIS computer.
    # --
    $ExcludeDrives = @()
    $ExcludeDrives += $(($env:SystemDrive) -replace(":",""))
    $ExcludeDrives += $VHDXDrive1.DriveLetter
    $ExcludeDrives += $VHDXDrive3.DriveLetter
    $ExcludeDrives += $(Get-Volume | Where-Object {$_.drivetype -eq 'CD-ROM'}).DriveLetter

    $Drives = Get-Volume | Where {$_.DriveLetter -notin $ExcludeDrives -and $_.DriveLetter -ne $null}
    $FoundImages = $Drives | foreach { (Get-ChildItem -Path "$($_.DriveLetter):\" -Recurse -filter "install.wim" -ErrorAction SilentlyContinue).fullname }


    if ($FoundImages.Count -gt 1) {

        $Images = @()
        Foreach ($Image in $FoundImages) {

            $ImageInfo = Get-WindowsImage -ImagePath $Image | Select-Object -Property ImageIndex, ImageName
            $ImageData = $ImageInfo | % { [PSCustomObject]@{ Name = $_.ImageName;  Index = $_.ImageIndex; Path = $Image } }
            $Images += $ImageData

        }
        $SelectedImage = $Images | Out-GridView -OutputMode Single

    } else {
        $ImageInfo = Get-WindowsImage -ImagePath $FoundImages | Select-Object -Property ImageIndex, ImageName | Out-GridView -OutputMode Single
        $SelectedImage = $ImageInfo | % { [PSCustomObject]@{ Name = $_.ImageName;  Index = $_.ImageIndex; Path = $FoundImages } }
    }



    # Expand Selected Server Image
    # ------------------------------------------------------------
    Expand-WindowsImage -ImagePath $SelectedImage.Path -Index $SelectedImage.Index -ApplyPath "$VHDXVolume3\" | Out-Null


    # Make boot files.
    # ------------------------------------------------------------
    & "$VHDXVolume3\Windows\system32\bcdboot.exe" "$VHDXVolume3\Windows" /s "$VHDXVolume1" /f UEFI | Out-Null


    # Find all Server 2025 drivers on all Media drives.
    # ------------------------------------------------------------
    $FoundDrivers = $Drives | foreach { Get-ChildItem -Path "$($_.DriveLetter):\" -Recurse -ErrorAction SilentlyContinue }
    $FoundDrivers = $FoundDrivers | Where {$_.FullName -like "*2K25*" -and $_.FullName -like "*amd*"-and $_.Name -like "*inf"}
    $FoundDrivers = $FoundDrivers | Where {$_.Name -ne "pvpanic-pci.inf" -and $_.Name -ne "smbus.inf"} | Select-Object -Unique

    # Add Drivers
    # ------------------------------------------------------------
    $FoundDrivers | foreach { Add-WindowsDriver -Path "$VHDXVolume3" -Driver $_.FullName } | Out-Null


    # Add default Unattend
    # ------------------------------------------------------------
    if (!(Test-Path -Path "$VHDXVolume3\Windows\Panther")) {
        New-Item -Path "$VHDXVolume3\Windows\Panther" -ItemType Directory | Out-Null
    }
    Get-Content "D:\Windows unattend\Unattend.xml" | Out-File "$VHDXVolume3\Windows\Panther\unattend.xml" -Encoding utf8


    # Add BootStrap script.
    # ------------------------------------------------------------
    if (!(Test-Path -Path "$VHDXVolume3\Scripts")) {
        New-Item -Path "$VHDXVolume3\Scripts" -ItemType Directory | Out-Null
    }
    Copy-Item -Path "D:\Windows unattend\Bootstrap.ps1" -Destination "$VHDXVolume3\Scripts"


    # Offline disk
    # ------------------------------------------------------------
    Get-Disk $VHDDrive.number | Set-Disk -IsOffline $true

}


<#

    Move OS disk back to template and convert.

#>


# Move Disk to template.
# ------------------------------------------------------------
$OrgDiskID = Reassign-PVEOwner -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -SourceNode $MasterID.Node -SourceVM $MasterID.VmID -TargetVM $TemplateID -SourceDisk $TmpDiskID -Wait


# Add virtio0 to boot..
# ------------------------------------------------------------
$Body = "boot=$([uri]::EscapeDataString("order=$OrgDiskID"))"
$null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($MasterID.Node)/qemu/$TemplateID/config" -Body $Body -Method POST -Headers $($PVEConnect.Headers)


# Convert TO template
# ------------------------------------------------------------
$null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($MasterID.Node)/qemu/$TemplateID/template" -Method POST -Headers $($PVEConnect.Headers)
