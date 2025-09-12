<#

    Default PROXMOX data

#>
#region connection

# HTTP Headers for connection.
# ------------------------------------------------------------
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "PVEAPIToken=root@pam!Powershell=16dcf2b5-1ca1-41cd-9e97-3c1d3d308ec0")
$headers.Add("Accept", "application/json")


# Ignore Self Signed Cert.
# ------------------------------------------------------------
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


# Proxmox API address.
# ------------------------------------------------------------
$ProxmoxAPI = "https://10.36.1.27:8006/api2/json"


# Get NODE info
# ------------------------------------------------------------
Write-Verbose "Get Proxmox Node"
Try {
    $ThisNode = ((Invoke-WebRequest -Uri "$ProxmoxAPI/cluster/status" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data | Where {$_.nodeid -eq "1"}
}
Catch {
    $ThisNode = $null; $_        
}

Write-Verbose "Get Proxmox Storage"
Try {
    $Storage = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/storage" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data | Where {$_.content -like "*images*"}
}
Catch {
    $Storage = $null; $_
}
if ($Storage.count -gt 1) {
    $Storage = $Storage | Out-GridView -OutputMode Single
}

Write-Verbose "Get Proxmox Network Zone"
Try {
    $Zone = (((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/sdn/zones" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data).zone
}
Catch {
    $Zone = $null; $_
}

if ($null -ne $Zone) {
    Write-Verbose "Get Proxmox Vnet"
    Try {
        $Switch = (((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/sdn/zones/$Zone/content" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data).vnet
    }
    Catch {
        $Switch = $null; $_
    }
} else {
    Write-Verbose "Get Proxmox Bridge"
    Try {
        $Switch = (((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/network" -Method Get -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data | where {$_.Type -eq "bridge"}).iface
    }
    Catch {
        $Switch = $null; $_
    }
}
if ($Null -eq $DefaultSwitch) {
    if ($Switch.count -gt 1) {
        $Switch = $Switch | Out-GridView -OutputMode Single
    }
} else {
    $Switch = $Switch | Where {$_ -eq $DefaultSwitch}
}


# Get Id of Deployment server....
# ------------------------------------------------------------
$AllVMs = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/" -Headers $headers | ConvertFrom-Json)[0]).data
$MasterID = ($AllVMs | Where {$_.name -like "LAB-Deploy*"}).vmid
#$MasterID = 100

#endregion


# Info of the VM created.
# ------------------------------------------------------------
$VMName = "2025-Desktop"
$Memory = 8*1024
$Cores = 4
$OSDisk = 50
$vmid = 2025


# Configure and create VM
# ------------------------------------------------------------
$body = "node=$($ThisNode.name)"
$body += "&vmid=$vmid"
$body += "&name=$(($VMName -split("\."))[0])"
$body += "&bios=ovmf"
$body += "&cpu=host"
$body += "&ostype=win11"
$body += "&machine=pc-q35-9.0"
$body += "&tpmstate0=$([uri]::EscapeDataString("$($Storage.storage):1,size=4M,version=v2.0"))"
$body += "&efidisk0=$([uri]::EscapeDataString("$($Storage.storage):1,efitype=4m,format=raw,pre-enrolled-keys=1"))"
$body += "&net0=$([uri]::EscapeDataString("virtio,bridge=$Switch,firewall=1"))"
$body += "&boot=$([uri]::EscapeDataString("order=net0"))"
$Body += "&scsihw=virtio-scsi-single"
$body += "&memory=$Memory"
$body += "&balloon=2048"
$body += "&cores=$Cores"
$body += "&scsi0=$([uri]::EscapeDataString("$($Storage.storage):$($OSDisk),format=raw"))"
$body += "&ide2=$([uri]::EscapeDataString("none,media=cdrom"))"


# Execute the create command..
# ------------------------------------------------------------
$null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/" -Body $body -Method Post -Headers $headers 



# Ensure VM exists prior to continiue
# ------------------------------------------------------------
Write-Host "Create"
for ($i=0; $i -le 1000; $i++) {
    try {
        $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers | ConvertFrom-Json)[0]).data
        if ($VMStatus.scsi0) {
            break
        } else {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }
    }
    catch {
    }
}


# Unmount disk

$body = "delete=scsi0"
$null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $headers 

# Ensure disk is unmounted.
# ------------------------------------------------------------
for ($i=0; $i -le 1000; $i++) {
    try {
        $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers | ConvertFrom-Json)[0]).data
        if ($VMStatus.unused0) {
            break
        } else {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }
    }
    catch {
    }
}


# Ensure TARGET disk is dont exist.
# ------------------------------------------------------------
for ($i=0; $i -le 1000; $i++) {
    try {
        $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/config" -Headers $headers | ConvertFrom-Json)[0]).data
        if (!($VMStatus.virtio5)) {
            break
        } else {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }
    }
    catch {
    }
}

# mount disk on "Deployment"
$body = "vmid=$VMID"
$body += "&target-vmid=$MasterID"
$body += "&disk=unused0"
$body += "&target-disk=scsi5"
$null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/move_disk" -Body $body -Method Post -Headers $headers 


# Ensure TARGET disk is dont exist.
# ------------------------------------------------------------
for ($i=0; $i -le 1000; $i++) {
    try {
        $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/config" -Headers $headers | ConvertFrom-Json)[0]).data
        if ($VMStatus.scsi5) {
            break
        } else {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }
    }
    catch {
    }
}


# Initialize disk, and create UEFI partions
# ------------------------------------------------------------
$VHDDrive = Get-Disk | Where {$_.partitionstyle -eq 'RAW' -and $_.Size -eq 50Gb }
Initialize-Disk -Number $VHDDrive.number -PartitionStyle GPT

Get-Partition -DiskNumber $VHDDrive.number | Remove-Partition -Confirm:$false

$VHDXDrive1 = New-Partition -DiskNumber $VHDDrive.number -GptType  "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" -AssignDriveLetter -Size 100Mb
$VHDXDrive1 | Format-Volume -FileSystem FAT32 -NewFileSystemLabel System -Confirm:$false | Out-null

$VHDXDrive2 = New-Partition -DiskNumber $VHDDrive.number -GptType "{e3c9e316-0b5c-4db8-817d-f92df00215ae}" -Size 16Mb


$VHDXDrive3 = New-Partition -DiskNumber $VHDDrive.number -UseMaximumSize -AssignDriveLetter
$VHDXDrive3 | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false | Out-null


# Add Drive letters
# ------------------------------------------------------------
#Add-PartitionAccessPath -DiskNumber $VHDDrive.number -PartitionNumber $VHDXDrive1.PartitionNumber -AssignDriveLetter
$VHDXDrive1 = Get-Partition -DiskNumber $VHDDrive.number -PartitionNumber $VHDXDrive1.PartitionNumber
$VHDXVolume1 = [string]$VHDXDrive1.DriveLetter+":"

#Add-PartitionAccessPath -DiskNumber $VHDDrive.number -PartitionNumber $VHDXDrive3.PartitionNumber -AssignDriveLetter
$VHDXDrive3 = Get-Partition -DiskNumber $VHDDrive.number -PartitionNumber $VHDXDrive3.PartitionNumber
$VHDXVolume3 = [string]$VHDXDrive3.DriveLetter+":"



## Get DVD drive letter of Windows Install media..
## ------------------------------------------------------------
##[string]$ImagePath = Get-Volume | Where-Object {$_.drivetype -eq 'CD-ROM'} | foreach { (Get-ChildItem -Path "$($_.DriveLetter):" -Recurse -filter "install.wim").fullname }

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
    $SelectedImage = $FoundImages
}


# List Server images
# ------------------------------------------------------------
$ImageIndex = (Get-WindowsImage -ImagePath $SelectedImage | Select-Object -Property ImageIndex, ImageName | Out-GridView -OutputMode Single).ImageIndex



## Exclude Path from Defender to speed up the process !!



# Expand Server 2025 Standard with Desktop
# ------------------------------------------------------------
Expand-WindowsImage -ImagePath $SelectedImage -Index $ImageIndex -ApplyPath "$VHDXVolume3\"


# Make boot files.. (comvert to powershell)
# ------------------------------------------------------------
cmd /c "$VHDXVolume3\Windows\system32\bcdboot $VHDXVolume3\Windows /s $VHDXVolume1 /f UEFI"


<#
# Export installed drivers from running system....
# ------------------------------------------------------------
Export-WindowsDriver -Online -Destination C:\TS-Data\test
#>
#Add-WindowsDriver -Path "$VHDXVolume3" -Driver "C:\TS-Data\test" -Recurse


# Find all Server 2025 drivers on all Media drives.
# ------------------------------------------------------------
#$Drivers = $(Get-Volume | Where-Object {$_.drivetype -eq 'CD-ROM'} | foreach { Get-ChildItem -Path "$($_.DriveLetter):" -Recurse })

$FoundDrivers = $Drives | foreach { Get-ChildItem -Path "$($_.DriveLetter):\" -Recurse -ErrorAction SilentlyContinue }
$FoundDrivers = $FoundDrivers | Where {$_.FullName -like "*2K25*" -and $_.FullName -like "*amd*"-and $_.Name -like "*inf"}
$FoundDrivers = $FoundDrivers | Where {$_.Name -ne "pvpanic-pci.inf" -and $_.Name -ne "smbus.inf"} | Select-Object -Unique

# Add Drivers
# ------------------------------------------------------------
$FoundDrivers | foreach { Add-WindowsDriver -Path "$VHDXVolume3" -Driver $_.FullName } | Out-Null


<#
# List installed drivers
# ------------------------------------------------------------
((Get-WindowsDriver -Path "$VHDXVolume3") | Select-Object ClassName, OriginalFileName).count

(Get-WindowsDriver -Path "$VHDXVolume3\").OriginalFileName

#>


# Add default Unattend
if (!(Test-Path -Path "$VHDXVolume3\Windows\Panther")) {
    New-Item -Path "$VHDXVolume3\Windows\Panther" -ItemType Directory | Out-Null
}
Get-Content "D:\Server Configs\SimpleUnattend.xml" | Out-File "$VHDXVolume3\Windows\Panther\unattend.xml" -Encoding utf8
#$UnattendXml | Out-File -FilePath "$VHDXVolume3\Windows\Panther\unattend.xml" -Encoding utf8


# Add BootStrap script.
if (!(Test-Path -Path "$VHDXVolume3\Scripts")) {
    New-Item -Path "$VHDXVolume3\Scripts" -ItemType Directory | Out-Null
}
Copy-Item -Path "D:\Server Configs\Bootstrap.ps1" -Destination "$VHDXVolume3\Scripts"





# Next Offline disk
Get-Disk $VHDDrive.number | Set-Disk -IsOffline $true


$body = "delete=scsi5"
$null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/config" -Body $body -Method Post -Headers $headers 


# Ensure disk is unmounted.
# ------------------------------------------------------------
for ($i=0; $i -le 1000; $i++) {
    try {
        $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/config" -Headers $headers | ConvertFrom-Json)[0]).data
        if ($VMStatus.unused0) {
            break
        } else {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }
    }
    catch {
    }
}

# Ensure TARGET disk is dont exist.
# ------------------------------------------------------------
for ($i=0; $i -le 1000; $i++) {
    try {
        $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers | ConvertFrom-Json)[0]).data
        if (!($VMStatus.scsi0)) {
            break
        } else {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }
    }
    catch {
    }
}

# mount disk on "Server"
$body = "vmid=$MasterID"
$body += "&target-vmid=$VMID"
$body += "&disk=unused0"
$body += "&target-disk=scsi0"
$null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/move_disk" -Body $body -Method Post -Headers $headers 

for ($i=0; $i -le 1000; $i++) {
    try {
        $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers | ConvertFrom-Json)[0]).data
        if ($VMStatus.scsi0) {
            break
        } else {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        }
    }
    catch {
    }
}

# Add virtio0 to boot..
$body = "boot=$([uri]::EscapeDataString("order=scsi0"))"
$null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $headers 


## 
# Convert TO template
$null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/template" -Method Post -Headers $headers 
