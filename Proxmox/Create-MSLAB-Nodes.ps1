<# 

    Create 2 Hyper-V servers
    8 vCpu
    32Gb Ram
    100Gb OS Drive
    200GB Data Drive

    Create 3 Azure Local Servers
    8 vCpu
    32Gb Ram
    50Gb OS Drive
    200GB Data Drive
    200GB Data Drive
    200GB Data Drive

    After creation, use the physical/PrepareInstallationMedia.ps1 to create the ISO files neeeded to install the servers.


#>


# The IP is used to define the VMID in Proxmox
# ------------------------------------------------------------
$VMConfig = @(
    [PSCustomObject]@{ Node = "HV-NODE-01"; IPAddress = "10.36.100.211"; Cpu=8; Memory=32; OSDrive=50; DataDrives=@("200") }
    [PSCustomObject]@{ Node = "HV-NODE-02"; IPAddress = "10.36.100.221"; Cpu=8; Memory=32; OSDrive=50; DataDrives=@("200") }
    [PSCustomObject]@{ Node = "AZ-NODE-01"; IPAddress = "10.36.100.231"; Cpu=8; Memory=32; OSDrive=50; DataDrives=@("200","200","200") }
    [PSCustomObject]@{ Node = "AZ-NODE-02"; IPAddress = "10.36.100.241"; Cpu=8; Memory=32; OSDrive=50; DataDrives=@("200","200","200") }
    [PSCustomObject]@{ Node = "AZ-NODE-03"; IPAddress = "10.36.100.251"; Cpu=8; Memory=32; OSDrive=50; DataDrives=@("200","200","200") }
)


# Import PVE modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false
Get-ChildItem -Path "D:\Deployment\Scripts\Proxmox\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


# Connect to PVE Cluster
# ------------------------------------------------------------
$PVEConnect = PVE-Connect -Authkey "root@pam!PowerShell=22c45e34-7a1b-4aa5-bf68-843780db6978" -Hostaddr "10.36.1.27"


# Get information required to create the VMs
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers


foreach ($VM in $VMConfig) {
    
    # Calculate VMID from IP Address
    # ------------------------------------------------------------
    $VMID = (($($($VM.IPAddress) -Split("\."))[1]).PadLeft(2,"0")) + (($($($VM.IPAddress) -Split("\."))[2]).PadLeft(2,"0")) + (($($($VM.IPAddress) -Split("\."))[3]).PadLeft(3,"0"))


    # Default Sever Configuration
    # ------------------------------------------------------------
    $Body = "node=$($PVELocation.Name)"
    $Body += "&vmid=$VMID"
    $Body += "&name=$($VM.Node)"
    $Body += "&bios=ovmf"
    $Body += "&cpu=host"
    $Body += "&ostype=win11"
    $Body += "&machine=pc-q35-10.0+pve1"
    $Body += "&tpmstate0=$([uri]::EscapeDataString("$($PVELocation.storage):1,size=4M,version=v2.0"))"
    $Body += "&efidisk0=$([uri]::EscapeDataString("$($PVELocation.storage):1,efitype=4m,format=raw,pre-enrolled-keys=1"))"
    $Body += "&net0=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1"))"
    $Body += "&net1=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1,link_down=1"))"
    if ($VM.Node -like "AZ-*") {
        $Body += "&net2=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1,link_down=1"))"
        $Body += "&net3=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1,link_down=1"))"
    }
    $Body += "&boot=$([uri]::EscapeDataString("order=scsi0"))"
    $Body += "&scsihw=virtio-scsi-single"
    $Body += "&memory=($($VM.memory)*1024)"
    $Body += "&balloon=2048"
    $Body += "&cores=$($VM.cpu)"


    # Create the Template VM
    # ------------------------------------------------------------
    $VMCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/" -Body $Body -Method POST -Headers $($PVEConnect.Headers)
    Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $VMCreate.data

    foreach ($drive in @($VM.osdrive) + $VM.datadrives) {

        # Add Data drive.
        # ------------------------------------------------------------
        $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $($PVELocation.Name) -VMID $VMID
        
        $DiskCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):$($drive)"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
        Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $DiskCreate.data
    }


    # Add Boot ISO.
    # ------------------------------------------------------------
    $Storage = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/storage" -Method GET -Headers $PVEConnect.Headers
    $Storage = $Storage.data | where {$_.content -like "*iso*" -and $_.type -eq "cifs"}

    $ISOStorage = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/storage/$($Storage.storage)/content" -Method GET -Headers $PVEConnect.Headers
    $ISOFile = $ISOStorage.data | Where {$_.volid -like "*$(($VM.Node).Substring(0,($VM.Node).Length-3))*"}

    if ($ISOFile) {
        $ISOAdd = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/$VMID/config" -Body "ide2=$([uri]::EscapeDataString("$($ISOFile.volid),media=cdrom"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
        Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $ISOAdd.data
    }

}


# Get MAC address from NODE Configuration
# ------------------------------------------------------------
foreach ($Node in $VMConfig) {

    $VMID = ((Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/cluster/resources?type=vm" -Headers $PVEConnect.Headers -Verbose:$false).data | Where {$_.name -eq $node.Node})
    if ($VMID.vmid) {
        $VMStatus = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($VMID.node)/qemu/$($VMID.vmid)/config" -Headers $($PVEConnect.Headers) -Verbose:$false).data
        $Interfaces = $VMStatus.PSObject.Properties | Where {$_.name -like "net*"} | Sort-Object -Property Name
        $Interfaces = $Interfaces | ForEach-Object { $_.Value -split("=|,") | Select-Object -Skip 1 -First 1 }

        Add-Member -InputObject $Node -NotePropertyName 'Interfaces' -NotePropertyValue $Interfaces
    }    
}


Write-Output "Copy the following output to the physical/PrepareInstallationMedia.ps1"
Write-Output "------------------------------------------------------------"
$VMConfig | Foreach {
    Write-Output "[PSCustomObject]@{ Node = `"$($_.Node)`"; IPAddress = `"$($_.IPAddress)`"; Subnet = `"255.255.255.0`"; Gateway = `"10.36.100.1`"; DNSServers = @(`"10.36.100.11`",`"10.36.100.11`"); Interfaces = @(`"$($($_.Interfaces) -join('","'))`") }"
}
Write-Output "------------------------------------------------------------"
