<# 

    Create 2 Hyper-V servers
    8 vCpu
    32Gb Ram
    50Gb OS Drive
    400GB Data Drive

    Create 5 Azure Local Servers
    8 vCpu
    32Gb Ram
    50Gb OS Drive
    5 x 500GB Data Drive

    After creation, use the physical/PrepareInstallationMedia.ps1 to create the ISO files neeeded to install the servers.


#>


# Path to PVE scripts and Functions.
# ------------------------------------------------------------
$RootPath = "D:\Proxmox Scripts"


# The IP is used to define the VMID in Proxmox
# ------------------------------------------------------------
$VMConfig = @(
    # 1 = Gateway
    # 11 - 100 Fabric Domain Servers / Services.

#    [PSCustomObject]@{ Node = "HV-NODE-01"; IPAddress = "10.36.200.211"; Subnet="255.255.255.0"; Gateway="10.36.200.1"; DNSServers=@("1.1.1.1","1.0.0.1"); Cpu=8;  Memory=32; OSDrive=50;  DataDrives=@("400") }
#    [PSCustomObject]@{ Node = "HV-NODE-02"; IPAddress = "10.36.200.212"; Subnet="255.255.255.0"; Gateway="10.36.200.1"; DNSServers=@("1.1.1.1","1.0.0.1"); Cpu=8;  Memory=32; OSDrive=50;  DataDrives=@("400") }

    [PSCustomObject]@{ Node = "AZ-NODE-01"; IPAddress = "10.36.200.221"; Subnet="255.255.255.0"; Gateway="10.36.200.1"; DNSServers=@("10.36.200.11","10.36.200.12"); Cpu=12; Memory=48; OSDrive=100; DataDrives=@("500","500","500","500","500","500") }
    [PSCustomObject]@{ Node = "AZ-NODE-02"; IPAddress = "10.36.200.222"; Subnet="255.255.255.0"; Gateway="10.36.200.1"; DNSServers=@("10.36.200.11","10.36.200.12"); Cpu=12; Memory=48; OSDrive=100; DataDrives=@("500","500","500","500","500","500") }
    [PSCustomObject]@{ Node = "AZ-NODE-03"; IPAddress = "10.36.200.223"; Subnet="255.255.255.0"; Gateway="10.36.200.1"; DNSServers=@("10.36.200.11","10.36.200.12"); Cpu=12; Memory=48; OSDrive=100; DataDrives=@("500","500","500","500","500","500") }
#   [PSCustomObject]@{ Node = "AZ-NODE-04"; IPAddress = "10.36.200.224"; Subnet="255.255.255.0"; Gateway="10.36.200.1"; DNSServers=@("10.36.200.11","10.36.200.12"); Cpu=12; Memory=48; OSDrive=100; DataDrives=@("500","500","500","500","500","500") }
#   [PSCustomObject]@{ Node = "AZ-NODE-05"; IPAddress = "10.36.200.225"; Subnet="255.255.255.0"; Gateway="10.36.200.1"; DNSServers=@("10.36.200.11","10.36.200.12"); Cpu=12; Memory=48; OSDrive=100; DataDrives=@("500","500","500","500","500","500") }

    # 231 - 240 Azure Range

)


# Import PVE modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false
Get-ChildItem -Path "$RootPath\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


# Connect to PVE Cluster
# ------------------------------------------------------------
$PVESecret = Get-Content "$RootPath\PVE-Secret.json" | Convertfrom-Json
$PVEConnect = PVE-Connect -Authkey "$($PVESecret.User)!$($PVESecret.TokenID)=$($PVESecret.Token)" -Hostaddr $($PVESecret.Host)


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
    $Body += "&machine=$([uri]::EscapeDataString("pc-q35-10.0+pve1"))"
    $Body += "&tpmstate0=$([uri]::EscapeDataString("$($PVELocation.storage):1,size=4M,version=v2.0"))"
    $Body += "&efidisk0=$([uri]::EscapeDataString("$($PVELocation.storage):1,efitype=4m,format=raw,pre-enrolled-keys=1"))"
    $Body += "&net0=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1,tag=200"))"
    $Body += "&net1=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1,link_down=1,tag=200"))"
    if ($VM.Node -like "AZ-*") {
        $Body += "&net2=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1,link_down=1"))"
        $Body += "&net3=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1,link_down=1"))"
    }
    $Body += "&boot=$([uri]::EscapeDataString("order=scsi0"))"
    $Body += "&scsihw=virtio-scsi-single"
    $Body += "&memory=$($($VM.memory)*1024)"
    $Body += "&balloon=2048"
    $Body += "&cores=$($VM.cpu)"


    # Create the Template VM
    # ------------------------------------------------------------
    $VMCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/" -Body $Body -Method POST -Headers $($PVEConnect.Headers)
    Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $VMCreate.data


    # Add OS drive.
    # ------------------------------------------------------------
    $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $($PVELocation.Name) -VMID $VMID
        
    $DiskCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):$($VM.osdrive),ssd=1"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
    Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $DiskCreate.data


    # Add Data drives.
    # ------------------------------------------------------------
    foreach ($drive in $VM.datadrives) {

        # Add Data drive. ( Please note for AZ-Local Data Drives MUST be SATA )
        # ------------------------------------------------------------
        if ($($VM.Node) -like "AZ*") {
            $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $($PVELocation.Name) -VMID $VMID -DiskType sata
        } else {
            $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $($PVELocation.Name) -VMID $VMID
        }
        
        $DiskCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):$($drive)"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
        Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $DiskCreate.data
    }


    # Add Disk Serial number.
    # ------------------------------------------------------------
    $VMStatus = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/$($VMID)/config" -Headers $($PVEConnect.Headers) -Verbose:$false).data
    $DiskData = $VMStatus.PSObject.Properties | Where {$_.name -match 'scsi\d+$|sata\d+$' -and $_.value -notlike "*serial*"}
   
    $DiskData | ForEach-Object {
        $Body = "$($_.name)=$([uri]::EscapeDataString("$($_.value),serial=$(($($_.value) -split(":|,"))[1])"))"
        $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/$VMID/config" -Body $Body -Method Post -Headers $PVEConnect.Headers -Verbose:$false
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


# Get MAC address from Created NODES Configuration
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



# Save Node information JSON, with MAC addresses.
# ------------------------------------------------------------
$VMConfig | where {$_.Node -like "HV*"} | Select-Object Node,IpAddress,Subnet,Gateway,DNSServers,Interfaces | ConvertTo-Json | `
    Out-File "$(Split-Path -Path $RootPath -Parent)\Physical Servers\Hyper-V\HV-Nodes.json"

$VMConfig | where {$_.Node -like "AZ*"} | Select-Object Node,IpAddress,Subnet,Gateway,DNSServers,Interfaces | ConvertTo-Json | `
    Out-File "$(Split-Path -Path $RootPath -Parent)\Physical Servers\Azure Local\AZ-Nodes.json"
