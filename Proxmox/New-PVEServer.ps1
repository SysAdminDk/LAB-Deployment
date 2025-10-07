param (
    [cmdletbinding()]
    [Parameter(ValueFromPipeline)]
    [string]$NewVMFQDN,
    [string]$MachineOU,
    [string]$DomainJoin,
    [string]$NewVmIp,
    [string]$LocalUsername,
    [string]$LocalPassword,
    [int]$VMMemory,
    [int]$VMCores,
    [string]$OSDisk,
    [object]$DefaultConnection,
    [object]$DefaultLocation,
    [switch]$Start
)

$RootPath = "D:\PVE Scripts"

<#

    1. User/script picks target node, storage, and network.

    3. Clone template → new VM.

    4. If required, migrate the VM to the requested node/storage.

    5. Boot....

#>



# Extract Info of the VM created.
# ------------------------------------------------------------
$VMName = $(($NewVMFQDN -split("\."))[0])
$VMID = (($($NewVmIp -Split("\."))[1]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[2]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[3]).PadLeft(3,"0"))
$VmDomain = $(($NewVMFQDN -split("\."))[1..99]) -join(".")
$IPGateway = "$(($($NewVmIp -Split("\."))[0..2]) -join(".")).1"

if ($null -eq $VMID) {
    $VMID = Get-Random -Minimum 88888888 -Maximum 99999999
}


# Define DNS servers
# ------------------------------------------------------------
if ($NewVMFQDN -Like "ADDS-01*") {
    $DNSServers = @("8.8.8.8", "8.8.4.4")
} else {
    $DNSServers = @(
        "$(($NewVmIp -split("\."))[0..2] -join(".")).11",
        "$(($NewVmIp -split("\."))[0..2] -join(".")).12",
        "$(($NewVmIp -split("\."))[0..2] -join(".")).13"
    )
}



<#

    Default PROXMOX data

#>
Write-Verbose "Script begin: $(Get-Date)"


# Import PVE modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false
Get-ChildItem -Path "$RootPath\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


if (!($DefaultConnection)) {
    # Connect to PVE Cluster
    # ------------------------------------------------------------
    $PVESecret = Get-Content "$RootPath\PVE-Secret.json" | Convertfrom-Json
    $PVEConnect = PVE-Connect -Authkey "$($PVESecret.User)!$($PVESecret.TokenID)=$($PVESecret.Token)" -Hostaddr $($PVESecret.Host)
} else {
    $PVEConnect = $DefaultConnection
}



# Get the Deployment server info
# ------------------------------------------------------------
If (!($DefaultLocation)) {
    $MasterServer = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "LAB-Deploy"
}




if (!($DefaultLocation)) {
    $PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -IncludeNode $MasterServer.Node
} else {
    $PVELocation = $DefaultLocation
}




<#

    Verify Deployment and Template is on same NODE

#>


# Find all templates
# ------------------------------------------------------------
If (!($DefaultLocation)) {
	$Templates = Get-PVETemplates -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers | Where {$_.node -eq $MasterServer.Node}
} else {
	$Templates = Get-PVETemplates -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers | Where {$_.node -eq $PVELocation.Name}
}


# Select the template to use.
# ------------------------------------------------------------
if ($Templates.Count -gt 1) {
    # Stupid OutGridview thinks the VMID is a number that need a thousands separator!
    $SelectedVMTemplate = $Templates | Select-Object @{Name="VmID"; Expression={ "$($_.vmid)"}},name,Node | Out-GridView -Title "Select VM template to use" -OutputMode Single
} else {
    $SelectedVMTemplate = $Templates
}

# If NO template, FAIL
# ------------------------------------------------------------
if (!($SelectedVMTemplate)) {
    Throw "No VM Template found or selected"
}



# Verify and Move Template if required.
# ------------------------------------------------------------
If ($MasterServer.Node -ne $SelectedVMTemplate.Node) {

#    # Move Template..
#    # ------------------------------------------------------------
#    #Move-PVEVM -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -SourceNode $SelectedVMTemplate.Node -TargetNode $MasterServer.Node -VMID $SelectedVMTemplate.VmID -Wait

# Switch to template on same node..

}



<#

    Create VM

#>

$AllVMIDs = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/cluster/resources?type=vm" -Headers $PVEConnect.Headers -Verbose:$false).data | Select-Object vmid, name
if ($AllVMIDs.vmid -contains $VMID) {
    throw "VMID already in use."

}

# Configure and create VM
# ------------------------------------------------------------
Write-Verbose "Proxmox: Create new VM: $VMName"


# Clone Template
# ------------------------------------------------------------
$VMCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$($SelectedVMTemplate.VmID)/clone" -Body "newid=$VMID&name=$NewVMFQDN&full=1&storage=$($PVELocation.storage)" -Method Post -Headers $PVEConnect.Headers -Verbose:$false

# Wait for clone...
# ------------------------------------------------------------
Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.name) -taskid $VMCreate.data


# Add Cloud Init drive, with bare minimum data.
# ------------------------------------------------------------
#$Body = "node=$($PVELocation.name)"
#$Body += "&ide2=$($PVELocation.Storage):cloudinit"
#$null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers


# Set bare minimum data in Cloud Init.
# ------------------------------------------------------------
#$Body = "node=$($PVELocation.name)"
#$Body += "&citype=configdrive2"
#$Body += "&ciuser=$LocalUsername"
#$Body += "&cipassword=$LocalPassword"
#$Body += "&searchdomain=$VmDomain"
#$Body += "&nameserver=$DNSServers"
#$Body += "&ipconfig0=$([uri]::EscapeDataString("ip=$NewVmIp/24,gw=$IPGateway"))"
#
#$null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers
#
#$null = Invoke-RestMethod -Method PUT -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/cloudinit" -Headers $PVEConnect.Headers


# Create AutoUnattend media, and add required scripts.
# ------------------------------------------------------------
If (!(Test-Path -Path "D:\$NewVMFQDN")) {
    New-Item -Path "D:\$NewVMFQDN" -ItemType Directory | Out-Null

    if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT")) {
        New-Item -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT" -ItemType Directory -Force | Out-Null
    }

    $NetworkData = @()
    $NetworkData += "auto eth0`r`n"
    $NetworkData += "iface eth0 inet static`r`n"
    $NetworkData += "        address $NewVmIp`r`n"
    $NetworkData += "        netmask 255.255.255.0`r`n"
    $NetworkData += "        gateway $IPGateway`r`n"
    $NetworkData += "        dns-nameservers $($DNSServers -join(" "))`r`n"

    $NetworkData | Out-File -FilePath "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000" -Encoding utf8 -Force

    if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\LATEST")) {
        New-Item -Path "D:\$NewVMFQDN\OPENSTACK\LATEST" -ItemType Directory -Force | Out-Null
    }

    $HostConfig = @()
    $HostConfig += "#cloud-config"
    $HostConfig += "hostname: $VMName"
    $HostConfig += "manage_etc_hosts: true"
    $HostConfig += "fqdn: $NewVMFQDN"
    $HostConfig += "user: $LocalUsername"
    $HostConfig += "password: $LocalPassword"
    $HostConfig += "chpasswd:"
    $HostConfig += "  expire: False"
    $HostConfig += "users:"
    $HostConfig += "  - default"
    $HostConfig += "package_upgrade: true"
    if ($MachineOU) {
        $HostConfig += "MachineOU: $MachineOU"
    }
    if ($DomainJoin) {
        $HostConfig += "DomainJoin: $DomainJoin"
    }
    $HostConfig | Out-File -FilePath "D:\$NewVMFQDN\OPENSTACK\LATEST\USER_DATA" -Encoding utf8 -Force


    if (!(Test-Path -Path "D:\$NewVMFQDN\Windows DSC")) {
        New-Item -Path "D:\$NewVMFQDN\Windows DSC" -ItemType Directory | Out-Null
    }
    Copy-Item -Path "D:\Server Roles" -Destination "D:\$NewVMFQDN\Windows DSC" -Recurse | Out-Null

    if ($VMName -eq "ADDS-01") {
        Copy-Item -Path "D:\TS-Data\ADTiering.zip" -Destination "D:\$NewVMFQDN" -Force
    }
}

New-ISOFileFromFolder -FilePath "D:\$NewVMFQDN" -Name "Unattend Media" -ResultFullFileName "D:\$NewVMFQDN.iso"

Remove-Item -Path "D:\$NewVMFQDN" -Recurse -Force

# Upload ISO.
$ISOStorage = ((Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage" -Headers $PVEConnect.Headers -Verbose:$false).data | Where {$_.content -like "*iso*"}).storage
$null = Upload-PVEISO -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $($PVEConnect.Headers) -Node $($PVELocation.name) -Storage $ISOStorage -IsoPath "D:\$NewVMFQDN.iso"

# Add Iso to NewVM
$Body = "node=$($PVELocation.name)"
$Body += "&ide2=$([uri]::EscapeDataString("local:iso/$NewVMFQDN.iso,media=cdrom"))"
$null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers -Verbose:$false


# Modify Boot sequence.
$Body = "boot=$([uri]::EscapeDataString("order=scsi0"))"
$null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Method POST -Headers $PVEConnect.Headers -Verbose:$false



<# 

    Modify New VM depending on selections..

#>


# Change Disk size, amount memory and cpu if needed
# ------------------------------------------------------------
Write-Verbose "Proxmox: Change VM configuration"
$VMStatus = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Headers $PVEConnect.Headers -Verbose:$false).data


if ($VMStatus.cores -ne $VMCores) {
    Write-Verbose "Proxmox: Update CPU Cores"

    $body = "cores=$VMCores"
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $PVEConnect.Headers -Verbose:$false

}


if ([math]::Round($($VMMemory * 1KB)) -ne $VMStatus.memory) {
    Write-Verbose "Proxmox: Update Memory size"

    $body = "memory=$($VMMemory*1KB)"
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $PVEConnect.Headers -Verbose:$false

}

# Calculate if OSDisk size differs, and change if needed.
# ------------------------------------------------------------
$OSDiskSize = ($VMStatus.((($VMStatus.boot -split("="))[-1] -split(";"))[0]) -split("="))[-1]+"b"
$SizeDiff = [math]::round($OSDisk - $OSDiskSize) / 1Gb


if ($SizeDiff -gt 0) {
    Write-Verbose "Proxmox: Update Disk size"

    $body = "disk=$($CurrentOSDisk.name)&size=$($OSDisk.ToLower().replace("gb","G"))"
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/resize" -Body $body -Method Put -Headers $PVEConnect.Headers -Verbose:$false

}



<#

    Add Extra Disks depending on server type.

#>


if ($VmDomain -ne "Workgroup") {

        switch ($VMName) {
        {$_ -like "ADDS-*"} {

            # Add 100Gb Backup Drive to All Domain Controllers.
            # ------------------------------------------------------------
            $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $PVELocation.name -VMID $VMID

            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):100"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
            $VMDiskCount++

        }
        {$_ -like "File-0*" -or $_ -like "*RDDB-*" -or $_ -like "*ADDS-*"} {
            
            # Add 10Gb Log Drive and 100Gb Data Drive to File Cluster and SQL Cluster
            # ------------------------------------------------------------
            $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $PVELocation.name -VMID $VMID

            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):20"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
            $VMDiskCount++

            $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $PVELocation.name -VMID $VMID

            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):100"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
            $VMDiskCount++

        }
    }
}


# Start new server
# ------------------------------------------------------------
$null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/status/start" -Headers $PVEConnect.Headers -Method POST -Verbose:$false

Write-Verbose "Script end: $(Get-Date)"
