param (
    [cmdletbinding()]
    [Parameter(ValueFromPipeline)]
    [string]$NewVMFQDN,
    [string]$MachineOU,
    [string]$DomainJoin,
    [string]$NewVmIp,
    [Nullable[int]]$vlan=$null,
    [string]$LocalUsername,
    [string]$LocalPassword,
    [int]$VMMemory=4,
    [int]$VMCores=2,
    [string]$OSDisk=50,
    [object]$DefaultConnection=$PVEConnect,
    [object]$DefaultLocation=$PVELocation,
    [switch]$Start
)


$ProductKey     = "N6W6X-H4P77-RJYTG-W77HT-RRKXT"



# Path to PVE scripts and Functions.
# ------------------------------------------------------------
$RootPath       = "D:\Deployment\Scripts\Proxmox"
$ModulesPath    = "D:\Deployment\Scripts\Functions"


<#

    This script creates new VM from selected template, see CreateProdDomain or CreateFabricDomain.



    1. User/script picks target node, storage, and network.

    3. Clone template → new VM.

    4. If required, migrate the VM to the requested node/storage.

    5. Boot....

#>



# Extract Info of the VM created.
# ------------------------------------------------------------
$VMName = $(($NewVMFQDN -split("\."))[0])
$VMID = (($($NewVmIp -Split("\."))[1]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[2]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[3]).PadLeft(3,"0"))
$VmDomain = $(($NewVMFQDN -split("\."))[1..9]) -join(".")
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
        "$(($NewVmIp -split("\."))[0..2] -join(".")).12"
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


# Import module New-ISOFIle.ps1
# - Source : https://github.com/TheDotSource/New-ISOFile/blob/main/New-ISOFile.ps1
# Import New-Unattend-ps1
# ------------------------------------------------------------
Write-Output "Import required modules"
$Modules = @(
    "New-ISOFile.ps1",
    "new-Unattend.ps1"
)
$Modules | ForEach-Object {
    If (Test-Path "$ModulesPath\$($_)") {
        #Write-Output " - $($_)"
        Import-Module -Name "$ModulesPath\$($_)" -Force
    } else {
        Throw "Unable to load required PS Modules"
    }
}



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


# Create AutoUnattend media, and add required scripts.
# ------------------------------------------------------------
If (!(Test-Path -Path "D:\$NewVMFQDN")) {
    New-Item -Path "D:\$NewVMFQDN" -ItemType Directory | Out-Null

    if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT")) {
        New-Item -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT" -ItemType Directory -Force | Out-Null
    }


    # Create Network configuration file
    # ------------------------------------------------------------
    $NetworkData = @()
    $NetworkData += "auto eth0"
    $NetworkData += "iface eth0 inet static"
    $NetworkData += "        address $NewVmIp"
    $NetworkData += "        netmask 255.255.255.0"
    $NetworkData += "        gateway $IPGateway"
    $NetworkData += "        dns-nameservers $($DNSServers -join(" "))"

    $NetworkData | Out-File -FilePath "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000" -Encoding utf8 -Force

    if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\LATEST")) {
        New-Item -Path "D:\$NewVMFQDN\OPENSTACK\LATEST" -ItemType Directory -Force | Out-Null
    }


    # Create Host configuration file
    # ------------------------------------------------------------
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



    if (!(Test-Path -Path "D:\$NewVMFQDN\TS-Data")) {
        New-Item -Path "D:\$NewVMFQDN\TS-Data" -ItemType Directory -Force | Out-Null
    }

    # Find Server Boot Strap file.
    # ------------------------------------------------------------
    $RunAtStartupFile = Get-ChildItem -Path "D:\Deployment\Scripts\Virtual\Server Roles" -Recurse -Filter "$VMName.ps1" -ErrorAction SilentlyContinue
    if (!($RunAtStartupFile)) {
        $FileSearch = "$(($VMName -split("-"))[0])-0x"
        $RunAtStartupFile = Get-ChildItem -Path "D:\Deployment\Scripts\Virtual\Server Roles" -Recurse -Filter "$FileSearch.ps1" -ErrorAction SilentlyContinue
    }
    if ($RunAtStartupFile) {
        Copy-Item -Path $RunAtStartupFile.FullName -Destination "D:\$NewVMFQDN\TS-Data"
    }

    
    # Special, only for Domain Controllers
    # ------------------------------------------------------------
    if ($VMName -eq "ADDS-01") {
        if (Test-Path -Path "D:\Deployment\Scripts\Virtual\Server Roles\AD Tiering.zip") {
            Copy-Item -Path "D:\Deployment\Scripts\Virtual\Server Roles\AD Tiering.zip" -Destination "D:\$NewVMFQDN\TS-Data" -Force
        }
    }
}


New-ISOFile -source "D:\$NewVMFQDN" -destinationIso "D:\ISOfiles\template\iso\$NewVMFQDN.iso" -title "Unattend Media" -force | Out-Null

#Remove-Item -Path "D:\$NewVMFQDN" -Recurse -Force


# Upload ISO.
#$ISOStorage = ((Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage" -Headers $PVEConnect.Headers -Verbose:$false).data | Where {$_.content -like "*iso*" -and $_.type -eq "dir"}).storage
#$null = Upload-PVEISO -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $($PVEConnect.Headers) -Node $($PVELocation.name) -Storage $ISOStorage -IsoPath "D:\$NewVMFQDN.iso"


# Wait for clone...
# ------------------------------------------------------------
Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.name) -taskid $VMCreate.data


# Add Iso to NewVM
$Body = "node=$($PVELocation.name)"
#$Body += "&ide2=$([uri]::EscapeDataString("local:iso/$NewVMFQDN.iso,media=cdrom"))"
$Body += "&ide2=$([uri]::EscapeDataString("ISOfiles:iso/$NewVMFQDN.iso,media=cdrom"))"
$null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers -Verbose:$false


# Modify Boot sequence.
$Body = "boot=$([uri]::EscapeDataString("order=scsi0"))"
$null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Method POST -Headers $PVEConnect.Headers -Verbose:$false


<# 

    Modify New VM depending on selections..

#>


# Get VM Configuration prior to updates / changes
# ------------------------------------------------------------
Write-Verbose "Proxmox: Change VM configuration"
$VMStatus = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Headers $PVEConnect.Headers -Verbose:$false).data


# Set VLan if needed
# ------------------------------------------------------------
if ($null -ne $VLan) {
    $NetAdapters = $VMStatus.PSObject.Properties | Where {$_.name -like "net*"}

    $Body = ""
    $NetAdapters | ForEach-Object {
        if ($_ -match ",tag=\d+$") {
            $Body += "$($_.name)=$([uri]::EscapeDataString($($($_.Value) -replace("\d+$","$Vlan"))))&"
        } else {
            $Body += "$($_.name)=$([uri]::EscapeDataString("$($_.Value),tag=$VLan"))&"
        }
    }
    $Body = $Body -replace("&$","")
    
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Method Put -Headers $PVEConnect.Headers -Verbose:$false
}



# Change CPU Count if needed
# ------------------------------------------------------------
if ($VMStatus.cores -ne $VMCores) {
    Write-Verbose "Proxmox: Update CPU Cores"

    $body = "cores=$VMCores"
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $PVEConnect.Headers -Verbose:$false

}

# Change Memory Size if needed
# ------------------------------------------------------------
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
        {$_ -like "File-0*" -or $_ -like "*RDDB-*"} {
            
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
if ($Start) {
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/status/start" -Headers $PVEConnect.Headers -Method POST -Verbose:$false
}

Write-Verbose "Script end: $(Get-Date)"
