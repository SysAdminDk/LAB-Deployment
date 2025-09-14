param (
    [cmdletbinding()]
    [Parameter(ValueFromPipeline)]
    [string]$NewVMFQDN="ADDS-01.Fabric.SecInfra.Dk",
    [string]$MachineOU=$null,
    [string]$NewVmIp="10.36.100.11",
    [string]$LocalUsername="Administrator",
    [string]$LocalPassword="P@ssword2025.!!",
    [int]$VMMemory=4,
    [int]$VMCores=2,
    [string]$OSDisk="50Gb",
    [object]$DefaultConnection,
    [object]$DefaultLocation,
    [switch]$Start
)



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

## Include Proxmox Connect script.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Get-ChildItem -Path ".\Functions" | ForEach-Object { Import-Module -Name $_.FullName -force }


if (!($DefaultConnection)) {
    $PVEConnect = PVE-Connect -Authkey "root@pam!Powershell=16dcf2b5-1ca1-41cd-9e97-3c1d3d308ec0" -Hostaddr "10.36.1.27"
} else {
    $PVEConnect = $DefaultConnection
}



# Get the Deployment server info
# ------------------------------------------------------------
$MasterServer = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "LAB-Deploy"




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
$Templates = Get-PVETemplates -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers | Where {$_.node -eq $MasterServer.Node}



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


$AllVMIDs = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu" -Headers $PVEConnect.Headers).data | Select-Object vmid, name
if ($AllVMIDs.vmid -contains $VMID) {
    throw "VMID already in use."

}

# Configure and create VM
# ------------------------------------------------------------
Write-Verbose "Proxmox: Create new VM: $VMName"
$VMCreate=$null
$VMStatus=$null

#try {
#    $VMStatus = ((Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Headers $PVEConnect.Headers -Verbose:$false | ConvertFrom-Json)[0]).data
#}
#catch {
#    try {
        # Clone template
        $VMCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$($SelectedVMTemplate.VmID)/clone" -Body "newid=$VMID&name=$NewVMFQDN&full=1&storage=$($PVELocation.storage)" -Method Post -Headers $PVEConnect.Headers -Verbose:$false

        # Wait for clone...
        Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.name) -taskid $VMCreate.data
#    }
#    catch {
#    }
#}


# Add Cloud Init drive, with bare minimum data.
# ------------------------------------------------------------
$Body = "node=$($PVELocation.name)"
$Body += "&ide2=$($PVELocation.Storage):cloudinit"
$null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers


# Set bare minimum data in Cloud Init.
# ------------------------------------------------------------
$Body = "node=$($PVELocation.name)"
$Body += "&citype=configdrive2"
$Body += "&ciuser=$LocalUsername"
$Body += "&cipassword=$LocalPassword"
$Body += "&searchdomain=$VmDomain"
$Body += "&nameserver=$DNSServers"
$Body += "&ipconfig0=$([uri]::EscapeDataString("ip=$NewVmIp/24,gw=$IPGateway"))"

$null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers

$null = Invoke-RestMethod -Method PUT -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/cloudinit" -Headers $PVEConnect.Headers


<# 

    Modify New VM depending on selections..

#>


# Change Disk size, amount memory and cpu if needed
# ------------------------------------------------------------
Write-Verbose "Proxmox: Change VM configuration"
$VMStatus = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Headers $PVEConnect.Headers).data

if ($VMStatus.cores -ne $VMCores) {
    Write-Verbose "Proxmox: Update CPU Cores"

    $body = "cores=$VMCores"
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $PVEConnect.Headers

}


if ([math]::Round($($VMMemory * 1KB)) -ne $VMStatus.memory) {
    Write-Verbose "Proxmox: Update Memory size"

    $body = "memory=$($VMMemory*1KB)"
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $PVEConnect.Headers

}

# Calculate if OSDisk size differs, and change if needed.
# ------------------------------------------------------------
$OSDiskSize = (($VMStatus.(($VMStatus.boot -split("="))[-1]) -split("="))[-1]+"b")
$SizeDiff = [math]::round($OSDisk - $OSDiskSize) / 1Gb


if ($SizeDiff -gt 0) {
    Write-Verbose "Proxmox: Update Disk size"

    $body = "disk=$($CurrentOSDisk.name)&size=$($OSDisk.ToLower().replace("gb","G"))"
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/resize" -Body $body -Method Put -Headers $PVEConnect.Headers 

}



<#

    Add Extra Disks depending on server type.

#>

if ($VmDomain -ne "Workgroup") {

    $LastVMDisk = [String](($VMStatus.PSObject.Properties | Where-Object { $_.Name -match $(($VMStatus.boot -split("="))[-1]) }).name | Sort-Object | Select-Object -Last 1)
    $VMDiskCount =  + ([MATH]::round([int]($LastVMDisk.Substring($LastVMDisk.Length -1, 1)) + 1))

    $StorageController = $(($VMStatus.boot -split("="))[-1]).Substring(0,  (($VMStatus.boot -split("="))[-1]).Length -1)
    

    switch ($VMName) {
        {$_ -like "ADDS-*"} { 
            Write-Host "Add 10Gb NTDS Drive"

            $DiskId = $StorageController + $VMDiskCount
            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):10"))" -Method Post -Headers $PVEConnect.Headers
            $VMDiskCount++

        }
        {$_ -eq "ADDS-01"} {
            Write-Host "Add 100Gb Backup Drive"

            $DiskId = $StorageController + $VMDiskCount
            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):100"))" -Method Post -Headers $PVEConnect.Headers
            $VMDiskCount++

        }
        {$_ -like "File-0*"} {
            Write-Host "Add 10Gb and 100Gb Data Drive"

            $DiskId = $StorageController + $VMDiskCount
            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):20"))" -Method Post -Headers $PVEConnect.Headers
            $VMDiskCount++

            $DiskId = $StorageController + $VMDiskCount
            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):100"))" -Method Post -Headers $PVEConnect.Headers
            $VMDiskCount++

        }
        {$_ -like "*RDDB-*"} {
            Write-Host "Add 10Gb and 100Gb Data Drive"

            $DiskId = $StorageController + $VMDiskCount
            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):10"))" -Method Post -Headers $PVEConnect.Headers
            $VMDiskCount++

            $DiskId = $StorageController + $VMDiskCount
            $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):100"))" -Method Post -Headers $PVEConnect.Headers
            $VMDiskCount++

        }
    }
}


# Start new server
# ------------------------------------------------------------
$null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/status/start" -Headers $PVEConnect.Headers -Method POST -Verbose:$false

Write-Verbose "Script end: $(Get-Date)"
