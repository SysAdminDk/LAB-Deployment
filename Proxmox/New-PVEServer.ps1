param (
    [cmdletbinding()]
    [Parameter(ValueFromPipeline)]
    [string[]]$NewVMFQDN="ADDS-01.Fabric.SecInfra.Dk",
    [string[]]$MachineOU=$null,
    [string[]]$NewVmIp="10.36.11.11",
    [string[]]$LocalAdminPassword="P@ssword2025.!!",
    [int]$VMMemory=4,
    [int]$VMCores=2,
    [string]$OSDisk="50Gb",
    [string]$DefaultStorage,
    [string]$DefaultSwitch,
    [switch]$Start
)



<#

    1. User/script picks target node, storage, and network.


    3. Clone template → new VM.

        In parallel, create 1 GB unattend disk on deployment server:

        3a. Format, drop autounattend.xml.

        3b. Offline and remove (unused0).

        3c. Attach unattend disk to the new VM.

    4. If required, migrate the VM to the requested node/storage.

    5. Boot....

#>



# Extract Info of the VM created.
# ------------------------------------------------------------
$VMName = $(($NewVMFQDN -split("\."))[0])
$VMID = (($($NewVmIp -Split("\."))[0]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[1]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[2]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[3]).PadLeft(3,"0"))
$VmDomain = $(($NewVMFQDN -split("\."))[1..99]) -join(".")
$IPGateway = "$(($($NewVmIp -Split("\."))[0..2]) -join(".")).1"

if ($null -eq $VMID) {
    $VMID = Get-Random -Minimum 888888888 -Maximum 999999999
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
& "\\10.36.2.8\shares\Github Repositories\LAB-Scripts\Proxmox\PVE-Functions.ps1"


$VMLocation = Get-PVELocation -ProxmoxAPI $DefaultProxmoxAPI -Headers $DefaultHeaders




<#

    Verify Deployment and Template is on same NODE

#>


# Find all templates
# ------------------------------------------------------------
$Templates = Get-PVETemplates -ProxmoxAPI $ProxmoxAPI -Headers $headers


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


# Get the Deployment server info
# ------------------------------------------------------------
$MasterServer = Get-PVEServerID -ProxmoxAPI $DefaultProxmoxAPI -Headers $DefaultHeaders -ServerName "Deploy"


# Verify and Move Template if required.
# ------------------------------------------------------------
If ($MasterServer.Node -ne $SelectedVMTemplate.Node) {

    # Move Template..
    # ------------------------------------------------------------
    Move-PVEVM -ProxmoxAPI $ProxmoxAPI -Headers $Headers -SourceNode $SelectedVMTemplate.Node -TargetNode $MasterServer.Node -VMID $SelectedVMTemplate.VmID -Wait
}



<#

    Create VM

#>


# Configure and create VM
# ------------------------------------------------------------
Write-Verbose "Proxmox: Create new VM: $VMName"
$VMCreate=$null
$VMStatus=$null

try {
    $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
}
catch {
    try {
        # Clone template
        $VMCreate = Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$($VMTemplate.VmID)/clone" -Body "newid=$VMID&name=$NewVMFQDN&full=1&storage=$($VMLocation.storage)" -Method Post -Headers $headers -Verbose:$false

        # Wait for clone...
        Start-PVEWait -ProxmoxAPI $DefaultProxmoxAPI -Headers $DefaultHeaders -node $($ThisNode.name) -taskid $VMCreate.data
    }
    catch {
    }
}


# Add Cloud Init drive, with bare minimum data.
# ------------------------------------------------------------
$body = "node=$($ThisNode.name)"
$body += "&ide2=$($VMLocation.Storage):cloudinit"
Invoke-RestMethod -Method POST -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Headers $Headers


# Set bare minimum data in Cloud Init.
# ------------------------------------------------------------
$body = "node=$($ThisNode.name)"
$body += "&citype=configdrive2"
$body += "&ciuser=Administrator"
$body += "&cipassword=P@ssword2025.!!"
$body += "&searchdomain=$VmDomain"
$body += "&nameserver=$DNSServers"
$body += "&ipconfig0=$([uri]::EscapeDataString("ip=10.36.8.12/24,gw=10.36.8.1"))"

Invoke-RestMethod -Method POST -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Headers $Headers

Invoke-RestMethod -Method PUT -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/cloudinit" -Headers $Headers


# Start new server
# ------------------------------------------------------------
$null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/status/start" -Headers $headers -Method Post -Verbose:$false


$VMStatus = Invoke-RestMethod "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/status/current" -Headers $headers
if ($VMStatus.data.balloon -gt 0) { "Windows likely finished setup" }

$VMStatus.data.balloon
$VMStatus.data.mem

$VMStatus.data.ballooninfo





while ($true) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($ip, $port)
        if ($tcp.Connected) {
            Write-Host "RDP is ready on $ip"
            $tcp.Close()
            break
        }
    } catch {
        Write-Host "Waiting for RDP..."
    }
    Start-Sleep -Seconds 10
}















    

    
    #endregion





    Write-Verbose "Proxmox: Unmount disk"

    $body = "delete=virtio5"
    $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/config" -Body $body -Method Post -Headers $headers -Verbose:$false


    # Ensure disk is unmounted.
    # ------------------------------------------------------------
    for ($i=0; $i -le 1000; $i++) {
        try {
            $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
            if ($VMStatus.unused0) {
                break
            } else {
                #Write-Host "." -NoNewline
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
            $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
            if (!($VMStatus.$($CurrentOSDisk.name))) {
                break
            } else {
                #Write-Host "." -NoNewline
                Start-Sleep -Seconds 1
            }
        }
        catch {
        }
    }


    # mount disk on "Server"
    # ------------------------------------------------------------
    Write-Verbose "Proxmox: Move disk to new VM"

    $body = "vmid=$MasterID"
    $body += "&target-vmid=$VMID"
    $body += "&disk=unused0"
    $body += "&target-disk=$($CurrentOSDisk.name)"
    $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/move_disk" -Body $body -Method Post -Headers $headers -Verbose:$false

    for ($i=0; $i -le 1000; $i++) {
        try {
            $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
            if ($VMStatus.$($CurrentOSDisk.name)) {
                break
            } else {
                #Write-Host "." -NoNewline
                Start-Sleep -Seconds 1
            }
        }
        catch {
        }
    }

    # Add SCSI0 to boot..
    # ------------------------------------------------------------
    Write-Verbose "Proxmox: Update Boot sequence"

    $body = "boot=$([uri]::EscapeDataString("order=$($CurrentOSDisk.name);net0"))"
    $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $headers -Verbose:$false


    # Change Disk size, amount memory and cpu if needed
    # ------------------------------------------------------------
    Write-Verbose "Proxmox: Change VM configuration"
    $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data

    if ($VMStatus.cores -ne $VMCores) {
        Write-Verbose "Proxmox: Update CPU Cores"

        $body = "cores=$VMCores"
        $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $headers -Verbose:$false

    }


    if ([math]::Round($($VMMemory * 1KB)) -ne $VMStatus.memory) {
        Write-Verbose "Proxmox: Update Memory size"

        $body = "memory=$($VMMemory*1KB)"
        $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $headers -Verbose:$false

    }

    # Calculate if OSDisk size differs, and change if needed.
    # ------------------------------------------------------------
    $OSDiskSize = ($($VMStatus.$($CurrentOSDisk.name) -split("="))[-1]+"b")
    $SizeDiff = [math]::round($OSDisk - $OSDiskSize) / 1Gb

    if ($SizeDiff -gt 0) {
        Write-Verbose "Proxmox: Update Disk size"

        $body = "disk=$($CurrentOSDisk.name)&size=$($OSDisk.ToLower().replace("gb","G"))"
        $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/resize" -Body $body -Method Put -Headers $headers 

    }


<#

    Add Extra Disks depending on server type.

#>

    if ($VmDomain -ne "Workgroup") {

        $DiskController = $(($CurrentOSDisk.name)[0..$($CurrentOSDisk.name.Length-2)]) -join("")

        switch ($VMName) {
            {$_ -like "ADDS-*"} { 
                Write-Host "Add 10Gb NTDS Drive"

                $DiskId = $DiskController + "1"
                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($Storage.storage):10"))" -Method Post -Headers $headers -Verbose:$false
            }
            {$_ -eq "ADDS-01"} {
                Write-Host "Add 100Gb Backup Drive"

                $DiskId = $DiskController + "2"
                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($Storage.storage):100"))" -Method Post -Headers $headers -Verbose:$false
            }
            {$_ -like "File-0*"} {
                Write-Host "Add 10Gb and 100Gb Data Drive"

                $DiskId = $DiskController + "1"
                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($Storage.storage):20"))" -Method Post -Headers $headers -Verbose:$false

                $DiskId = $DiskController + "2"
                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($Storage.storage):100"))" -Method Post -Headers $headers -Verbose:$false
            }
            {$_ -like "*RDDB-*"} {
                Write-Host "Add 10Gb and 100Gb Data Drive"

                $DiskId = $DiskController + "1"
                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($Storage.storage):10"))" -Method Post -Headers $headers -Verbose:$false

                $DiskId = $DiskController + "2"
                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($Storage.storage):100"))" -Method Post -Headers $headers -Verbose:$false

            }
        }
    }


    # Start if defined.
    # ------------------------------------------------------------
    if ($Start) {
        Write-Verbose "Proxmox: Start VM"
        $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/status/start" -Headers $headers -Method Post -Verbose:$false
    }
}

Write-Verbose "Script end: $(Get-Date)"
