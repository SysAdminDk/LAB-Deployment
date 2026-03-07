<#

    Requires
    - PVE Node(s) with Disk, CPU and memory to handle the amount of VMs
    - Create Master Deployment server using, Create-DeploymentServer.ps1
    - VM Template(s) have been created using New-PVEVMTemplate.ps1


    Create required servers for the FABRIC Domain.
    - Server list found in ./ConfigFiles/FabricDomain.json

#>

# Do Not Just Execute.
# ------------------------------------------------------------
break


# Path to PVE scripts and Functions.
# ------------------------------------------------------------
$RootPath          = "D:\Scripts"


# Download required files
# ------------------------------------------------------------
# ...


# LAB Domain Defaults.
# ------------------------------------------------------------
$DefaultUser       = "Administrator"
$DefaultPass       = "DefaultPassword"
$DefaultVLanId     = 200


# Configure or extract the Vendor Max, will be used for all VMs created.
# ------------------------------------------------------------
#$MacPrefix         = "BC:24"
#$VendorMac         = (((Get-NetAdapter).MacAddress -split("-"))[0..1]) -join("-")


# List of VMs to create.
# ------------------------------------------------------------
# \\10.36.1.32\MyGithub\LAB-Deployment\ConfigFiles
$Servers = Get-Content "$RootPath\FabricDomain.json" | Convertfrom-Json


# Import PVE modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false
Get-ChildItem -Path "$RootPath\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }




# Connect to PVE Cluster
# ------------------------------------------------------------
$PVESecret = Get-Content "$RootPath\PVE-Secret.json" | Convertfrom-Json
$PVEConnect = PVE-Connect -Authkey "$($PVESecret.User)!$($PVESecret.TokenID)=$($PVESecret.Token)" -Hostaddr $($PVESecret.Host)


# Get information required to create the template (VM)
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers


# Find all templates
# ------------------------------------------------------------
$Templates = Get-PVETemplates -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers


# Select the template to use.
# ------------------------------------------------------------
if ($Templates.Count -gt 1) {
    # Stupid OutGridview thinks the VMID is a number that need a thousands separator!
    $SelectedVMTemplate = $Templates | Select-Object @{Name="VmID"; Expression={ "$($_.vmid)"}},name,Node | Out-GridView -Title "Select VM template to use" -OutputMode Single
} else {
    $SelectedVMTemplate = $Templates
}


<#
($Servers | ForEach-Object { $_.VMName }).IndexOf('ADDS-01')
#>

# Create the servers listed.
# ------------------------------------------------------------
Foreach ($Server in $Servers) {
    Write-Host "Create Server : $($Server.Name).$($Server.DomainName)"


    # Extract required data from IP information
    # ------------------------------------------------------------
    $MACAddress = $Server.Network.PhysicalAddress -replace(":","-")
    $VLanId     = ($Server.Network.IPv4Address -split("\."))[-2]
    
    $Disks = @()
    $Disks += $Server.Hardware.Disks.System
    $Disks += $($Server.Hardware.Disks.data | % { $_ })


    # Create Server in PVE
    # ------------------------------------------------------------
<#
    New-PVEServer -FQDN "$($Server.Name).$($Server.DomainName)" `

                  -NetAdapterMac $MACAddress `
                  -vlan $VLanId `

                  -VMMemory $Server.Hardware.MaxMemory `

                  -VMCores $Server.Hardware.CPUCores `
                  -Disks $($Disks -Join(",")) `

                  -DefaultConnection $PVEConnect `
                  -DefaultLocation $PVELocation `
                  -Template $SelectedVMTemplate
#>

    # Create Server JSON file
    # ------------------------------------------------------------
    $Server | ConvertTo-Json -Depth 5 | Out-File -FilePath "D:\Deployment\Controll\$MACAddress.json"

}



<#

New-PVEServer -FQDN temp.prod.secinfra.dk -IpAddress 10.36.200.112 -IpSubnet 255.255.255.0 -IpGateway 10.36.200.1 -DnsServers @("8.8.8.8","8.8.4.4") `
    -NetAdapterMac $MACAddress -DefaultConnection $PVEConnect -DefaultLocation $PVELocation -Template $SelectedVMTemplate -DomainJoin $DefaultDomain `
    -DomainOU "" -LocalUsername Administrator -LocalPassword TestPassword -OSDisk 50 -ProductKey 1111 -vlan 200 -VMMemory 8 -VMCores 4 -StartFile BootStrap

#>