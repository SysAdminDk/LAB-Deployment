<#

    Requires
    - PVE Node(s) with Disk, CPU and memory to handle the amount of VMs
    - Create Master Deployment server using, Create-DeploymentServer.ps1
    - VM Template(s) have been created using New-PVEVMTemplate.ps1



    Create required servers for the PROD Domain.
    - Server list found in ./ConfigFiles/ProdDomain.json

#>

# Do Not Just Execute.
# ------------------------------------------------------------
break


# Path to PVE scripts and Functions.
# ------------------------------------------------------------
$RootPath          = "G:\Shares\Personal Github\LAB-Deployment" # "C:\GitClone"
$ScriptPath        = "G:\Shares\Personal Github\PVE-Platform" # Join-Path -Path $RootPath -ChildPath "PVE-Platform"


# Download required files
# ------------------------------------------------------------
# ...


# Defaults.
# ------------------------------------------------------------
$DefaultUser       = "Administrator"
$DefaultPass       = "DefaultPassword"
$DefaultDomain     = "Prod.SecInfra.Dk"
$DefaultVLanId     = 100

# Configure or extract the Vendor Max, will be used for all VMs created.
# ------------------------------------------------------------
#$MacPrefix        = "BC:24"
$VendorMac         = (((Get-NetAdapter).MacAddress -split("-"))[0..1]) -join("-")


# List of VMs to create.
# ------------------------------------------------------------
$Servers           = Get-Content "$RootPath\ConfigFiles\ProdDomain.json" | Convertfrom-Json


# Import PVE modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false
Get-ChildItem -Path "$ScriptPath\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


# Connect to PVE Cluster
# ------------------------------------------------------------
$PVESecret = Get-Content "$ScriptPath\PVE-Secret.json" | Convertfrom-Json
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
Foreach ($Server in $Servers[0,1]) {
    Write-Host "Create Server : $($Server.Name).$DefaultDomain"

    if ($Server.DomainName) {
        $Server.DomainName = $DefaultDomain
    } else {
        $Server | Add-Member -MemberType NoteProperty -Name DomainName -Value $DefaultDomain
    }

    # Find Server Boot Strap file.
    # ------------------------------------------------------------
#    $StartFile = Get-ChildItem -Path $RootPath -Recurse -Filter "$($Server.Name).ps1" -ErrorAction SilentlyContinue
#    if (!($StartFile)) {
#        $FileSearch = "$(($Server.Name -split("-"))[0])-0x"
#        $StartFile = Get-ChildItem -Path $RootPath -Recurse -Filter "$FileSearch.ps1" -ErrorAction SilentlyContinue
#    }

    $JoinOptions = $null
    if ($($Server.Name) -ne "ADDS-01") {
        $JoinOptions = "$($DefaultUser):$($DefaultPass)"
        if ($Server.JoinOptions) {
            $Server.JoinOptions = $JoinOptions
        } else {
            $Server | Add-Member -MemberType NoteProperty -Name JoinOptions -Value $JoinOptions
        }
    }


    # Convert IP 2 MAC
    # ------------------------------------------------------------
    $MACAddress = IP2Mac -IpAddress $Server.Address

    if ($Server.MACAddress) {
        $Server.MACAddress = $MACAddress
    } else {
        $Server | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress
    }
    

    # Create Server in PVE
    # ------------------------------------------------------------
    New-PVEServer -FQDN "$($Server.Name).$DefaultDomain" `
                  -IpAddress $Server.Address `
                  -IpSubnet $Server.Subnet `
                  -IpGateway $Server.Gateway `
                  -DnsServers $Server.DNS `
                  -NetAdapterMac $MACAddress `
                  -vlan $DefaultVLanId `
                  -VMMemory $Server.Memory `
                  -LocalUsername $DefaultUser `
                  -LocalPassword $DefaultPass `
                  -DomainJoin $JoinOptions `
                  -DomainOU $Server.DomainOU `
                  -VMCores $Server.Cores `
                  -Disks $Server.Disks `
                  -DefaultConnection $PVEConnect `
                  -DefaultLocation $PVELocation `
                  -ProductKey $DefaultProductKey `
                  -Template $SelectedVMTemplate `
                  -StartFile $StartFile.FullName


    # Create Server JSON file
    # ------------------------------------------------------------
    $Server | Select-Object Name,DomainName,JoinOptions,Address,Subnet,Gateway,DNS,Roles,Tasks | ConvertTo-Json | Out-File -FilePath "D:\Deployment\Controll\$MACAddress.json"

}



<#

New-PVEServer -FQDN temp.prod.secinfra.dk -IpAddress 10.36.200.112 -IpSubnet 255.255.255.0 -IpGateway 10.36.200.1 -DnsServers @("8.8.8.8","8.8.4.4") `
    -NetAdapterMac $MACAddress -DefaultConnection $PVEConnect -DefaultLocation $PVELocation -Template $SelectedVMTemplate -DomainJoin $DefaultDomain `
    -DomainOU "" -LocalUsername Administrator -LocalPassword TestPassword -OSDisk 50 -ProductKey 1111 -vlan 200 -VMMemory 8 -VMCores 4 -StartFile BootStrap

#>