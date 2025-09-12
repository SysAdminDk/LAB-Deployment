param (
    [cmdletbinding()]
    [Parameter(ValueFromPipeline)]
    [string[]]$NewVMFQDN="PAW-21.Prod.SysAdmins.DK",
    [string[]]$NewVmIp="10.36.8.121",
    [string[]]$LocalAdminPassword="Dharma05052023.!!",
    [int]$VMMemory="8",
    [int]$VMCores="4",
    [string]$OSDisk="100Gb",
    [string]$DefaultStorage="Fast-SSD",
    [string]$DefaultSwitch="vmbr8"
)


# Extract Info of the VM created.
# ------------------------------------------------------------
$VMName = $(($NewVMFQDN -split("\."))[0])
$VMID = ($($NewVmIp -Split("\."))[-2]) + (($($NewVmIp -Split("\."))[-1]).PadLeft(3,"0"))
$VmDomain = $(($NewVMFQDN -split("\."))[1..99]) -join(".")
$IPGateway = "$(($($NewVmIp -Split("\."))[0..2]) -join(".")).1"


$2025 = "6BNHF-JJK28-KBQYX-324MR-Q9RHQ"
$2022 = "MHP2P-7NQ83-YMYBY-9PF6W-7FWDW"
$W11  = "DHTYN-PTBDJ-C9H6V-9DPWG-P7JXM"

$ProductKey = $W11


<#

    Default PROXMOX data

#>
Write-Verbose "Script begin: $(Get-Date)"

#region


# HTTP Headers for connection.
# ------------------------------------------------------------
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "PVEAPIToken=root@pam!Powershell-Access=dfcf6742-f05d-465a-ae34-2f96b5aebfca")
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
$ProxmoxAPI = "https://10.36.1.22:8006/api2/json"

    
# Get NODE info
# ------------------------------------------------------------
Write-Verbose "Get Proxmox Node"
Try {
    $ThisNode = ((Invoke-WebRequest -Uri "$ProxmoxAPI/cluster/status" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data | Where {$_.nodeid -eq "0"}
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
if ($Null -eq $DefaultStorage) {
    if ($Storage.count -gt 1) {
        $Storage = $Storage | Out-GridView -OutputMode Single
    }
} else {
    $Storage = $Storage | Where {$_.Storage -eq $DefaultStorage}
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



#$($ThisNode.name)
#$($Storage.storage)


# Get Id of Deployment server....
# ------------------------------------------------------------
Write-Verbose "Proxmox: Get Deployment Server ID"
$AllVMs = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
#$MasterID = ($AllVMs | Where {$_.name -eq "Priv-Development"}).vmid
$MasterID = ($AllVMs | Where {$_.name -like "*Deployment*"}).vmid
$TemplateID = ($AllVMs | Where {$_.name -eq "W11-Desktop"}).vmid

#endregion


<#

    Create VM

#>
#region create



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
        $VMCreate = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$TemplateID/clone" -Body "newid=$VMID&name=Prod-$VMName&full=1&storage=$($Storage.storage)" -Method Post -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
    }
    catch {
        $_
    }
}

if ($null -ne $VMCreate) {
    # Ensure VM exists prior to continiue
    # ------------------------------------------------------------
    Write-Verbose "Cloning"

    for ($i=0; $i -le 1000; $i++) {
        try {
            $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data

            # get OS disk ID and type
            [array]$CurrentOSDisk = $($VMStatus.psobject.Properties | Select-Object name,value | Where {$_.value -like "*-disk-*G"})
            if ($CurrentOSDisk.value) {
                break
            } else {
                Write-Host "." -NoNewline
                Start-Sleep -Seconds 1
            }
        }
        catch {
        }
    }
    Write-Host ""

    # Unmount disk
    # ------------------------------------------------------------
    Write-Verbose "Proxmox: Unmount OS disk on new VM"
    $body = "delete=$($CurrentOSDisk.name)"
    $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $headers -Verbose:$false


    # Ensure disk is unmounted.
    # ------------------------------------------------------------
    for ($i=0; $i -le 1000; $i++) {
        try {
            $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
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
    #Write-Host ""

    # Ensure TARGET disk is dont exist.
    # ------------------------------------------------------------
    for ($i=0; $i -le 1000; $i++) {
        try {
            $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
            if (!($VMStatus.virtio5)) {
                break
            } else {
                #Write-Host "." -NoNewline
                Start-Sleep -Seconds 1
            }
        }
        catch {
        }
    }
    #Write-Host ""

    # mount disk on "Deployment"
    # ------------------------------------------------------------
    Write-Verbose "Proxmox: Mount new OS disk on `"Master`" server"
    $body = "vmid=$VMID"
    $body += "&target-vmid=$MasterID"
    $body += "&disk=unused0"
    $body += "&target-disk=virtio5"
    $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/move_disk" -Body $body -Method Post -Headers $headers -Verbose:$false


    # Ensure TARGET disk is dont exist.
    # ------------------------------------------------------------
    for ($i=0; $i -le 1000; $i++) {
        try {
            $VMStatus = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$MasterID/config" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data
            if ($VMStatus.virtio5) {
                break
            } else {
                #Write-Host "." -NoNewline
                Start-Sleep -Seconds 1
            }
        }
        catch {
        }
    }
    #Write-Host ""

    # Mount disk on Deployment Server
    # ------------------------------------------------------------
    Write-Verbose "Windows: Mount Disk."

    for ($i=0; $i -le 60; $i++) {

        $VHDDrive = Get-Disk | Where {$_.OperationalStatus -eq "Offline"}
        if ($null -eq $VHDDrive) {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 1
        } else {
            break
        }
    }
    if ($null -eq $VHDDrive) {
        Throw "Still no drive mounted"
    }

    Set-Disk -Number $VHDDrive.number -IsOffline:$false
    Set-Disk -Number $VHDDrive.number -IsReadOnly:$false


    # Get drive letter
    # ------------------------------------------------------------
    $VHDXDrive3 = Get-Partition -DiskNumber $VHDDrive.number | Where {$_.Size -gt "10Gb"}
    $VHDXVolume3 = [string]$VHDXDrive3.DriveLetter+":"


    # Add ADDS feature
    # ------------------------------------------------------------
    if ( ($VmDomain -eq "PROD.SysAdmins.DK") -And ($NewVMFQDN -Like "ADDS-0*") ) {
        Write-Verbose "Windows: DISM Add Domain Featuers"

        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:DNS-Server-Full-Role /All | Out-Null
        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:DirectoryServices-DomainController /All | Out-Null

        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:RSAT-AD-Tools-Feature | Out-Null
        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:RSAT-ADDS-Tools-Feature | Out-Null
        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:DirectoryServices-DomainController-Tools | Out-Null
        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:ActiveDirectory-PowerShell | Out-Null
        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:DirectoryServices-AdministrativeCenter | Out-Null
        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:Microsoft-Windows-GroupPolicy-ServerAdminTools-Update | Out-Null
        Dism /Image:"$VHDXVolume3" /Enable-Feature /FeatureName:DNS-Server-Tools | Out-Null
    }


    #region Unattend.
    Write-Verbose "Windows: Create Unattend Xml"


    # Define DNS servers
    # ------------------------------------------------------------
    if ( ($VmDomain -eq "Prod.SysAdmins.DK") -And ($NewVMFQDN -Like "ADDS-01*") ) {
        $DNSServer = @("8.8.8.8","8.8.4.4")
    } else {
        $DNSServer = @("10.36.8.11","10.36.8.12","10.36.8.13")
    }


    # Write Default Unattend.xml
    # ------------------------------------------------------------
    $UnattendXml = @()
    $UnattendXml += "<?xml version=`"1.0`" encoding=`"utf-8`"?>"
    $UnattendXml += "<unattend xmlns=`"urn:schemas-microsoft-com:unattend`">"
    $UnattendXml += " <settings pass=`"specialize`">"
    $UnattendXml += "  <component name=`"Microsoft-Windows-Shell-Setup`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
    $UnattendXml += "   <ComputerName>$VMName</ComputerName>"
    $UnattendXml += "   <TimeZone>Romance Standard Time</TimeZone>"
    $UnattendXml += "   <ProductKey>$ProductKey</ProductKey>"
    $UnattendXml += "   <RegisteredOrganization>SysAdmins AD Lab</RegisteredOrganization>"
    $UnattendXml += "   <RegisteredOwner>Jan Kristensen</RegisteredOwner>"
    $UnattendXml += "  </component>"

    if ( ($VmDomain -eq "Prod.SysAdmins.DK") -And ($NewVMFQDN -NotLike "ADDS-01*") ) {
        $UnattendXml += "  <component name=`"Microsoft-Windows-UnattendedJoin`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
        $UnattendXml += "   <Identification>"
        $UnattendXml += "    <Credentials>"
        $UnattendXml += "     <Domain>$(($VmDomain -split("\."))[0])</Domain>" # Join Credentials Domain
        $UnattendXml += "     <Username>Administrator</Username>"              # Join Credentials User
        $UnattendXml += "     <Password>$LocalAdminPassword</Password>"        # Join Credentials Password
        $UnattendXml += "    </Credentials>"
        $UnattendXml += "    <JoinDomain>$VmDomain</JoinDomain>"               # Domain to join !!!
        $UnattendXml += "   </Identification>"
        $UnattendXml += "  </component>"
    }

    $UnattendXml += "  <component name=`"Microsoft-Windows-TCPIP`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
    $UnattendXml += "   <Interfaces>"
    $UnattendXml += "    <Interface wcm:action=`"add`">"
    $UnattendXml += "     <Ipv4Settings>"
    $UnattendXml += "      <DhcpEnabled>false</DhcpEnabled>"
    $UnattendXml += "      <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>"
    $UnattendXml += "     </Ipv4Settings>"
    $UnattendXml += "     <Identifier>Ethernet</Identifier>"
    $UnattendXml += "     <Routes>"
    $UnattendXml += "      <Route wcm:action=`"add`">"
    $UnattendXml += "       <Identifier>1</Identifier>"
    $UnattendXml += "       <Prefix>0.0.0.0/0</Prefix>"
    $UnattendXml += "       <NextHopAddress>$IPGateway</NextHopAddress>"
    $UnattendXml += "      </Route>"
    $UnattendXml += "     </Routes>"
    $UnattendXml += "     <UnicastIpAddresses>"
    $UnattendXml += "      <IpAddress wcm:action=`"add`" wcm:keyValue=`"1`">$NewVmIp/24</IpAddress>"
    $UnattendXml += "     </UnicastIpAddresses>"
    $UnattendXml += "    </Interface>"
    $UnattendXml += "   </Interfaces>"
    $UnattendXml += "  </component>"
    $UnattendXml += "  <component name=`"Microsoft-Windows-DNS-Client`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
    $UnattendXml += "   <Interfaces>"
    $UnattendXml += "    <Interface wcm:action=`"add`">"
    $UnattendXml += "     <DNSServerSearchOrder>"

    # Add DNS servers
    # ------------------------------------------------------------
    for ($i=0; $i -lt $DNSServer.count; $i++) {
        $UnattendXml += "      <IpAddress wcm:action=`"add`" wcm:keyValue=`"$($i+1)`">$($DNSServer[$i])</IpAddress>"
    }

    $UnattendXml += "     </DNSServerSearchOrder>"
    $UnattendXml += "     <Identifier>Ethernet</Identifier>"
    $UnattendXml += "     <EnableAdapterDomainNameRegistration>true</EnableAdapterDomainNameRegistration>"
    $UnattendXml += "     <DNSDomain>$VmDomain</DNSDomain>"
    $UnattendXml += "     <DisableDynamicUpdate>false</DisableDynamicUpdate>"
    $UnattendXml += "    </Interface>"
    $UnattendXml += "   </Interfaces>"
    $UnattendXml += "  </component>"

    $UnattendXml += "  <component name=`"Microsoft-Windows-TerminalServices-LocalSessionManager`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
    $UnattendXml += "   <fDenyTSConnections>false</fDenyTSConnections>"
    $UnattendXml += "  </component>"
    $UnattendXml += "  <component name=`"Networking-MPSSVC-Svc`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
    $UnattendXml += "   <FirewallGroups>"
    $UnattendXml += "    <FirewallGroup wcm:action=`"add`" wcm:keyValue=`"EnableRDP`">"
    $UnattendXml += "     <Active>true</Active>"
    $UnattendXml += "     <Profile>all</Profile>"
    $UnattendXml += "     <Group>RemoteDesktop</Group>"
    $UnattendXml += "    </FirewallGroup>"
    $UnattendXml += "   </FirewallGroups>"
    $UnattendXml += "  </component>"

    $UnattendXml += " </settings>"
    $UnattendXml += " <settings pass=`"oobeSystem`">"
    $UnattendXml += "  <component name=`"Microsoft-Windows-Shell-Setup`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
    $UnattendXml += "   <UserAccounts>"
    $UnattendXml += "    <AdministratorPassword>"
    $UnattendXml += "     <Value>$LocalAdminPassword</Value>"
    $UnattendXml += "     <PlainText>true</PlainText>"
    $UnattendXml += "    </AdministratorPassword>"
    $UnattendXml += "   </UserAccounts>"
    $UnattendXml += "   <RegisteredOrganization></RegisteredOrganization>"
    $UnattendXml += "   <RegisteredOwner></RegisteredOwner>"
    $UnattendXml += "   <OOBE>"
    $UnattendXml += "    <HideEULAPage>true</HideEULAPage>"
    $UnattendXml += "    <ProtectYourPC>1</ProtectYourPC>"
    $UnattendXml += "    <HideLocalAccountScreen>true</HideLocalAccountScreen>"
    $UnattendXml += "    <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>"
    $UnattendXml += "    <HideOnlineAccountScreens>true</HideOnlineAccountScreens>"
    $UnattendXml += "    <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>"
    $UnattendXml += "    <SkipUserOOBE>true</SkipUserOOBE>"
    $UnattendXml += "    <SkipMachineOOBE>true</SkipMachineOOBE>"
    $UnattendXml += "    <NetworkLocation>Work</NetworkLocation>"
    $UnattendXml += "   </OOBE>"

    if ( ($VmDomain -eq "Prod.SysAdmins.DK") -And ($VMName -eq "ADDS-01") ) {
        $UnattendXml = "   <AutoLogon>"
        $UnattendXml += "    <Password>"
        $UnattendXml += "    <Value>$LocalAdminPassword</Value>"
        $UnattendXml += "    <PlainText>true</PlainText>"
        $UnattendXml += "    </Password>"
        $UnattendXml += "    <Enabled>true</Enabled>"
        $UnattendXml += "    <LogonCount>2</LogonCount>"
        $UnattendXml += "    <Username>Administrator</Username>"
        $UnattendXml += "   </AutoLogon>"

        $UnattendXml += "   <FirstLogonCommands>"
        $UnattendXml += "   <SynchronousCommand wcm:action=`"add`">"
        $UnattendXml += "   <CommandLine>%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -file `"C:\TS-Data\Create-Domain.ps1`"</CommandLine>"
        $UnattendXml += "   <Description>Install Domain</Description>"
        $UnattendXml += "   <Order>1</Order>"
        $UnattendXml += "   <RequiresUserInput>true</RequiresUserInput>"
        $UnattendXml += "   </SynchronousCommand>"
        $UnattendXml += "   </FirstLogonCommands>"
    }

    $UnattendXml += "  </component>"
    $UnattendXml += "  <component name=`"Microsoft-Windows-International-Core`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
    $UnattendXml += "   <InputLocale>da-DK</InputLocale>"
    $UnattendXml += "   <SystemLocale>da-DK</SystemLocale>"
    $UnattendXml += "   <UILanguage>en-US</UILanguage>"
    $UnattendXml += "   <UILanguageFallback>en-US</UILanguageFallback>"
    $UnattendXml += "   <UserLocale>da-DK</UserLocale>"
    $UnattendXml += "  </component>"
    $UnattendXml += " </settings>"
    $UnattendXml += "</unattend>"


    if (!(Test-Path -Path "$VHDXVolume3\Windows\Panther")) {
        New-Item -Path "$VHDXVolume3\Windows\Panther" -ItemType Directory | Out-Null
    }

    $UnattendXml | Out-File -FilePath "D:\Server Configs\Temp-Unattend.xml" -Encoding utf8
    $UnattendXml | Out-File -FilePath "$VHDXVolume3\Windows\Panther\unattend.xml" -Encoding utf8
    
    #endregion


    if ( ($NewVMFQDN -like "*.Prod.SysAdmins.DK") -And ($VMName -eq "ADDS-01") ) {
        Write-Verbose "Windows: Copy Domain Script"

        # Copy Scripts !!!
        if (!(Test-Path -Path "$VHDXVolume3\TS-Data")) {
            New-Item -Path "$VHDXVolume3\TS-Data" -ItemType Directory | Out-Null
        }
        # C:\TS-Data\Create-Domain.ps1
        #Copy-Item -Path "D:\Scripts\Create-Domain.ps1" -Destination "$VHDXVolume3\TS-Data\Create-Domain.ps1"
        $CreateDomain = Get-Content -Path "D:\Scripts\Create-Domain.ps1"
        $CreateDomain = $CreateDomain -replace("DefaultPasswordReplace",$LocalAdminPassword)
        $CreateDomain | Out-File "$VHDXVolume3\TS-Data\Create-Domain.ps1" -Force

        <#
        $CreateDomain | Where {$_ -like "*UserPassword = *"}
        #>

    }


    # Unmount disk
    Write-Verbose "Windows: Offline disk"

    Get-Disk $VHDDrive.number | Set-Disk -IsOffline $true


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
    #Write-Host ""

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
    #Write-Host ""

    # mount disk on "Server"
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
    Write-Verbose "Proxmox: Update Boot sequence"

    $body = "boot=$([uri]::EscapeDataString("order=$($CurrentOSDisk.name);net0"))"
    $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $headers -Verbose:$false


    # Change Disk size, amount memory and cpu if needed
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

    # 
    # ------------------------------------------------------------
    if ($VmDomain -eq "PROD.SysAdmins.DK") {
        switch ($VMName) {
            {$_ -like "ADDS-*"} { 
                Write-Host "Add 10Gb NTDS Drive"

                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "sata1=$([uri]::EscapeDataString("$($Storage.storage):10"))" -Method Post -Headers $headers -Verbose:$false

            }
            {$_ -eq "ADDS-01"} {
                Write-Host "Add 100Gb Backup Drive"

                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "sata2=$([uri]::EscapeDataString("$($Storage.storage):100"))" -Method Post -Headers $headers -Verbose:$false

            }
            {$_ -like "File-0*"} {
                Write-Host "Add 100Gb Data Drive"

                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "sata1=$([uri]::EscapeDataString("$($Storage.storage):100"))" -Method Post -Headers $headers -Verbose:$false
            }
            {$_ -like "*RDDB-*"} {
                Write-Host "Add 10Gb and 100Gb Data Drive"

                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "sata1=$([uri]::EscapeDataString("$($Storage.storage):10"))" -Method Post -Headers $headers -Verbose:$false
                $Null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/config" -Body "sata2=$([uri]::EscapeDataString("$($Storage.storage):100"))" -Method Post -Headers $headers -Verbose:$false

            }
        }
    }


    # Start..
    Write-Verbose "Proxmox: Start VM"
    $null = Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/status/start" -Headers $headers -Method Post -Verbose:$false


    Write-Verbose "Sleeping"
    $time = (3 * 60) # seconds, use you actual time in here
    foreach($i in (1..$time)) {
        $percentage = $i / $time
        $remaining = New-TimeSpan -Seconds ($time - $i)
        $message = "{0:p0} complete, remaining time {1}" -f $percentage, $remaining
        Write-Progress -Status $message -PercentComplete ($percentage * 100) -Activity "Wait for Server installation"
        Start-Sleep 1
    }
    Write-Progress -Activity "Wait for Server installation" -Completed
    Write-Verbose ""
}

Write-Verbose "Script end: $(Get-Date)"
