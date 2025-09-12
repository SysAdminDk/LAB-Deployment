<#

    
    Functions used in PVE-NewVM and PVE-NEWTemplate scripts


#>

function PVE-Connect {
    $AuthKey = "root@pam!Powershell=16dcf2b5-1ca1-41cd-9e97-3c1d3d308ec0"
    $HostAddr = "10.36.1.27"

    #$AuthKey = "root@pam!Powershell-Access=dfcf6742-f05d-465a-ae34-2f96b5aebfca"
    #$HostAddr = "10.36.1.22"


    # HTTP Headers for connection.
    # ------------------------------------------------------------
    $DefaultHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $DefaultHeaders.Add("Authorization", "PVEAPIToken=$AuthKey")
    $DefaultHeaders.Add("Accept", "application/json")


    # Ignore Self Signed Cert.
    # ------------------------------------------------------------
    $AddType = @()
    $AddType += "using System.Net;"
    $AddType += "using System.Security.Cryptography.X509Certificates;"
    $AddType += "public class TrustAllCertsPolicy : ICertificatePolicy {"
    $AddType += "    public bool CheckValidationResult("
    $AddType += "        ServicePoint srvPoint, X509Certificate certificate,"
    $AddType += "        WebRequest request, int certificateProblem) {"
    $AddType += "        return true;"
    $AddType += "    }"
    $AddType += "};"
    $AddType = "[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy"
    Add-Type -TypeDefinition $AddType

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Proxmox API address.
    # ------------------------------------------------------------
    $DefaultProxmoxAPI = "https://$HostAddr`:8006/api2/json"
}


function Get-PVELocation {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory)][string]$ProxmoxAPI,
        [Parameter(Position=1,Mandatory)][object]$Headers
    )


    # Get NODE info
    # ------------------------------------------------------------
    Write-Verbose "Get Proxmox Nodes"

    Try {
        $NodesData = @()

        $NodesQuery = (Invoke-RestMethod -Uri "$ProxmoxAPI/cluster/status" -Headers $Headers).data | Where {$_.type -eq "node"}
        
        foreach ($Node in $NodesQuery) {
            $NodeDataArray = @(
                [PSCustomObject]@{ Name = $Node.Name; }
            )
            $NodesData += $NodeDataArray
        }
    }
    Catch {
        Write-Error "Unable to get any available nodes...."
    }


    # Get Storage info
    # ------------------------------------------------------------
    Write-Verbose "Get Proxmox Nodes Storage"

    Try {
        $StorageData = @()

        foreach ($Node in $NodesData) {
            $NodeStorageQuery = (Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$($Node.name)/storage" -Headers $Headers).data | Where {$_.content -like "*images*"}

            foreach ($Storage in $NodeStorageQuery) {
                $NodeStorageArray = @(
                    [PSCustomObject]@{ Name    = $Node.Name;
                                       Storage = $Storage.storage;
                                       Avail   = [math]::round($Storage.avail / 1Gb);
                                       Used    = [math]::round($Storage.used / 1Gb);
                                       Total   = [math]::round($Storage.total / 1Gb);
                                     }
                )
                $StorageData += $NodeStorageArray
            }
        }

    }
    Catch {
        Write-Error "Unable to get any available storage on any nodes"
    }


    # Get Network info
    # ------------------------------------------------------------
    Write-Verbose "Get Proxmox Bridge"

    Try {
        $BridgeData = @()

        foreach ($Node in $NodesData) {

            $NodeBridgeQuery = ((Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$($Node.name)/network" -Method Get -Headers $Headers).data | where {$_.Type -eq "bridge"}) | Select-Object iface,address,cidr

            foreach ($Bridge in $NodeBridgeQuery) {
                $NodeBridgeArray = @(
                    [PSCustomObject]@{ Name    = $Node.Name;
                                       Address = $Bridge.address;
                                       Network = $Bridge.cidr;
                                       Interface = $Bridge.iface;
                                     }
                )
                $BridgeData += $NodeBridgeArray
            }
        }
    }
    Catch {
        $Switch = ""
    }


    # Join the arrays and show selection
    # ------------------------------------------------------------
    $Result = foreach ($a in $StorageData) {
        foreach ($b in $BridgeData | Where-Object { $_.Name -eq $a.Name }) {
            [PSCustomObject]@{ Name      = $a.Name
                               Storage   = $a.Storage
                               Avail     = $a.Avail
                               Used      = $a.Used
                               Total     = $a.Total
                               Address   = $b.Address
                               Network   = $b.Network
                               Interface = $b.Interface
                            }
        }
    }

    $VMLocation = $Result | Out-GridView -Title "Select Node, Storage and network for the new VM" -OutputMode Single
    return $VMLocation
}




Function Get-PVETemplates {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ProxmoxAPI,
        [Parameter(Mandatory)][object]$Headers
    )

    $Alltemplates = @()

    $NodesQuery = ((Invoke-WebRequest -Uri "$ProxmoxAPI/cluster/status" -Headers $Headers -Verbose:$false | ConvertFrom-Json)[0]).data | Where {$_.type -eq "node"}

    foreach ($Node in $NodesQuery) {

        $NodeTemplateQuery = ((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($Node.name)/qemu/" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data | Where {$_.template -eq 1}
        foreach ($Template in $NodeTemplateQuery) {

            $TemplateArray = @(
                [PSCustomObject]@{
                                  VmID = "$($Template.vmid)"
                                  Name = "$($Template.Name)";
                                  Node = "$($Node.Name)";
                                 }
                              )
            $Alltemplates += $TemplateArray
        }
    }
    return $Alltemplates
}



Function Get-PVEServerID {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ProxmoxAPI,
        [Parameter(Mandatory)][object]$Headers,
        [string]$ServerName
    )

    $NodesQuery = ((Invoke-WebRequest -Uri "$ProxmoxAPI/cluster/status" -Headers $Headers -Verbose:$false | ConvertFrom-Json)[0]).data | Where {$_.type -eq "node"}
    $AllVMs = @()
    foreach ($Node in $NodesQuery) {

        $VMData = (((Invoke-WebRequest -Uri "$ProxmoxAPI/nodes/$($Node.name)/qemu/" -Headers $headers -Verbose:$false | ConvertFrom-Json)[0]).data | Where {$_.template -ne 1 -and $_.name -like "*$ServerName*"})

        if ($VMData) {
            $NodeDataArray = @(
                [PSCustomObject]@{
                                  VmID = "$($VMData.vmid)"
                                  Name = "$($VMData.Name)";
                                  Node = "$($Node.Name)";
                                 }
            )
            $AllVMs += $NodeDataArray
        }
    }

    if ($AllVMs.Count -gt 1) {
        $VMMaster = $AllVMs | Out-GridView -Title "Select VM to use for mounting the Deployment Drives." -OutputMode Single
    } else {
        $VMMaster = $AllVMs
    }

    Return $VMMaster
}


function Start-PVEWait {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ProxmoxAPI,
        [Parameter(Mandatory)][object]$Headers,
        [Parameter(Mandatory)][string]$Node,
        [Parameter(Mandatory)][string]$Taskid
    )

    $TimeoutSeconds = 600
    $StartTime = Get-Date
    $EndTime = $startTime.AddSeconds($TimeoutSeconds)

    do {
        $TaskStatus = Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$Node/tasks/$Taskid/status" -Headers $headers

        if ($TaskStatus.data.status -ne "running") {
            Write-Progress -Activity "Waiting for PVE Task ($($TaskStatus.data.type))" -Status "Completed" -PercentComplete 100
            return
        }

        $Elapsed = (Get-Date) - $StartTime
        $Percent = [math]::Min(($elapsed.TotalSeconds / $TimeoutSeconds) * 100, 100)
        
        Write-Progress -Activity "Waiting for PVE Task ($($TaskStatus.data.type))" -Status "Running" -PercentComplete $Percent
        Start-Sleep -Seconds 5

    } while ($true)
}


Function Move-PVEVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ProxmoxAPI,
        [Parameter(Mandatory)][object]$Headers,
        [Parameter(Mandatory)][string]$SourceNode,
        [Parameter(Mandatory)][string]$TargetNode,
        [Parameter(Mandatory)][string]$VMID,
        [switch]$Wait
    )

    $body = "vmid=$VMID"
    $body += "&target=$TargetNode"
    try {
        $MoveStatus = Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$SourceNode/qemu/$VMID/migrate" -Body $body -Method Post -Headers $Headers
    }
    Catch {
        if ($_ -like "*target is local*") {
            Write-Warning "Target is local node"
        } else {
            $_
        }
    }

    if ($Wait) {
        Start-PVEWait -ProxmoxAPI $ProxmoxAPI -Headers $Headers -node $SourceNode -taskid $MoveStatus.data
    } else {
        return
    }
}

<#
function Move-PVEDisk {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ProxmoxAPI,
        [Parameter(Mandatory)][object]$Headers,
        [Parameter(Mandatory)][string]$SourceNode=$($ThisNode.Name),
        [Parameter(Mandatory)][string]$SourceVM=$VMID,
        [Parameter(Mandatory)][string]$TargetVM=$($MasterServer.VmId),
        [string]$SourceDisk="scsi0",
        [string]$TargetDisk="scsi1",
        [string][ValidateSet("scsi","sata","virtio")]$DiskType="scsi|sata|virtio",
        [switch]$Wait
    )


    # Get Drive to move..
    # ------------------------------------------------------------
    if ($SourceDisk -eq "First") {
        $SourceVmData = (Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$SourceNode/qemu/$SourceVM/config" -Headers $headers).data
        $SourceVMDisk = $SourceVmData.PSObject.Properties | Where-Object { $_.Name -match $DiskType -and $_.Value -like "*$SourceVM*"}
        if ($SourceVMDisk.count -gt 1) {
            $SourceVMDisk = $SourceVMDisk | Sort-Object -Property Name | Select-Object -First 1
        }
    } else {
        $SourceVmData = (Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$SourceNode/qemu/$SourceVM/config" -Headers $headers).data
        $SourceVMDisk = $SourceVmData.PSObject.Properties | Where-Object { $_.Name -eq $SourceDisk -and $_.Value -like "*$SourceVM*"}
    }


    # Detach disk from VM
    # ------------------------------------------------------------
    $body = "delete=$($VMDiskInfo.name)"
    $UnMount = Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$SourceNode/qemu/$SourceVM/config" -Body $body -Method Post -Headers $headers

    Start-PVEWait -ProxmoxAPI $DefaultProxmoxAPI -Headers $DefaultHeaders -node $($ThisNode.name) -taskid $UnMount.data


    # Get Target data.
    $TargetVMData = (Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$SourceNode/qemu/$TargetVM/config" -Method Get -Headers $headers).data


    # Find Target Disk NUmber to use
    if ($TargetDisk -eq "Next") {

        $VMDisks = ($TargetVMData.PSObject.Properties | Where-Object { $_.Name -match $DiskType -and $_.value -like "*$TargetVM*"}).name

        $LastVMDisk = [String](($VMDisks | Sort-Object)[-1])
        $NextVMDisk = $LastVMDisk.Substring(0, $LastVMDisk.Length -1) + ([MATH]::round([int]($LastVMDisk.Substring($LastVMDisk.Length -1, 1)) + 1))

        # Add to VM
        $body = "vmid=$VMID"
        $body += "&target-vmid=$($MasterServer.VmID)"
        $body += "&disk=unused0"
        $body += "&target-disk=$NextVMDisk"
        $MoveDisk = Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/move_disk" -Body $body -Method Post -Headers $headers

    } else {

        # Test if Target Disk exists
        ($TargetVMData.PSObject.Properties | Where-Object { $_.Name -match $DiskType -and $_.name -eq $TargetDisk}).name
        $TargetDisk

        if () {
            throw "Selected Controller ID is already in use"
        }

        # Add to VM
        $body = "vmid=$VMID"
        $body += "&target-vmid=$($MasterServer.VmID)"
        $body += "&disk=unused0"
        $body += "&target-disk=$TargetDisk"
        $MoveDisk = Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$($ThisNode.name)/qemu/$VMID/move_disk" -Body $body -Method Post -Headers $headers

    }

    if ($Wait) {
        Start-PVEWait -ProxmoxAPI $ProxmoxAPI -Headers $Headers -node $SourceNode -taskid $MoveDisk.data
    } else {
        return
    }
}
#>

<#
function Create-WinUnattend {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$VMFQDN=$NewVMFQDN,
        [Parameter(Mandatory)][object]$DNSServers,
        [Parameter(Mandatory)][string]$ProductKey,
        [Parameter(Mandatory)][string]$Password=$LocalAdminPassword,
        [string]$JoinOU
    )


    $VMName = $(($NewVMFQDN -split("\."))[0])
    $VmDomain = $(($NewVMFQDN -split("\."))[1..99]) -join(".")


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
    $UnattendXml += "   <RegisteredOrganization>SecInfra AD Lab</RegisteredOrganization>"
    $UnattendXml += "   <RegisteredOwner>Jan Kristensen</RegisteredOwner>"
    $UnattendXml += "  </component>"

    if ( ($VmDomain -ne "Workgroup") -And ($NewVMFQDN -NotLike "ADDS-01*") ) {
        $UnattendXml += "  <component name=`"Microsoft-Windows-UnattendedJoin`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">"
        $UnattendXml += "   <Identification>"
        $UnattendXml += "    <Credentials>"
        $UnattendXml += "     <Domain>$(($VmDomain -split("\."))[0])</Domain>"   # Join Credentials Domain
        $UnattendXml += "     <Username>Administrator</Username>"                # Join Credentials User
        $UnattendXml += "     <Password>$LocalAdminPassword</Password>"          # Join Credentials Password
        $UnattendXml += "    </Credentials>"
        $UnattendXml += "    <JoinDomain>$VmDomain</JoinDomain>"                 # Domain to join !!!
        if ($null -ne $MachineOU) {

            $JoinOUArray = @()
            $JoinOUArray += $MachineOU
            $JoinOUArray += ($VmDomain -split("\.") | ForEach-Object { "DC=" + $_ })
            $JoinOU = $JoinOUArray -join(",")

            $UnattendXml += "    <MachineObjectOU>$JoinOU</MachineObjectOU>"  # OU If specified.
        }
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
    $UnattendXml += "   </OOBE>"

    if ($VMName -eq "ADDS-01") {
        $UnattendXml += "   <AutoLogon>"
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
        $UnattendXml += "   <CommandLine>%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -file `"C:\Scripts\Create-Domain.ps1`"</CommandLine>"
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

    return $UnattendXml

}
#>