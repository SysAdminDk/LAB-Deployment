<#

    
    Functions used in PVE-NewVM and PVE-NEWTemplate scripts


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