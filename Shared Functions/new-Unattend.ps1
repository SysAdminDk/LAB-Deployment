function New-Unattend {
    Param
    (
        [parameter(Mandatory=$true)][string]$ComputerName,
        [parameter(Mandatory=$false)][string]$ProductKey,
        [parameter(Mandatory=$false)][string]$AdminUsername = "Administrator",
        [parameter(Mandatory=$false)][string]$AdminPassword = $(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 25 | ForEach-Object {[char]$_})),
        [parameter(Mandatory=$false)][string]$DomainName,
        [parameter(Mandatory=$false)][object]$Interfaces,
        [parameter(Mandatory=$false)][string]$IPAddress,
        [parameter(Mandatory=$false)][string]$SubnetMask,
        [parameter(Mandatory=$false)][string]$Gateway,
        [parameter(Mandatory=$false)][object]$DNSServers,
        [parameter(Mandatory=$false)][string]$RunAtStartup,
        [parameter(Mandatory=$false)][int]$DiskId = 0
    )

    if ($DomainName) {
        $Netbios = $($DomainName -split("\."))[0]
    }
    if ( ($IPAddress) -and ($SubnetMask) ) {
        $IPPrefix = (($SubnetMask -split '\.' | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') } ) -join("")) -replace '0','' | Measure-Object -Character | Select-Object -ExpandProperty Characters
        $NetworkAddress = "$IPAddress/$IPPrefix"
    }
    $org = "SecInfra"
    $Owner = "Jan Kristensen"
    $RunAtStartup = "C:\TS-Data\$RunAtStartup"


    # Write Default Unattend.xml
    # ------------------------------------------------------------
    $UnattendXml = @()
    $UnattendXml += "<?xml version=`"1.0`" encoding=`"utf-8`"?>"
    $UnattendXml += "<unattend xmlns=`"urn:schemas-microsoft-com:unattend`" xmlns:wcm=`"http://schemas.microsoft.com/WMIConfig/2002/State`">"
    $UnattendXml += "    <settings pass=`"windowsPE`">"
    $UnattendXml += "        <component name=`"Microsoft-Windows-International-Core-WinPE`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
    $UnattendXml += "            <UILanguage>en-US</UILanguage>"
    $UnattendXml += "            <InputLocale>en-US</InputLocale>"
    $UnattendXml += "            <SystemLocale>en-US</SystemLocale>"
    $UnattendXml += "            <UILanguageFallback>en-US</UILanguageFallback>"
    $UnattendXml += "            <UserLocale>en-US</UserLocale>"
    $UnattendXml += "        </component>"
    $UnattendXml += "        <component name=`"Microsoft-Windows-Setup`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
    $UnattendXml += "            <DiskConfiguration>"
    $UnattendXml += "                <Disk wcm:action=`"add`">"
    $UnattendXml += "                <DiskID>$DiskId</DiskID>"
    $UnattendXml += "                <WillWipeDisk>true</WillWipeDisk>"
    $UnattendXml += "                    <CreatePartitions>"
    $UnattendXml += "                        <CreatePartition wcm:action=`"add`">"
    $UnattendXml += "                            <Order>1</Order>"
    $UnattendXml += "                            <Type>EFI</Type>"
    $UnattendXml += "                            <Size>300</Size>"
    $UnattendXml += "                        </CreatePartition>"
    $UnattendXml += "                        <CreatePartition wcm:action=`"add`">"
    $UnattendXml += "                            <Order>2</Order>"
    $UnattendXml += "                            <Type>MSR</Type>"
    $UnattendXml += "                            <Size>128</Size>"
    $UnattendXml += "                        </CreatePartition>"
    $UnattendXml += "                        <CreatePartition wcm:action=`"add`">"
    $UnattendXml += "                            <Order>3</Order>"
    $UnattendXml += "                            <Type>Primary</Type>"
    $UnattendXml += "                            <Extend>true</Extend>"
    $UnattendXml += "                        </CreatePartition>"
    $UnattendXml += "                    </CreatePartitions>"
    $UnattendXml += "                    <ModifyPartitions>"
    $UnattendXml += "                        <ModifyPartition wcm:action=`"add`">"
    $UnattendXml += "                            <Order>1</Order>"
    $UnattendXml += "                            <PartitionID>1</PartitionID>"
    $UnattendXml += "                            <Label>System</Label>"
    $UnattendXml += "                            <Format>FAT32</Format>"
    $UnattendXml += "                        </ModifyPartition>"
    $UnattendXml += "                        <ModifyPartition wcm:action=`"add`">"
    $UnattendXml += "                            <Order>2</Order>"
    $UnattendXml += "                            <PartitionID>3</PartitionID>"
    $UnattendXml += "                            <Label>Windows</Label>"
    $UnattendXml += "                            <Letter>C</Letter>"
    $UnattendXml += "                            <Format>NTFS</Format>"
    $UnattendXml += "                        </ModifyPartition>"
    $UnattendXml += "                    </ModifyPartitions>"
    $UnattendXml += "                </Disk>"
    $UnattendXml += "                <WillShowUI>OnError</WillShowUI>"
    $UnattendXml += "            </DiskConfiguration>"
    $UnattendXml += "            <ImageInstall>"
    $UnattendXml += "                <OSImage>"
    $UnattendXml += "                    <InstallToAvailablePartition>true</InstallToAvailablePartition>"
    $UnattendXml += "                    <WillShowUI>OnError</WillShowUI>"
    $UnattendXml += "                </OSImage>"
    $UnattendXml += "            </ImageInstall>"
    $UnattendXml += "            <UpgradeData>"
    $UnattendXml += "                <Upgrade>false</Upgrade>"
    $UnattendXml += "                <WillShowUI>OnError</WillShowUI>"
    $UnattendXml += "            </UpgradeData>"
    $UnattendXml += "            <UserData>"
    $UnattendXml += "                <AcceptEula>true</AcceptEula>"
    if ($ProductKey) {
        $UnattendXml += "                <ProductKey>"
        $UnattendXml += "                    <Key>$ProductKey</Key>"
        $UnattendXml += "                    <WillShowUI>OnError</WillShowUI>"
        $UnattendXml += "                </ProductKey>"
    }
    $UnattendXml += "            </UserData>"
    $UnattendXml += "        </component>"
    $UnattendXml += "    </settings>"

    $UnattendXml += "    <settings pass=`"specialize`">"
    $UnattendXml += "        <component name=`"Microsoft-Windows-Shell-Setup`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
    $UnattendXml += "            <ComputerName>$ComputerName</ComputerName>"
    $UnattendXml += "            <RegisteredOrganization>$Org</RegisteredOrganization>"
    $UnattendXml += "            <RegisteredOwner>$Owner</RegisteredOwner>"
    if ($ProductKey) {
        $UnattendXml += "            <!-- <ProductKey>$ProductKey</ProductKey> -->"
    }
    $UnattendXml += "            <TimeZone>Romance Standard Time</TimeZone>"
    $UnattendXml += "        </component>"


    if ( ($DomainName) -and ($AdminUsername) -and ($AdminPassword) ) {
        $UnattendXml += "        <component name=`"Microsoft-Windows-UnattendedJoin`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
        $UnattendXml += "            <Identification>"
        $UnattendXml += "                <Credentials>"
        $UnattendXml += "                    <Domain>$DomainName</Domain>"
        $UnattendXml += "                    <Username>$AdminUsername</Username>"
        $UnattendXml += "                    <Password>$AdminPassword</Password>"
        $UnattendXml += "                </Credentials>"
        $UnattendXml += "                <JoinDomain>$DomainName</JoinDomain>"
        $UnattendXml += "            </Identification>"
        $UnattendXml += "        </component>"
    }


    if ($Interfaces) {
        $UnattendXml += "        <component name=`"Microsoft-Windows-TCPIP`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
        $UnattendXml += "            <Interfaces>"

        $UnattendXml += "                <Interface wcm:action=`"add`">"
        $UnattendXml += "                    <Ipv4Settings>"
        $UnattendXml += "                        <DhcpEnabled>false</DhcpEnabled>"
        $UnattendXml += "                        <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>"
        $UnattendXml += "                    </Ipv4Settings>"


        $UnattendXml += "                    <Identifier>Ethernet</Identifier>"

        if ( ($IPAddress) -and ($DNSServers) -and ($Gateway) ) {

            $UnattendXml += "                    <UnicastIpAddresses>"
            $UnattendXml += "                        <IpAddress wcm:action=`"add`" wcm:keyValue=`"1`">$NetworkAddress</IpAddress>"
            $UnattendXml += "                    </UnicastIpAddresses>"

            $UnattendXml += "                    <Routes>"
            $UnattendXml += "                        <Route wcm:action=`"add`">"
            $UnattendXml += "                            <Identifier>0</Identifier>"
            $UnattendXml += "                            <Prefix>0.0.0.0/0</Prefix>"
            $UnattendXml += "                            <NextHopAddress>$Gateway</NextHopAddress>"
            $UnattendXml += "                        </Route>"
            $UnattendXml += "                    </Routes>"

        } else {
            $UnattendXml += "                    <DhcpEnabled>true</DhcpEnabled>"
        }

        $UnattendXml += "                </Interface>"
        $UnattendXml += "            </Interfaces>"
        $UnattendXml += "        </component>"


        $UnattendXml += "        <component name=`"Microsoft-Windows-DNS-Client`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
        $UnattendXml += "            <Interfaces>"
        $UnattendXml += "            <Interface wcm:action=`"add`">"
        $UnattendXml += "                <Identifier>Ethernet</Identifier>"
        $UnattendXml += "                <DNSServerSearchOrder>"

            $DNSServers | ForEach-Object {
                $key = ([array]::IndexOf($DNSServers, $_)) + 1
                $UnattendXml += "                    <IpAddress wcm:action=`"add`" wcm:keyValue=`"$key`">$($_)</IpAddress>"
            }

        $UnattendXml += "                </DNSServerSearchOrder>"
        $UnattendXml += "            </Interface>"
        $UnattendXml += "        </Interfaces>"
        $UnattendXml += "        </component>"
    }


    $UnattendXml += "        <component name=`"Microsoft-Windows-TerminalServices-LocalSessionManager`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
    $UnattendXml += "            <fDenyTSConnections>false</fDenyTSConnections>"
    $UnattendXml += "        </component>"
    $UnattendXml += "        <component name=`"Networking-MPSSVC-Svc`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
    $UnattendXml += "            <FirewallGroups>"
    $UnattendXml += "                <FirewallGroup wcm:action=`"add`" wcm:keyValue=`"RemoteDesktop`">"
    $UnattendXml += "                    <Active>true</Active>"
    $UnattendXml += "                    <Profile>all</Profile>"
    $UnattendXml += "                    <Group>@FirewallAPI.dll,-28752</Group>"
    $UnattendXml += "                </FirewallGroup>"
    $UnattendXml += "            </FirewallGroups>"
    $UnattendXml += "        </component>"

    $UnattendXml += "    </settings>"

    $UnattendXml += "    <settings pass=`"oobeSystem`">"
    $UnattendXml += "        <component name=`"Microsoft-Windows-International-Core`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
    $UnattendXml += "            <InputLocale>da-DK</InputLocale>"
    $UnattendXml += "            <SystemLocale>da-DK</SystemLocale>"
    $UnattendXml += "            <UILanguage>en-US</UILanguage>"
    $UnattendXml += "            <UserLocale>en-US</UserLocale>"
    $UnattendXml += "        </component>"
    $UnattendXml += "        <component name=`"Microsoft-Windows-Shell-Setup`" processorArchitecture=`"amd64`" publicKeyToken=`"31bf3856ad364e35`" language=`"neutral`" versionScope=`"nonSxS`">"
    $UnattendXml += "            <UserAccounts>"
    $UnattendXml += "                <AdministratorPassword>"
    $UnattendXml += "                    <Value>$AdminPassword</Value>"
    $UnattendXml += "                    <PlainText>true</PlainText>"
    $UnattendXml += "                </AdministratorPassword>"
    $UnattendXml += "           </UserAccounts>"

    if ($RunAtStartup) {
        $UnattendXml += "            <AutoLogon>"
        $UnattendXml += "                <Username>$AdminUsername</Username>"
        $UnattendXml += "                <Enabled>true</Enabled>"
        $UnattendXml += "                <LogonCount>3</LogonCount>"
        $UnattendXml += "                <Password>"
        $UnattendXml += "                    <Value>$AdminPassword</Value>"
        $UnattendXml += "                    <PlainText>true</PlainText>"
        $UnattendXml += "                </Password>"

        if ($DomainName) {
            $UnattendXml += "                <Domain>$DomainName</Domain>"
        }

        $UnattendXml += "            </AutoLogon>"
        $UnattendXml += "            <FirstLogonCommands>"
        $UnattendXml += "                <SynchronousCommand wcm:action=`"add`">"
        $UnattendXml += "                    <CommandLine>powershell.exe -ExecutionPolicy Bypass -NoProfile -file `"$RunAtStartup`"</CommandLine>"
        $UnattendXml += "                    <Description>BootStrap Script</Description>"
        $UnattendXml += "                    <Order>1</Order>"
        $UnattendXml += "                    <RequiresUserInput>true</RequiresUserInput>"
        $UnattendXml += "                </SynchronousCommand>"
        $UnattendXml += "            </FirstLogonCommands>"
    }

    $UnattendXml += "            <OOBE>"
    $UnattendXml += "                <HideEULAPage>true</HideEULAPage>"
    $UnattendXml += "                <SkipMachineOOBE>true</SkipMachineOOBE>"
    $UnattendXml += "                <ProtectYourPC>3</ProtectYourPC>"
    $UnattendXml += "                <HideLocalAccountScreen>true</HideLocalAccountScreen>"
    $UnattendXml += "                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>"
    $UnattendXml += "                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>"
    $UnattendXml += "                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>"
    $UnattendXml += "            </OOBE>"
    $UnattendXml += "        </component>"

    $UnattendXml += "    </settings>"
    $UnattendXml += "</unattend>"

    return $UnattendXml
}


