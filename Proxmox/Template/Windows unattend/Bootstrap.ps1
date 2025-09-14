<# 

     _____          _        _ _       _   _              ______             _       _                   
    |_   _|        | |      | | |     | | (_)             | ___ \           | |     | |                  
      | | _ __  ___| |_ __ _| | | __ _| |_ _  ___  _ __   | |_/ / ___   ___ | |_ ___| |_ _ __ __ _ _ __  
      | || '_ \/ __| __/ _` | | |/ _` | __| |/ _ \| '_ \  | ___ \/ _ \ / _ \| __/ __| __| '__/ _` | '_ \ 
     _| || | | \__ \ || (_| | | | (_| | |_| | (_) | | | | | |_/ / (_) | (_) | |_\__ \ |_| | | (_| | |_) |
     \___/_| |_|___/\__\__,_|_|_|\__,_|\__|_|\___/|_| |_| \____/ \___/ \___/ \__|___/\__|_|  \__,_| .__/ 
                                                                                                  | |    
                                                                                                  |_| 
#>


<# 

    Simple way of getting Server Name and IP from Cloud Init drive.

#>

# Find Cloud Init Media Drive.
# ------------------------------------------------------------
$MediaDrive = Get-WmiObject -Class Win32_volume -Filter "DriveType = '5'"
if ($null -ne $MediaDrive.Name) {

<# 

#>

    # Get content from NetConfig file
    # ------------------------------------------------------------
    $NetworkConfig = Get-Content -Path $(Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "0000").FullName


    # Extract values from NetworkConfig
    # ------------------------------------------------------------
    $DNSServers = ((($NetworkConfig | Where {$_ -like "*dns-nameservers*"}) -replace("dns-nameservers","")).trim() -split(" |,"))
    $Gateway = (($NetworkConfig | Where {$_ -like "*gateway*"}) -replace("gateway","")).trim()
    $Address = (($NetworkConfig | Where {$_ -like "*address*"}) -replace("address","")).trim()
    $Netmask = (($NetworkConfig | Where {$_ -like "*netmask*"}) -replace("netmask","")).trim()
    $Prefix = (($Netmask -split '\.' | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') } ) -join("")) -replace '0','' | Measure-Object -Character | Select-Object -ExpandProperty Characters


    # Apply NetConfig
    # ------------------------------------------------------------
    Get-NetAdapter | New-NetIPAddress -IPAddress "$Address" -PrefixLength $Prefix -DefaultGateway $Gateway | Out-Null
    Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $DNSServers | Out-Null

<# 

#>

    # Get content from User Data 
    # ------------------------------------------------------------
    $HostConfig = Get-Content -Path $(Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "USER_DATA").FullName


    # Extract values from User Data
    # ------------------------------------------------------------
    $HostName = ($HostConfig | Where {$_ -like "*hostname*"}) -Replace("^(?:\w+):\s","")
    $DomainName = ((($HostConfig | Where {$_ -like "*fqdn*"}) -Replace("^(?:\w+):\s","") -split("\."))[1..99]) -join(".")
    $Username = (($HostConfig | Where {$_ -like "*user*"})[0]) -Replace("^(?:\w+):\s","")
    $Password = ($HostConfig | Where {$_ -like "*password*"}) -Replace("^(?:\w+):\s","")


    # Set user password.
    # ------------------------------------------------------------
    $CryptPassword = ConvertTo-SecureString $Password -AsPlainText -Force
    Set-LocalUser -Name $Username -Password $CryptPassword


    # Verify Internet Access.
    # ------------------------------------------------------------
    for($i=0; $i -lt 100; $i++) {

        $NetworkTest = Test-NetConnection -ComputerName "api.github.com" -Port 443
        if ($NetworkTest.TcpTestSucceeded) {
            break
        } else {
            Start-Sleep -Seconds 5
        }
    }


    if (-not $NetworkTest.TcpTestSucceeded) {
        throw "Timeout waiting for $HostToCheck on port $Port"
    }        


    # Get Server Config file, if any exists
    # ------------------------------------------------------------
    try {

        # Get the file list at root of repo
        # ------------------------------------------------------------
        $Uri = "https://api.github.com/repos/SysAdminDk/LAB-Deployment/contents/Windows%20Servers?ref=main"
        $Files = Invoke-RestMethod -Uri $Uri -Headers @{ "User-Agent" = "Powershell" }

        $DownloadFile = $Files | Where-Object { $_.name -eq "$Hostname.ps1" }
        if ($null -eq $DownloadFile) {

            $HostPrefix = $($Hostname -split("-"))[0]
            $DownloadFile = $Files | Where-Object { $_.name -eq "$HostPrefix-0x.ps1" }
        }
        
        # Download selected file
        # ------------------------------------------------------------
        Invoke-WebRequest -Uri $DownloadFile.download_url -OutFile "C:\Scripts\$Hostname.ps1"


        # Get Domain Name from DNS Suffix
        # --------------------------------------------------------------------------------------------------
        $Netbios = $(($DomainName -split("\."))[0]).ToUpper()


        # Enabled Autologin
        # --------------------------------------------------------------------------------------------------
        $AutoLoginData = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

        if ($AutoLoginData.AutoLogonCount -le 2) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoLogonCount" -value 3
        }
        if ($AutoLoginData.AutoAdminLogon -eq 0) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoAdminLogon" -value 1
        }
        if ($AutoLoginData.DefaultUserName -ne $env:USERNAME) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultUserName" -value $env:USERNAME -Force
        }
        if ( (!($AutoLoginData.DefaultPassword)) -or ($AutoLoginData.DefaultPassword -ne $UserPassword) ) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $Password -Force
        }
        if ($AutoLoginData.DefaultDomainName -ne $Netbios) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $Netbios -Force
        }


        # Registry Run
        # --------------------------------------------------------------------------------------------------
        if (!(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Install Domain" -ErrorAction SilentlyContinue)) {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Install Domain" -Value "Powershell.exe -ExecutionPolicy Bypass -File `"C:\Scripts\$Hostname.ps1`"" | Out-Null
        }

    }
    catch {
    }


    # If DNS server is on same subnet, Domain Join..
    # ------------------------------------------------------------
    function Get-NetworkPrefix {
        param([string]$Ip)
        return ($Ip -split '\.')[0..2] -join "."
    }


    # Address Prefix
    # ------------------------------------------------------------
    $ServerPrefix = Get-NetworkPrefix $Address
    $DnsPrefixes = $DNSServers | ForEach-Object { Get-NetworkPrefix $_ } | Sort-Object -Unique


    if ($DnsPrefixes -contains $ServerPrefix) {

        # Domain Join
        # ------------------------------------------------------------
        $Credentials = New-Object System.Management.Automation.PSCredential ($Username, $CryptPassword)
        Add-Computer -NewName $HostName -DomainName $DomainName -Credential $Credentials -Restart

    } else {

        # First Domain Controller or Workgroup
        # ------------------------------------------------------------
        Rename-Computer -NewName $HostName -Restart

    }
}
