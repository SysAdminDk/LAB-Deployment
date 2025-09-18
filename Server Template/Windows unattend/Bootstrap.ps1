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


# Start logging.
# ------------------------------------------------------------
$LogFile = "$($ENV:SystemRoot)\Temp\Bootstrap.log"
"[$(Get-Date)] Starting bootstrap..." | Out-File -FilePath $LogFile -Append


# Find Media Drive.
# ------------------------------------------------------------
$MediaDrives = Get-WmiObject -Class Win32_volume -Filter "DriveType = '5'"
foreach ($MediaDrive in $MediaDrives) {

    "[$(Get-Date)] Checking $($Mediadrive.name)" | Out-File -FilePath $LogFile -Append


    # Get content from NetConfig file
    # ------------------------------------------------------------
    $NetworkConfigFile = $(Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "0000" -ErrorAction SilentlyContinue)
    if ($NetworkConfigFile) {
        $NetworkConfig = Get-Content -Path $NetworkConfigFile.FullName

        # Network Config
        # ------------------------------------------------------------
        if ($NetworkConfig) {

            # Extract values from NetworkConfig
            # ------------------------------------------------------------
            "[$(Get-Date)] Extracting Network Configuration" | Out-File -FilePath $LogFile -Append

            $DNSServers = ((($NetworkConfig | Where {$_ -like "*nameservers*"}) -replace("dns-nameservers","")).trim() -split "[ ,]+")
            $IPGateway  = (($NetworkConfig  | Where {$_ -like "*gateway*"})     -replace("gateway","")).trim()
            $IPAddress  = (($NetworkConfig  | Where {$_ -like "*address*"})     -replace("address","")).trim()
            $IPNetmask  = (($NetworkConfig  | Where {$_ -like "*netmask*"})     -replace("netmask","")).trim()


            # Apply NetConfig
            # ------------------------------------------------------------
            "[$(Get-Date)] Apply Network Configuration" | Out-File -FilePath $LogFile -Append

            $IPPrefix = (($IPNetmask -split '\.' | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') } ) -join("")) -replace '0','' | Measure-Object -Character | Select-Object -ExpandProperty Characters
            Get-NetAdapter | New-NetIPAddress -IPAddress "$IPAddress" -PrefixLength $IPPrefix -DefaultGateway $IPGateway | Out-Null

            $DNSServers = $DNSServers | ForEach-Object { $_.Trim() }
            Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $DNSServers | Out-Null
        }
    }


    # Get content from User Data 
    # ------------------------------------------------------------
    $HostConfigFile = Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "USER_DATA" -ErrorAction SilentlyContinue
    if ($HostConfigFile) {
        $HostConfig = Get-Content -Path $HostConfigFile.FullName

        # Host Config
        # ------------------------------------------------------------
        if ($HostConfig) {

            # Extract values from User Data
            # ------------------------------------------------------------
            "[$(Get-Date)] Apply Network Configuration" | Out-File -FilePath $LogFile -Append

            $HostName   = ($HostConfig  | Where {$_ -like "*hostname*"})   -Replace("^(?:\w+):\s","")
            $DomainName = (($HostConfig | Where {$_ -like "*fqdn*"})       -Replace("^(?:\w+):\s","") -split("\.", 2))[1]
            $Username   = (($HostConfig | Where {$_ -like "*user*"})[0])   -Replace("^(?:\w+):\s","")
            $Password   = ($HostConfig  | Where {$_ -like "*password*"})   -Replace("^(?:\w+):\s","")
            $DomainJoin = ($HostConfig  | Where {$_ -like "*DomainJoin*"}) -Replace("^(?:\w+):\s","")
            $DomainJoin = ($HostConfig  | Where {$_ -like "*DomainJoin*"}) -Replace("^(?:\w+):\s","")
            $MachineOU  = ($HostConfig  | Where {$_ -like "*MachineOU*"})  -Replace("^(?:\w+):\s","")


            # Set user password.
            # ------------------------------------------------------------
            if ($Username -and $Password) {
                "[$(Get-Date)] Set Local User Password." | Out-File -FilePath $LogFile -Append

                $CryptPassword = ConvertTo-SecureString $Password -AsPlainText -Force
                if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
                    Set-LocalUser -Name $Username -Password $CryptPassword
                }
            }
        }


        # Set startup script, if exists.
        # ------------------------------------------------------------
        $RunAtStartupFile = Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "$HostName.ps1" -ErrorAction SilentlyContinue
        if (!($RunAtStartupFile)) {
            $FileSearch = "$(($HostName -split("-"))[0])-0x"
            $RunAtStartupFile = Get-ChildItem -Path $MediaDrive.Name -Recurse -Filter "$FileSearch.ps1" -ErrorAction SilentlyContinue
        }


        # Set startup script, if exists.
        # ------------------------------------------------------------
        if ($($RunAtStartupFile.FullName) -and $Username -and $Password) {

            "[$(Get-Date)] Add Autologon and Resume BootStrap" | Out-File -FilePath $LogFile -Append

            # Setup Autologon
            # --------------------------------------------------------------------------------------------------
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoLogonCount" -value 2
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoAdminLogon" -value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultUserName" -value $Username -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $Password -Force


            # Registry Run
            # --------------------------------------------------------------------------------------------------
            if (!(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Resume BootStrap" -ErrorAction SilentlyContinue)) {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Resume BootStrap" -Value "Powershell.exe -ExecutionPolicy Bypass -File `"$($RunAtStartupFile.FullName)`"" | Out-Null
            }
        }
    }
}


# Function - Extract network prefix
# ------------------------------------------------------------
function Get-NetworkPrefix {
    param([string]$Ip)
    return ($Ip -split '\.')[0..2] -join "."
}


# If Domain Join..
# ------------------------------------------------------------
$ServerPrefix = Get-NetworkPrefix $Address
$DnsPrefixes = $DNSServers | ForEach-Object { Get-NetworkPrefix $_ } | Sort-Object -Unique

if ($DnsPrefixes -contains $ServerPrefix) {

    "[$(Get-Date)] Domain Join" | Out-File -FilePath $LogFile -Append

    # Domain Join
    # ------------------------------------------------------------
    if ($DomainJoin) {

        # If Domain Join Creds have been provided, use that.
        # ------------------------------------------------------------
        $DomainCreds = $DomainJoin -Split(":") 
        $CryptPassword = ConvertTo-SecureString $($DomainCreds[1]) -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ($($DomainCreds[0]), $CryptPassword)

    } else {

        # If No Domain Join Creds, try using default.
        # ------------------------------------------------------------
        $CryptPassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ($Username, $CryptPassword)    
    }

    if ($null -ne $MachineOU) {
        $DomainDN = (($DomainName -split("\.")) | ForEach-Object { "DC=$($_)" }) -join(",")
        $JoinMachineOU = @($MachineOU ,$DomainDN) -Join(",")

        Add-Computer -NewName $HostName -DomainName $DomainName -Credential $Credentials -OUPath $JoinMachineOU -Restart

    } else {

        Add-Computer -NewName $HostName -DomainName $DomainName -Credential $Credentials -Restart

    }

} else {

    "[$(Get-Date)] Rename Server" | Out-File -FilePath $LogFile -Append

    # First Domain Controller or Workgroup
    # ------------------------------------------------------------
    Rename-Computer -NewName $HostName -Restart

}
