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

    

    # If DNS server is on same subnet, Domain Join..
    # ------------------------------------------------------------
    function Get-NetworkPrefix {
        param([string]$Ip)
        return ($Ip -split '\.')[0..2] -join "."
    }

    # Address Prefix
    $ServerPrefix = Get-NetworkPrefix $Address

    # DNSServers Prefix (Unique)
    $DnsPrefixes = $DNSServers | orEach-Object { Get-NetworkPrefix $_ } | Sort-Object -Unique

    if ($DnsPrefixes -contains $ServerPrefix) {

        # Domain Join
        # ------------------------------------------------------------
        
        $Credentials = New-Object System.Management.Automation.PSCredential ($Username, $CryptPassword)
        Add-Computer -NewName $HostName -DomainName $DomainName -Credential $Credentials -Restart

    } else {

        # First Domain Controller or Workgroup
        # ------------------------------------------------------------
        Rename-Computer -ComputerName $HostName -Restart

    }
}
