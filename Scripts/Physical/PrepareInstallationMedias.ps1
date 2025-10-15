<#

    Pre Execution requirements.

    1a. Download latest Windows Server 2025 install media.
        - Mount ISO, and copy content to "D:\TS-Data\Server Reference\Server 2025 Files"
    

    1b. Download Azure Local install media.
        - Mount ISO, and copy content to "D:\TS-Data\Server Reference\Azure Local Files"


    2. Get Drivers from Physical Node (Manufacture install, and export drivers)
        - See script "ExtractDrivers.ps1"
        - Copy drivers to "D:\TS-Data\Server Reference\Windows Drivers"

    3. Install WinPE
       - needed to add PowerShell to the boot.wim


    This script will do the following.

    1a. Extract selected Server version from WIM
        Windows Server 2025 Standard
        Windows Server 2025 Standard (Desktop Experience)
        Windows Server 2025 Datacenter
        Windows Server 2025 Datacenter (Desktop Experience)

    1b. Extract selected Server version from WIM
        Azure Stack HCI

    2. Add Required Drivers
    3. Add Unattend.xml foreach server in the NODES list.
    4. Add Custom Start script to boot image, selects Unattended from first MAC address
    5. Add NODE setup script


#>
break

<#
# Hyper-V Nodes.
# ------------------------------------------------------------
$ProductKey = "N6W6X-H4P77-RJYTG-W77HT-RRKXT"
$PrepNodeScript = "D:\Deployment\Scripts\Physical\PrepHyperVNode.ps1"

$Nodes = @(
    [PSCustomObject]@{ Node = "HV-NODE-01"; IPAddress = "10.36.100.211"; Subnet = "255.255.255.0"; Gateway = "10.36.100.1"; DNSServers = @("8.8.8.8","8.8.4.4"); Interfaces = @("BC:24:11:9B:4E:56", "BC:24:11:16:DD:15") }
    [PSCustomObject]@{ Node = "HV-NODE-02"; IPAddress = "10.36.100.221"; Subnet = "255.255.255.0"; Gateway = "10.36.100.1"; DNSServers = @("8.8.8.8","8.8.4.4"); Interfaces = @("BC:24:11:20:95:20", "BC:24:11:06:66:6C") }
)
#>

<#
# Azure Local Nodes.
# ------------------------------------------------------------
$ProductKey = ""
$PrepNodeScript = "PrepAzureLocalNode.ps1"

$Nodes = @(
    [PSCustomObject]@{ Node = "AZ-NODE-01"; IPAddress = "10.36.100.231"; Subnet = "255.255.255.0"; Gateway = "10.36.100.1"; DNSServers = @("10.36.100.11","10.36.100.11"); Interfaces = @("BC:24:11:95:0E:15", "BC:24:11:43:C2:2E", "BC:24:11:D0:4F:57", "BC:24:11:3B:D0:26") }
    [PSCustomObject]@{ Node = "AZ-NODE-02"; IPAddress = "10.36.100.241"; Subnet = "255.255.255.0"; Gateway = "10.36.100.1"; DNSServers = @("10.36.100.11","10.36.100.11"); Interfaces = @("BC:24:11:48:8F:A0", "BC:24:11:6C:F0:10", "BC:24:11:4E:E7:B4", "BC:24:11:22:6C:CB") }
    [PSCustomObject]@{ Node = "AZ-NODE-03"; IPAddress = "10.36.100.251"; Subnet = "255.255.255.0"; Gateway = "10.36.100.1"; DNSServers = @("10.36.100.11","10.36.100.11"); Interfaces = @("BC:24:11:EC:32:FB", "BC:24:11:9F:49:EB", "BC:24:11:24:88:C4", "BC:24:11:A4:72:8C") }
    [PSCustomObject]@{ Node = "AZ-NODE-04"; IPAddress = "10.36.100.261"; Subnet = "255.255.255.0"; Gateway = "10.36.100.1"; DNSServers = @("10.36.100.11","10.36.100.11"); Interfaces = @() }
    [PSCustomObject]@{ Node = "AZ-NODE-05"; IPAddress = "10.36.100.271"; Subnet = "255.255.255.0"; Gateway = "10.36.100.1"; DNSServers = @("10.36.100.11","10.36.100.11"); Interfaces = @() }
)
#>

<#

    Add Network Information to the Arrays.

#>


# Set Defaults.
# ------------------------------------------------------------
$ScriptPath = "D:\Deployment\Scripts\Physical" ## Change
$TemplatePath = "D:\temp\ServerTemplates\$($Nodes.node[0].Substring(0,2))-NODES"
$ISOFiles = "D:\ISOfiles\template\iso" # For PVE ISO Share....
$MountPath = "D:\temp\wimmount"


# Ensure all Directories exist.
# ------------------------------------------------------------
If (!(Test-Path -Path "$TemplatePath")) {
    New-Item -Path "$TemplatePath" -ItemType Directory | Out-Null
}
if (!(Test-Path -Path "$TemplatePath\Unattends")) {
    New-Item -Path "$TemplatePath\Unattends" -ItemType Directory | Out-Null
}
If (!(Test-Path -Path "$ISOFiles")) {
    New-Item -Path "$ISOFiles" -ItemType Directory | Out-Null
}
If (!(Test-Path -Path "$MountPath")) {
    New-Item -Path "$MountPath" -ItemType Directory | Out-Null
}


# Locate the Data Drive.
# ------------------------------------------------------------
$ExcludeDrives = @()
$ExcludeDrives += $(($env:SystemDrive) -replace(":",""))
$ExcludeDrives += $(Get-Volume | Where-Object {$_.drivetype -eq 'CD-ROM'}).DriveLetter

$Drives = Get-Volume | Where {$_.DriveLetter -notin $ExcludeDrives -and $_.DriveLetter -ne $null}


# Find OEM drivers.
# ------------------------------------------------------------
$FoundDrivers = $Drives | foreach { Get-ChildItem -Path "$($_.DriveLetter):\" -Recurse -ErrorAction SilentlyContinue }
$FoundDrivers = $FoundDrivers | Where {$_.FullName -like "*2K25*" -and $_.FullName -like "*amd*"-and $_.Name -like "*inf"}
$FoundDrivers = $FoundDrivers | Where {$_.Name -ne "pvpanic-pci.inf" -and $_.Name -ne "smbus.inf"} | Select-Object -Unique


# Find all instances of Install.Wim om THIS computer.
# ------------------------------------------------------------
$FoundImages = $Drives | foreach { (Get-ChildItem -Path "$($_.DriveLetter):\" -Recurse -filter "install.wim" -ErrorAction SilentlyContinue).FullName } | Where-Object { $_ }
$FoundImages = $FoundImages | Where {$_ -notlike "*$TemplatePath*"}


if ($FoundImages.GetType().BaseType -eq "System.Array") {

    $Images = @()
    Foreach ($Image in $FoundImages) {

        $ImageInfo = Get-WindowsImage -ImagePath $Image | Select-Object -Property ImageIndex, ImageName
        $ImageData = $ImageInfo | % { [PSCustomObject]@{ Name = $_.ImageName;  Index = $_.ImageIndex; Path = $Image } }
        $Images += $ImageData

    }
    $SelectedImage = $Images | Out-GridView -OutputMode Single

} else {
    $ImageInfo = Get-WindowsImage -ImagePath $FoundImages | Select-Object -Property ImageIndex, ImageName | Out-GridView -OutputMode Single
    $SelectedImage = $ImageInfo | % { [PSCustomObject]@{ Name = $_.ImageName;  Index = $_.ImageIndex; Path = $FoundImages } }
}


<# --- #>


# Copy Installation files.
# ------------------------------------------------------------
Copy-Item -Path "$(Split-Path (Split-Path $SelectedImage.path))\*" -Destination $TemplatePath -Recurse -Exclude @("*install.wim*") -Force


# Copy Startup Scripts
# ------------------------------------------------------------
if (Test-Path -Path "$ScriptPath\$PrepNodeScript" -ErrorAction SilentlyContinue) {
    if (!(Test-Path -Path "$TemplatePath\Sources\`$OEM`$\`$1\TS-Data")) {
        New-Item -Path "$TemplatePath\Sources\`$OEM`$\`$1\TS-Data" -ItemType Directory | Out-Null
    }
    Copy-Item "$ScriptPath\$PrepNodeScript" -Destination "$TemplatePath\Sources\`$OEM`$\`$1\TS-Data\BootStrap.ps1" -Force
}



# Copy Hyper-V scripts.
# ------------------------------------------------------------
if ($Nodes.Node[0] -like "HV*") {
    $HyperVScriptPath = Split-Path $ScriptPath -Parent

    if (Test-Path -Path "$HyperVScriptPath\Hyper-V" -ErrorAction SilentlyContinue) {
        if (!(Test-Path -Path "$TemplatePath\Sources\`$OEM`$\`$1\TS-Data\HyperV")) {
            New-Item -Path "$TemplatePath\Sources\`$OEM`$\`$1\TS-Data\HyperV" -ItemType Directory | Out-Null
        }
        Copy-Item "$HyperVScriptPath\Hyper-V\" -Destination "$TemplatePath\Sources\`$OEM`$\`$1\TS-Data\HyperV\" -Recurse -Force
    }
}


# Extract Server WIM
# ------------------------------------------------------------
if (Test-Path -Path "$TemplatePath\Sources\Install.wim") {
    Remove-Item -Path "$TemplatePath\Sources\Install.wim" -Force
}
if (!(Test-Path -Path "$TemplatePath\Sources\Install.wim")) {
    Export-WindowsImage -SourceImagePath $($SelectedImage.Path) -SourceIndex $($SelectedImage.Index) -DestinationImagePath "$TemplatePath\Sources\Install.wim" -DestinationName $($SelectedImage.Name) | Out-Null
} else {
    throw "Install wim still exists"
}


<# --- #>


# Mount Install.wim
# ------------------------------------------------------------
Mount-WindowsImage -ImagePath "$TemplatePath\Sources\Install.wim" -Index 1 -Path $MountPath | Out-Null


# Add Drivers
# ------------------------------------------------------------
$FoundDrivers | foreach { Add-WindowsDriver -Path $MountPath -Driver $_.FullName }


# Enable Hyper-V
# ------------------------------------------------------------
Get-WindowsOptionalFeature -Path $MountPath -FeatureName *Hyper-V* | ForEach-Object {
    Try {
        Enable-WindowsOptionalFeature -Path $MountPath -FeatureName $_.FeatureName -All -ErrorAction Stop | Out-Null
    } Catch {
        Write-Verbose "Skipping feature $($_.FeatureName): $_"
    }
}



# Enable Clustering.
# ------------------------------------------------------------
if ($Nodes.Node[0] -like "AZ*") {
    Get-WindowsOptionalFeature -Path $MountPath -FeatureName *Cluster* | ForEach-Object {
        Try {
            Enable-WindowsOptionalFeature -Path $MountPath -FeatureName $_.FeatureName -All -ErrorAction Stop | Out-Null
        } Catch {
            Write-Verbose "Skipping feature $($_.FeatureName): $_"
        }
    }
}



# Save Install.wim
# ------------------------------------------------------------
Dismount-WindowsImage -Path $MountPath -Save | Out-Null


<# --- #>


# Mount BOOT.wim
# ------------------------------------------------------------
Mount-WindowsImage -ImagePath "$TemplatePath\sources\boot.wim" -Index 2 -Path $MountPath | Out-Null


# Add Storage Drivers
# ------------------------------------------------------------
$FoundDrivers | Where {$_.name -match "vioscsi|viostor|netkvm"} | foreach { Add-WindowsDriver -Path $MountPath -Driver $_.fullname } | Out-Null
<#
Get-WindowsDriver -Path $MountPath
#>


# Add PowerShell and required modules.
# ------------------------------------------------------------
Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\" | `
    Where {$_.Name -in @("WinPE-WMI.cab", "WinPE-NetFX.cab", "WinPE-PowerShell.cab") } |`
        ForEach-Object { Add-WindowsPackage -Path $MountPath -PackagePath $_.FullName | Out-Null }


# Create Powershell Startup script
# ------------------------------------------------------------
$newstart = @()
$newstart += "# Just for fun.."
$newstart += "# ------------------------------------------------------------"
$newstart += "Write-Output `"  _                     _ _               _   _             _   _                 _          _ `""
$newstart += "Write-Output `" | |                   | (_)             | | | |           | | | |               | |        | |`""
$newstart += "Write-Output `" | |     ___   __ _  __| |_ _ __   __ _  | | | |_ __   __ _| |_| |_ ___ _ __   __| | ___  __| |`""
$newstart += "Write-Output `" | |    / _ \ / _```` |/ _```` | | '_ \ / _```` | | | | | '_ \ / _```` | __| __/ _ \ '_ \ / _```` |/ _ \/ _```` |`""
$newstart += "Write-Output `" | |___| (_) | (_| | (_| | | | | | (_| | | |_| | | | | (_| | |_| ||  __/ | | | (_| |  __/ (_| |`""
$newstart += "Write-Output `" \_____/\___/ \__,_|\__,_|_|_| |_|\__, |  \___/|_| |_|\__,_|\__|\__\___|_| |_|\__,_|\___|\__,_|`""
$newstart += "Write-Output `"                                   __/ |                                                       `""
$newstart += "Write-Output `"                                  |___/                                                        `""
$newstart += ""
$newstart += ""
$newstart += "wpeinit"
$newstart += "Start-Sleep -Seconds 10"
$newstart += ""
$newstart += ""
$newstart += "# Get first active MAC"
$newstart += "# ------------------------------------------------------------"
$newstart += "`$MacAddress = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object {`$_.NetEnabled -eq `$true} | Select-Object MACAddress | Select-Object -First 1 -ExpandProperty MacAddress"
$newstart += "`$MacAddress = `$MacAddress -replace(`":`",`"-`")"
$newstart += "Write-Host `"Found MacAddress: `$MacAddress`""
$newstart += ""
$newstart += ""
$newstart += "# Find install media"
$newstart += "# ------------------------------------------------------------"
$newstart += "`$MediaDrives = Get-CimInstance -ClassName Win32_Volume | Where {`$_.drivetype -eq 5} | Select-Object DriveLetter"
$newstart += "`$InstallMedia = `$MediaDrives | Where { (Test-Path -Path  `"`$(`$_.DriveLetter)\Sources`") -and (Test-Path -Path  `"`$(`$_.DriveLetter)\Unattends`") } | Select-Object -ExpandProperty DriveLetter"
$newstart += "Write-Host `"Found Installation Media: `$InstallMedia`""
$newstart += ""
$newstart += ""
$newstart += "# Define unattend file"
$newstart += "# ------------------------------------------------------------"
$newstart += "`$UnattendFile = `"`$InstallMedia\Unattends\`$MacAddress.xml`""
$newstart += "Write-Host `"Path to Unattended.xml `$UnattendFile`""
$newstart += ""
$newstart += ""
$newstart += "# Launch Setup.exe"
$newstart += "# ------------------------------------------------------------"
$newstart += "if (Test-Path `$UnattendFile) {"
$newstart += "    Write-Host `"Running setup with `$UnattendFile`""
$newstart += "    Start-Process -FilePath `"$InstallMedia\setup.exe`" -ArgumentList `"/unattend:`$UnattendFile`" -Wait"
$newstart += "} else {"
$newstart += "    Write-Host `"Running setup without unattend`""
$newstart += "    Start-Process -FilePath `"$InstallMedia\setup.exe`" -Wait"
$newstart += "}"
$newstart += ""
$newstart += "Start-Sleep -Seconds 30"
$newstart += "exit 0"

$newstart | Out-File -FilePath "$MountPath\windows\temp\Start-Setup.ps1" -Encoding utf8 -Force


# Change Boot sequence..
# ------------------------------------------------------------
$winpeshl = @()
$winpeshl += "[LaunchApps]"
$winpeshl += "%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe, -NoProfile -ExecutionPolicy Bypass -File `"%SYSTEMROOT%\Temp\Start-Setup.ps1`""

$winpeshl  | Out-File -FilePath "$MountPath\windows\system32\winpeshl.ini" -Encoding oem


# Save Boot image
# ------------------------------------------------------------
Dismount-WindowsImage -Path $MountPath -Save | Out-Null


# Import module New-ISOFIle.ps1
# - Source : https://github.com/TheDotSource/New-ISOFile/blob/main/New-ISOFile.ps1
# ------------------------------------------------------------
Import-Module -Name "D:\Deployment\Scripts\Functions\New-ISOFile.ps1" -Force -Verbose
Import-Module -Name "D:\Deployment\Scripts\Functions\new-Unattend.ps1" -Force -Verbose


foreach ($Node in $Nodes) {

    # Add Unattend Files....
    # ------------------------------------------------------------
    if (Test-Path -Path "$TemplatePath\Unattends") {

        $FileName = "$TemplatePath\Unattends\$($Node.Interfaces[0] -replace(":","-")).xml"

        $RandomPassword = $(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 25 | ForEach-Object {[char]$_}))

        if ($Node.DNSServers[0] -match "10.36.\b+") {
        
            New-Unattend -ComputerName $Node.Node -RunAtStartup "BootStrap.ps1" -Interfaces $Node.Interfaces -ProductKey $ProductKey `
                -AdminUsername "Administrator" -AdminPassword $RandomPassword -DomainName "Fabric.SecInfra.Dk" `
                -IPAddress $Node.IPAddress -SubnetMask $Node.Subnet -Gateway $Node.Gateway -DNSServers $Node.DNSServers | Out-File "$FileName" -Encoding utf8 -Force
        
        } else {

            New-Unattend -ComputerName $Node.Node -RunAtStartup "BootStrap.ps1" -Interfaces $Node.Interfaces -ProductKey $ProductKey `
                -AdminUsername "Administrator" -AdminPassword $RandomPassword `
                -IPAddress $Node.IPAddress -SubnetMask $Node.Subnet -Gateway $Node.Gateway -DNSServers $Node.DNSServers | Out-File "$FileName" -Encoding utf8 -Force

        }
    }
}


# Make ISO
# ------------------------------------------------------------ 
if (Test-Path -Path $ISOFiles) {
    $IsoFileName = Split-Path -Path $TemplatePath -Leaf
    New-ISOFile -source $TemplatePath -destinationIso "$ISOFiles\$IsoFileName.iso" -bootFile "$TemplatePath\efi\microsoft\boot\efisys_noprompt.bin" -title "$($Node.Node)" -force
}
