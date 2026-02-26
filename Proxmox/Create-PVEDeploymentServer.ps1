<# 

    Create Deployment server.
    4 vCpu
    8Gb Ram
    50Gb OS Drive
    100GB Data Drive


    Download Server 2025 Eval.
    https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso

    Download VirtIO Drivers.
    https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso
    

    Do the Windows Installation.

#>


# Required to import unsigned modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false


# Name of the "Master" VM
# ------------------------------------------------------------
$VMName = "Deployment"


# Path to PVE scripts and Functions.
# ------------------------------------------------------------
$RootPath          = "G:\Shares\Personal Github\LAB-Deployment" # "C:\GitClone"
$ScriptPath        = "G:\Shares\Personal Github\PVE-Platform" # Join-Path -Path $RootPath -ChildPath "PVE-Platform"


# Import PVE modules
# ------------------------------------------------------------
Get-ChildItem -Path "$ScriptPath\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


# Import required Shared Modules ( MOVE Shared Functions )
# ------------------------------------------------------------
@("New-ISOFile.ps1", "new-Unattend.ps1") | ForEach-Object {
    If (Test-Path "G:\PhysicalDriveBackup\Shares\New Github Repos\Shared Functions\$($_)") {
        Import-Module -Name "G:\PhysicalDriveBackup\Shares\New Github Repos\Shared Functions\$($_)" -Force
    }
}


# Connect to PVE Cluster
# ------------------------------------------------------------
$PVESecret  = Get-Content "$ScriptPath\PVE-Secret.json" | Convertfrom-Json
$PVEConnect = PVE-Connect -Authkey "$($PVESecret.User)!$($PVESecret.TokenID)=$($PVESecret.Token)" -Hostaddr $($PVESecret.Host)


# Get information required to create the template (VM)
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers
$ISOStorage  = ((Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage" -Headers $($PVEConnect.Headers)).data | Where {$_.content -like "*iso*" -and $_.type -eq "dir"}).storage


# Download Windows Server 2025 EVAL Iso
# ------------------------------------------------------------
$DownloadBody  = "content=iso"
$DownloadBody += "&node=$($PVELocation.name)"
$DownloadBody += "&url=$([uri]::EscapeDataString("https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"))"
$DownloadBody += "&filename=$([uri]::EscapeDataString("Server2025.iso"))"

$2025Result = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage/$ISOStorage/download-url" -Headers $($PVEConnect.Headers) -Body $DownloadBody


# Download VirtIO Windows Drivers.
# ------------------------------------------------------------
$DownloadBody  = "content=iso"
$DownloadBody += "&node=$($PVELocation.name)"
$DownloadBody += "&url=$([uri]::EscapeDataString("https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso"))"
$DownloadBody += "&filename=$([uri]::EscapeDataString("virtio-win.iso"))"

$DriverResult = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage/$ISOStorage/download-url" -Headers $($PVEConnect.Headers) -Body $DownloadBody


# Wait all 3 downloads.
# ------------------------------------------------------------
Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $2025Result.data
Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $DriverResult.data


# Next avalible High VMID
# ------------------------------------------------------------
#$VMID = Get-PVENextID -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $($PVEConnect.Headers)
$VMID = "99999901"


# Create Temp folder, to be converted to ISO.
# ------------------------------------------------------------
If (-NOT(Test-Path -Path "$($env:TEMP)\$VMID")) {
    New-Item -Path "$($env:TEMP)\$VMID" -ItemType Directory | Out-Null
}


##############################################################


<#
    
    Clone GIT Repo to C:\Scripts

#>
if (-Not(Test-Path -Path "$($env:TEMP)\$VMID\Scripts")) {
    New-Item -Path "$($env:TEMP)\$VMID\Scripts" -ItemType Directory | Out-Null
}
Copy-Item -Path "**GIT**\*" -Destination "$($env:TEMP)\$VMID\Scripts" -Recurse -Force


##############################################################


# Create AutoUnattended.iso
# ------------------------------------------------------------
<#

    Encode the FirstLogonCommands !

    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("GCI (((Get-Volume -FileSystemLabel `"virtio-win*`").DriveLetter) + `":\`") -Recurse -Include *.inf | ? { `$_.FullName -match `"2K25`" -and `$_.FullName -match `"AMD`" } | % { pnputil /add-Driver `$_.FullName /install }"))
    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Get-Volume | Foreach { if (Test-Path -Path `"`$(`$_.DriveLetter):\Scripts`") { Copy-Item -Path `"`$(`$_.DriveLetter):\Scripts`" -Destination `"`$(`$env:SystemDrive)`" -Recurse -Force -ErrorAction SilentlyContinue } }"))

#>
New-Unattend -ComputerName $VMName -AdminUsername "Administrator" -AdminPassword "P@ssw0rd2025$" `
    -FirstLogonCommands @(
        [PSCustomObject]@{ Name = "Add Drivers";  Command = "PowerShell -NoProfile -ExecutionPolicy Bypass -EncodedCommand RwBDAEkAIAAoACgAKABHAGUAdAAtAFYAbwBsAHUAbQBlACAALQBGAGkAbABlAFMAeQBzAHQAZQBtAEwAYQBiAGUAbAAgACIAdgBpAHIAdABpAG8ALQB3AGkAbgAqACIAKQAuAEQAcgBpAHYAZQBMAGUAdAB0AGUAcgApACAAKwAgACIAOgBcACIAKQAgAC0AUgBlAGMAdQByAHMAZQAgAC0ASQBuAGMAbAB1AGQAZQAgACoALgBpAG4AZgAgAHwAIAA/ACAAewAgACQAXwAuAEYAdQBsAGwATgBhAG0AZQAgAC0AbQBhAHQAYwBoACAAIgAyAEsAMgA1ACIAIAAtAGEAbgBkACAAJABfAC4ARgB1AGwAbABOAGEAbQBlACAALQBtAGEAdABjAGgAIAAiAEEATQBEACIAIAB9ACAAfAAgACUAIAB7ACAAcABuAHAAdQB0AGkAbAAgAC8AYQBkAGQALQBEAHIAaQB2AGUAcgAgACQAXwAuAEYAdQBsAGwATgBhAG0AZQAgAC8AaQBuAHMAdABhAGwAbAAgAH0A" }
        [PSCustomObject]@{ Name = "Copy Scripts"; Command = "PowerShell -NoProfile -ExecutionPolicy Bypass -EncodedCommand RwBlAHQALQBWAG8AbAB1AG0AZQAgAHwAIABGAG8AcgBlAGEAYwBoACAAewAgAGkAZgAgACgAVABlAHMAdAAtAFAAYQB0AGgAIAAtAFAAYQB0AGgAIAAiACQAKAAkAF8ALgBEAHIAaQB2AGUATABlAHQAdABlAHIAKQA6AFwAUwBjAHIAaQBwAHQAcwAiACkAIAB7ACAAQwBvAHAAeQAtAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAiACQAKAAkAF8ALgBEAHIAaQB2AGUATABlAHQAdABlAHIAKQA6AFwAUwBjAHIAaQBwAHQAcwAiACAALQBEAGUAcwB0AGkAbgBhAHQAaQBvAG4AIAAiACQAKAAkAGUAbgB2ADoAUwB5AHMAdABlAG0ARAByAGkAdgBlACkAIgAgAC0AUgBlAGMAdQByAHMAZQAgAC0ARgBvAHIAYwBlACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlACAAfQAgAH0A" }
    ) | `
    Out-File -FilePath "$($env:TEMP)\$VMID\AutoUnattend.xml" -Encoding utf8 -Force


# Create Unattended ISO
# ------------------------------------------------------------
$null = New-ISOFile -source "$($env:TEMP)\$VMID" -destinationIso "$($env:TEMP)\$VMID.iso" -force


# Upload ISO to PVE Node.
# ------------------------------------------------------------
$null = Upload-PVEISO -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $($PVEConnect.Headers) -Node $($PVELocation.Name) -Storage $ISOStorage -IsoPath "$($env:TEMP)\$VMID.iso"


# Get ISO Content and Add the files to the Deployment VM
$ISOFiles      = ((Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage/$ISOStorage/content" -Headers $($PVEConnect.Headers)).data).volid
$DriverMedia   = $ISOFiles | Where {$_ -like "*virtio*.iso"}
$InstallMedia  = $ISOFiles | Where {$_ -like "*Server2025*.iso"}
$UnattendMedia = $ISOFiles | Where {$_ -like "*$VMID*.iso"}


# Default Deployent Sever Configuration
# ------------------------------------------------------------
$Body = "node=$($PVELocation.Name)"
$Body += "&vmid=$VMID"
$Body += "&name=$VMName"
$Body += "&bios=ovmf"
$Body += "&cpu=x86-64-v2-AES"
$Body += "&ostype=win11"
$Body += "&machine=pc-q35-9.0"
$Body += "&tpmstate0=$([uri]::EscapeDataString("$($PVELocation.storage):1,size=4M,version=v2.0"))"
$Body += "&efidisk0=$([uri]::EscapeDataString("$($PVELocation.storage):1,efitype=4m,format=raw,pre-enrolled-keys=1"))"
$Body += "&net0=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1"))"
$Body += "&boot=$([uri]::EscapeDataString("order=scsi0;ide2"))"
$Body += "&scsihw=virtio-scsi-single"
$Body += "&memory=8192"
$Body += "&balloon=2048"
$Body += "&cores=4"
$Body += "&scsi0=$([uri]::EscapeDataString("$($PVELocation.storage):50,ssd=on,format=raw"))"
$Body += "&scsi1=$([uri]::EscapeDataString("$($PVELocation.storage):200,ssd=on,format=raw"))"
$Body += "&ide0=$([uri]::EscapeDataString("$InstallMedia,media=cdrom"))"
$Body += "&ide1=$([uri]::EscapeDataString("$DriverMedia,media=cdrom"))"
$Body += "&ide2=$([uri]::EscapeDataString("$UnattendMedia,media=cdrom"))"


# Create the Template VM
# ------------------------------------------------------------
$VMCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/" -Body $Body -Method POST -Headers $($PVEConnect.Headers)
Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $VMCreate.data


# Start new server
# ------------------------------------------------------------
$null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/status/start" -Headers $($PVEConnect.Headers) -Method POST
