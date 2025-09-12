$Featuers = Get-WindowsFeature -Name RSAT-*

$FileData = @()
$FileData += "function RSATFeatures {"

$Featuers | ForEach-Object {

    $FileData += "    # Ensure Feature $($_.DisplayName) are installed"
    $FileData += "    WindowsFeature $($_.Name) {"
    $FileData += "        Name   = `"$($_.Name)`""
    $FileData += "        Ensure = `"Present`""
    $FileData += "    }"
    $FileData += ""
}

$FileData += "}"

