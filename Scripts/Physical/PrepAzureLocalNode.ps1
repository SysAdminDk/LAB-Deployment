<#

    Auto Configure Azure Local node

#>


# Clear Autologin
# ------------------------------------------------------------
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value '0' -ErrorAction SilentlyContinue


# Cleanup System drive
# ------------------------------------------------------------
if (Test-Path -Path "$($ENV:SystemDrive)\Windows.old") {
    Remove-Item -Path "$($ENV:SystemDrive)\Windows.old" -Force
}


# Change Administrator password and show on screen.
# ------------------------------------------------------------
if (!((gwmi win32_computersystem).partofdomain)) {
    $NewPassword = $(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 15 | ForEach-Object {[char]$_}))
    $SecurePassword = ConvertTo-SecureString -string $NewPassword -AsPlainText -Force
    Set-LocalUser -Name Administrator -Password $SecurePassword

    $PwdCmd = @()
    $PwdCmd += "Write-Host `"=== IMPORTANT: Temporary local admin password ===`"`r`n" 
    $PwdCmd += "write-host `"`"`r`n" 
    $PwdCmd += "write-host `"Username : Administrator`r`n"
    $PwdCmd += "write-host `"Password : $NewPassword`r`n"
    $PwdCmd += "write-host `"`"`r`n" 
    $PwdCmd += "Write-Host `"Please take a note of it or change to a known`"`r`n" 
    $PwdCmd += "Write-Host `"RDP access is avalible on $($CurrentIP.IPAddress)`"`r`n" 
    $PwdCmd += "write-host `"`"`r`n" 
    $PwdCmd += "Read-Host -Prompt 'Press ENTER to close this window'`r`n" 
    $PwdCmd += "exit`r`n"

    Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoExit -Command $PwdCmd"

}
