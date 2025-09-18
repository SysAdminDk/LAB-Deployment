# Cleanup AutoLogon and Run registry
# --------------------------------------------------------------------------------------------------
$AutoLoginData = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

if ($AutoLoginData.AutoLogonCount -ne 0) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoLogonCount" -value 0
}
if ($AutoLoginData.AutoAdminLogon -ne 0) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AutoAdminLogon" -value 0
}
if ($AutoLoginData.DefaultUserName) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultUserName" -value $null -Force
}
if ($AutoLoginData.DefaultPassword) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $null -Force
}
if ($AutoLoginData.DefaultDomainName) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $null -Force
}
