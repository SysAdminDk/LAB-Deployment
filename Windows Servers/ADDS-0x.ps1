<#
    ______                      _         _____             _             _ _               
    |  _  \                    (_)       /  __ \           | |           | | |              
    | | | |___  _ __ ___   __ _ _ _ __   | /  \/ ___  _ __ | |_ _ __ ___ | | | ___ _ __ ___ 
    | | | / _ \| '_ ` _ \ / _` | | '_ \  | |    / _ \| '_ \| __| '__/ _ \| | |/ _ \ '__/ __|
    | |/ / (_) | | | | | | (_| | | | | | | \__/\ (_) | | | | |_| | | (_) | | |  __/ |  \__ \
    |___/ \___/|_| |_| |_|\__,_|_|_| |_|  \____/\___/|_| |_|\__|_|  \___/|_|_|\___|_|  |___/


    Install & Configure Additional Domain Controllers.
#>


# Verify Domain Membership
# ------------------------------------------------------------
if (!((gwmi win32_computersystem).partofdomain)) {
    
    Throw "Domain join have must have failed"

}


if ((gwmi win32_computersystem).partofdomain) {

    # Install ADDS & DNS
    # --------------------------------------------------------------------------------------------------
    if ((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Available") {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }


    # Gennerate Safe Mode Password.
    # ------------------------------------------------------------
    $PWString = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 25 | ForEach-Object {[char]$_})
    $SecurePassword = ConvertTo-SecureString -string $PWString -AsPlainText -Force


    # Promote domain controller
    # ------------------------------------------------------------
    Install-ADDSDomainController -DomainName $ENV:USERDNSDOMAIN -SafeModeAdministratorPassword $SecurePassword -NoRebootOnCompletion -Confirm:$false -Credential $Credentials

}



# Cleanup when Domain is up and running.
# --------------------------------------------------------------------------------------------------
Try {
    $DomainQuery = Get-ADDomain -Identity $DomainName -ErrorAction SilentlyContinue
}
Catch {
    Write-Host "Domain not created yet, continue script"
}

if ( ((gwmi win32_computersystem).partofdomain) -and ($null -ne $DomainQuery) ) {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -name "AutoAdminLogon" -value 0
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -name "AutoLogonCount" -value 0
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -name "DefaultUserName " -value ""
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -name "DefaultDomainName" -value ""
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Install Domain" -Force -ErrorAction SilentlyContinue
}