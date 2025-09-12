function Feature_Chocolatey {
    # Ensure Chocolatey is installed
    Script InstallChocolatey {
        SetScript = {
            if (-not (Test-Path "$env:ProgramData\chocolatey\bin\choco.exe")) {
                Write-Verbose "Installing Chocolatey..."
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Set-ExecutionPolicy Bypass -Scope Process -Force
                $script = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
                Invoke-Expression $script
            }
        }
        TestScript = {
            Test-Path "$env:ProgramData\chocolatey\bin\choco.exe"
        }
        GetScript = {
            @{ Result = (Test-Path "$env:ProgramData\chocolatey\bin\choco.exe") }
        }
    }
}
