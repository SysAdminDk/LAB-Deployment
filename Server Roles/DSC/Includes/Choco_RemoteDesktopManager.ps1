Feature Choco_RemoteDesktopManager {
    # Example: ensure Remote Desktop Manager (from Chocolatey) is installed
    Script InstallRDM {
        SetScript = {
            & "$env:ProgramData\chocolatey\bin\choco.exe" install rdm -y --no-progress
        }
        TestScript = {
            Test-Path "C:\Program Files\Devolutions\Remote Desktop Manager\RemoteDesktopManager.exe"
        }
        GetScript = {
            @{ Result = (& "$env:ProgramData\chocolatey\bin\choco.exe" list  | Select-String "rdm") }
        }
        DependsOn = "[Script]InstallChocolatey"
    }
}
