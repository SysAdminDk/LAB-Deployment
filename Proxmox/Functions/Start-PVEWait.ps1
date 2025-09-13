function Start-PVEWait {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ProxmoxAPI,
        [Parameter(Mandatory)][object]$Headers,
        [Parameter(Mandatory)][string]$Node,
        [Parameter(Mandatory)][string]$Taskid
    )

    $TimeoutSeconds = 600
    $StartTime = Get-Date
    $EndTime = $startTime.AddSeconds($TimeoutSeconds)

    do {
        $TaskStatus = Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$Node/tasks/$Taskid/status" -Headers $headers
        $TaskStatus.data.status
        if ($TaskStatus.data.status -ne "running") {
            Write-Progress -Activity "Waiting for PVE Task ($($TaskStatus.data.type))" -Status "Completed" -PercentComplete 100
            return
        }

        $Elapsed = (Get-Date) - $StartTime
        $Percent = [math]::Min(($elapsed.TotalSeconds / $TimeoutSeconds) * 100, 100)
        
        Write-Progress -Activity "Waiting for PVE Task ($($TaskStatus.data.type))" -Status "Running" -PercentComplete $Percent
        Start-Sleep -Seconds 5

    } while ($true)
}
