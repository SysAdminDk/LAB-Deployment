Function Move-PVEVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$ProxmoxAPI,
        [Parameter(Mandatory)][object]$Headers,
        [Parameter(Mandatory)][string]$VMID,
        [Parameter(Mandatory)][string]$SourceNode,
        [Parameter(Mandatory)][string]$TargetNode,
        [string]$Targetstorage,
        [switch]$Wait
    )

    $body = "vmid=$VMID"
    $body += "&target=$TargetNode"
    if ($Targetstorage) {
        $body += "&targetstorage=$Targetstorage"
    }

    try {
        $MoveStatus = Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$SourceNode/qemu/$VMID/migrate" -Body $body -Method Post -Headers $Headers
    }
    Catch {
        if ($_ -like "*target is local*") {
            Write-Warning "Target is local node"
        } else {
            $_
        }
    }

    if ($Wait) {
        Start-PVEWait -ProxmoxAPI $ProxmoxAPI -Headers $Headers -node $SourceNode -taskid $MoveStatus.data
    } else {
        return
    }
}