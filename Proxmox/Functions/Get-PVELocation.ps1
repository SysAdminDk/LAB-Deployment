function Get-PVELocation {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory)][string]$ProxmoxAPI,
        [Parameter(Position=1,Mandatory)][object]$Headers
    )


    # Get NODE info
    # ------------------------------------------------------------
    Write-Verbose "Get Proxmox Nodes"

    Try {
        $NodesData = @()

        $NodesQuery = (Invoke-RestMethod -Uri "$ProxmoxAPI/cluster/status" -Headers $Headers).data | Where {$_.type -eq "node"}
        
        foreach ($Node in $NodesQuery) {
            $NodeDataArray = @(
                [PSCustomObject]@{ Name = $Node.Name; }
            )
            $NodesData += $NodeDataArray
        }
    }
    Catch {
        Write-Error "Unable to get any available nodes...."
    }


    # Get Storage info
    # ------------------------------------------------------------
    Write-Verbose "Get Proxmox Nodes Storage"

    Try {
        $StorageData = @()

        foreach ($Node in $NodesData) {
            $NodeStorageQuery = (Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$($Node.name)/storage" -Headers $Headers).data | Where {$_.content -like "*images*"}

            foreach ($Storage in $NodeStorageQuery) {
                $NodeStorageArray = @(
                    [PSCustomObject]@{ Name    = $Node.Name;
                                       Storage = $Storage.storage;
                                       Avail   = [math]::round($Storage.avail / 1Gb);
                                       Used    = [math]::round($Storage.used / 1Gb);
                                       Total   = [math]::round($Storage.total / 1Gb);
                                     }
                )
                $StorageData += $NodeStorageArray
            }
        }

        $StorageData = $StorageData | where {$_.avail -ne 0}

    }
    Catch {
        Write-Error "Unable to get any available storage on any nodes"
    }


    # Get Network info
    # ------------------------------------------------------------
    Write-Verbose "Get Proxmox Bridge"

    Try {
        $BridgeData = @()

        foreach ($Node in $NodesData) {

            $NodeBridgeQuery = ((Invoke-RestMethod -Uri "$ProxmoxAPI/nodes/$($Node.name)/network" -Method Get -Headers $Headers).data | where {$_.Type -eq "bridge"}) | Select-Object iface,address,cidr

            foreach ($Bridge in $NodeBridgeQuery) {
                $NodeBridgeArray = @(
                    [PSCustomObject]@{ Name    = $Node.Name;
                                       Address = $Bridge.address;
                                       Network = $Bridge.cidr;
                                       Interface = $Bridge.iface;
                                     }
                )
                $BridgeData += $NodeBridgeArray
            }
        }
    }
    Catch {
        $Switch = ""
    }


    # Join the arrays and show selection
    # ------------------------------------------------------------
    $Result = foreach ($a in $StorageData) {
        foreach ($b in $BridgeData | Where-Object { $_.Name -eq $a.Name }) {
            [PSCustomObject]@{ Name      = $a.Name
                               Storage   = $a.Storage
                               Avail     = $a.Avail
                               Used      = $a.Used
                               Total     = $a.Total
                               #Address   = $b.Address
                               #Network   = $b.Network
                               Interface = $b.Interface
                            }
        }
    }

    $VMLocation = $Result | Out-GridView -Title "Select Node, Storage and network for the new VM" -OutputMode Single
    return $VMLocation
}
