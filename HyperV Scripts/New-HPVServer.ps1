param (
    [cmdletbinding()]
    [Parameter(ValueFromPipeline)]
    [string]$NewVMFQDN,
    [string]$MachineOU,
    [string]$DomainJoin,
    [string]$NewVmIp,
    [string]$LocalUsername,
    [string]$LocalPassword,
    [int]$VMMemory,
    [int]$VMCores,
    [string]$OSDisk,
    [object]$DefaultConnection,
    [object]$DefaultLocation,
    [switch]$Start
)


# Path to PVE scripts and Functions.
# ------------------------------------------------------------
$RootPath = "D:\PVE Scripts"

