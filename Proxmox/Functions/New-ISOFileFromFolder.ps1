<#
    ORG - https://github.com/waldo1001/Cloud.Ready.Software.PowerShell/tree/master/PSModules/Cloud.Ready.Software.Windows
#>
Function New-ISOFileFromFolder{
    <#
        .SYNOPSIS
        Creates an ISO file from a filepath
    #>
    param(
        [Parameter(Mandatory=$true)]
        [String]$FilePath,
        [Parameter(Mandatory=$true)]
        [String]$Name,
        [Parameter(Mandatory=$true)]
        [String]$ResultFullFileName
    )

    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $dftd = New-Object -ComObject IMAPI2.MsftDiscFormat2Data
    $Recorder = New-Object -ComObject IMAPI2.MsftDiscRecorder2

    $fsi.FileSystemsToCreate = 7
    $fsi.VolumeName = $Name
    $fsi.FreeMediaBlocks = 1000000  #default 332800

    
    $fsi.Root.AddTreeWithNamedStreams($FilePath,$false)
    
    $resultimage = $fsi.CreateResultImage()
    $resultStream = $resultimage.ImageStream

    Write-IStreamToFile $resultStream $ResultFullFileName
}