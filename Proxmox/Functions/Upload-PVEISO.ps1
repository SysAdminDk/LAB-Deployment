function Upload-PVEISO {
    param(
        [string]$ProxmoxAPI,
        [Object]$Headers,
        [string]$Node,
        [string]$Storage,
        [string]$IsoPath
    )


    if ($(Get-Item $IsoPath).Length -gt (100MB)) {
        throw "ISO file is too large, max allowed size is 100MB."
    }

    $fileName = [System.IO.Path]::GetFileName($IsoPath)
    $url = "$ProxmoxAPI/nodes/$Node/storage/$Storage/upload"

    $boundary = [System.Guid]::NewGuid().ToString()

    $bodyLines = @()
    $bodyLines += "--$boundary"
    $bodyLines += 'Content-Disposition: form-data; name="content"'
    $bodyLines += ""
    $bodyLines += "iso"
    $bodyLines += "--$boundary"
    $bodyLines += "Content-Disposition: form-data; name=""filename""; filename=""$fileName"""
    $bodyLines += "Content-Type: application/octet-stream"
    $bodyLines += ""

    $preBytes = [Text.Encoding]::ASCII.GetBytes(($bodyLines -join "`r`n") + "`r`n")
    $fileBytes = [System.IO.File]::ReadAllBytes($IsoPath)
    $postBytes = [System.Text.Encoding]::ASCII.GetBytes("`r`n--$boundary--`r`n")

    $allBytes = New-Object byte[] ($preBytes.Length + $fileBytes.Length + $postBytes.Length)
    [Array]::Copy($preBytes, 0, $allBytes, 0, $preBytes.Length)
    [Array]::Copy($fileBytes, 0, $allBytes, $preBytes.Length, $fileBytes.Length)
    [Array]::Copy($postBytes, 0, $allBytes, $preBytes.Length + $fileBytes.Length, $postBytes.Length)

    $request = [System.Net.HttpWebRequest]::Create($url)
    $request.Method = "POST"
    $request.Headers.Add("Authorization", $Headers["Authorization"])
    $request.Accept = "application/json"
    $request.ContentType = "multipart/form-data; boundary=$boundary"
    $request.ContentLength = $allBytes.Length

    $reqStream = $request.GetRequestStream()
    $reqStream.Write($allBytes, 0, $allBytes.Length)
    $reqStream.Close()

    $response = $request.GetResponse()
    $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
    $result = $sr.ReadToEnd()
    $sr.Close()
    $response.Close()

    return $result
}
