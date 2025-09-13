function PVE-Connect {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Authkey,
        [Parameter(Mandatory)][string]$Hostaddr
    )

#    $AuthKey = "root@pam!Powershell=16dcf2b5-1ca1-41cd-9e97-3c1d3d308ec0"
#    $HostAddr = "10.36.1.27"

    #$AuthKey = "root@pam!Powershell-Access=dfcf6742-f05d-465a-ae34-2f96b5aebfca"
    #$HostAddr = "10.36.1.22"


    # HTTP Headers for connection.
    # ------------------------------------------------------------
    $DefaultHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $DefaultHeaders.Add("Authorization", "PVEAPIToken=$AuthKey")
    $DefaultHeaders.Add("Accept", "application/json")


# Ignore Self Signed Cert.
# ------------------------------------------------------------
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


    # Proxmox API address.
    # ------------------------------------------------------------
    $DefaultProxmoxAPI = "https://$HostAddr`:8006/api2/json"

    return @( [PSCustomObject]@{ PVEAPI  = $DefaultProxmoxAPI; Headers = $DefaultHeaders } )

}

