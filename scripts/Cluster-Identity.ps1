# Shared read-only checks. No credentials or raw kubeconfig are persisted.
function Invoke-LabJson {
    param([string]$Command, [string[]]$Arguments, [switch]$AllowEmpty)
    $output = & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command identity lookup failed (exit $LASTEXITCODE)." }
    $text = ($output | Out-String).Trim()
    if (-not $text -and $AllowEmpty) { return $null }
    if (-not $text) { throw "$Command identity lookup returned no data." }
    return $text | ConvertFrom-Json
}

function Assert-ApiServerRanges {
    param([string[]]$Ranges)
    if (-not $Ranges -or $Ranges.Count -gt 20) { throw 'Supply 1-20 explicit API server authorized IPv4 CIDRs (/24 through /32); automatic egress discovery is not used.' }
    foreach ($range in $Ranges) {
        if ($range -notmatch '^(\d+\.\d+\.\d+\.\d+)/(2[4-9]|3[0-2])$') { throw "Invalid or overly broad API server authorized range: $range" }
        $address = $null
        if (-not [Net.IPAddress]::TryParse($Matches[1], [ref]$address) -or $address.AddressFamily -ne 'InterNetwork' -or $address.ToString() -ne $Matches[1]) { throw "Invalid IPv4 range: $range" }
        $prefix = [int]$Matches[2]
        $bytes = $address.GetAddressBytes()
        if ($bytes[0] -in @(0,10,127) -or $bytes[0] -ge 224 -or
            ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
            ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) -or
            ($bytes[3] % [math]::Pow(2, 32-$prefix)) -ne 0) { throw "Use a public, canonical operator-egress IPv4 CIDR: $range" }
    }
    if (@($Ranges | Sort-Object -Unique).Count -ne $Ranges.Count) { throw 'API server authorized ranges contain duplicates.' }
}

function Assert-LiveCluster {
    param($State, $Cluster)
    $expected = "$($State.resourceGroupId)/providers/Microsoft.ContainerService/managedClusters/$($State.projectName)"
    if ($Cluster.id -ne $expected -or -not $Cluster.resourceUid) { throw 'AKS resource ID or immutable resourceUID is missing or inconsistent.' }
    Assert-ApiServerRanges -Ranges @($State.apiServerAuthorizedIpRanges)
    if ((@($Cluster.apiServerAccessProfile.authorizedIpRanges | Sort-Object) -join ',') -ne (@($State.apiServerAuthorizedIpRanges | Sort-Object) -join ',')) {
        throw 'Live API server authorized ranges differ from the deployment manifest.'
    }
    if ($State.runtimeProof -and ($State.runtimeProof.clusterResourceId -ne $Cluster.id -or $State.runtimeProof.clusterResourceUid -ne $Cluster.resourceUid)) {
        throw 'AKS immutable identity changed; refusing a recreated or foreign cluster.'
    }
}

function Get-KubeClusterProof {
    param($State, $Cluster)
    Assert-LiveCluster -State $State -Cluster $Cluster
    $context = (& kubectl config current-context | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $context) { throw 'A current kubeconfig context is required.' }
    $server = (& kubectl --context $context config view --minify --raw -o 'jsonpath={.clusters[0].cluster.server}' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the kubeconfig server.' }
    $uri = $null
    if (-not [uri]::TryCreate($server, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.Port -ne 443 -or
        $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/' -or $uri.Host -ne [string]$Cluster.fqdn) {
        throw 'Kubeconfig server does not match the owned Azure cluster FQDN.'
    }
    $insecure = (& kubectl --context $context config view --minify --raw -o 'jsonpath={.clusters[0].cluster.insecure-skip-tls-verify}' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $insecure -notin @('', 'false')) { throw 'Kubeconfig must verify the server certificate.' }
    $ca = (& kubectl --context $context config view --minify --raw -o 'jsonpath={.clusters[0].cluster.certificate-authority-data}' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $ca) { throw 'Kubeconfig must contain its Azure-provided CA data.' }
    $caHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String($ca)))
    # Check the recorded server and CA before contacting Kubernetes with credentials.
    if ($State.runtimeProof -and ($State.runtimeProof.server -ne $server -or $State.runtimeProof.caSha256 -ne $caHash)) {
        throw 'Kubeconfig server or CA differs from the recorded cluster identity.'
    }
    $namespace = Invoke-LabJson -Command kubectl -Arguments @('--context', $context, 'get', 'namespace', 'kube-system', '-o', 'json')
    if (-not $namespace.metadata.uid -or ($State.runtimeProof -and $State.runtimeProof.kubeSystemUid -ne $namespace.metadata.uid)) {
        throw 'The immutable kube-system namespace UID differs from the recorded cluster.'
    }
    return [pscustomobject]@{context=$context; proof=[pscustomobject]@{
        clusterResourceId=[string]$Cluster.id;clusterResourceUid=[string]$Cluster.resourceUid;
        server=$server;caSha256=$caHash;kubeSystemUid=[string]$namespace.metadata.uid
    }}
}
