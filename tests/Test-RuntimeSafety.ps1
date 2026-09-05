#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$statePath = Join-Path $root '.aks-runtime-lab-state-aks-runtime-lab.json'
if (Test-Path -LiteralPath $statePath) { throw 'Use a fresh checkout without an ownership manifest for mocked tests.' }
$sub = '00000000-0000-0000-0000-000000000000'
$tenant = '11111111-1111-1111-1111-111111111111'
$rg = "/subscriptions/$sub/resourceGroups/aks-runtime-lab-rg"
$owner = 'abcdefabcdefabcdefabcdefabcdefab'
$server = 'https://owned.eastus.azmk8s.io:443'
$ca = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('mock-ca'))
$caHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String($ca)))
$state = @{version=1;projectName='aks-runtime-lab';ownerToken=$owner;subscriptionId=$sub;tenantId=$tenant;resourceGroupId=$rg;
    apiServerAuthorizedIpRanges=@('203.0.113.10/32'); runtimeProof=@{clusterResourceId="$rg/providers/Microsoft.ContainerService/managedClusters/aks-runtime-lab";clusterResourceUid='immutable-arm-id';server=$server;caSha256=$caHash;kubeSystemUid='immutable-kube-id'}}
function global:az {
    $global:LASTEXITCODE=0
    $a=@($args)
    if ($a[0] -eq 'account') { return (@{id=$sub;tenantId=$(if($global:AksRuntimeCase -eq 'tenant'){'foreign'}else{$tenant})}|ConvertTo-Json -Compress) }
    if ($a[0] -eq 'group') { return (@{id=$rg;tags=@{'nlzt-owner'=$owner}}|ConvertTo-Json -Compress) }
    if ($a[0] -eq 'aks') { return (@{id=$state.runtimeProof.clusterResourceId;resourceUid=$(if($global:AksRuntimeCase -eq 'arm-uid'){'recreated'}else{'immutable-arm-id'});fqdn='owned.eastus.azmk8s.io';apiServerAccessProfile=@{authorizedIpRanges=@($(if($global:AksRuntimeCase -eq 'network-drift'){'0.0.0.0/0'}else{'203.0.113.10/32'}))}}|ConvertTo-Json -Depth 8 -Compress) }
    throw "Unexpected Azure command $a"
}
function global:kubectl {
    $global:LASTEXITCODE=0
    $a=@($args)
    if ($a[0] -eq '--context') { $a=$a[2..($a.Count-1)] }
    if ($a[0] -eq 'config' -and $a[1] -eq 'current-context') { return 'aks-runtime-lab' }
    if ($a[0] -eq 'config') {
        if (($a -join ' ') -match 'certificate-authority-data') { return $(if($global:AksRuntimeCase -eq 'ca') {[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('other'))}else{$ca}) }
        if (($a -join ' ') -match 'insecure-skip-tls') { return 'false' }
        return $(if($global:AksRuntimeCase -eq 'server'){'https://foreign.example'}else{$server})
    }
    if ($a[0] -eq 'get' -and $a[1] -eq 'namespace') {
        if ($a[2] -eq 'kube-system') { return (@{metadata=@{uid=$(if($global:AksRuntimeCase -eq 'kube-uid'){'foreign'}else{'immutable-kube-id'})}}|ConvertTo-Json -Compress) }
        return (@{metadata=@{uid='test-namespace-uid';labels=@{'nlzt-owner'=$(if($global:AksRuntimeCase -eq 'foreign-namespace'){'foreign'}else{$owner})}}}|ConvertTo-Json -Depth 6 -Compress)
    }
    if ($a[0] -eq 'get' -and $a[1] -eq 'pods') {
        return (@{items=@($(if($global:AksRuntimeCase -eq 'foreign-pod') {@{metadata=@{name='drift-test';labels=@{'nlzt-owner'='foreign'}}}}))}|ConvertTo-Json -Depth 8 -Compress)
    }
    if ($a[0] -eq 'get' -and $a[1] -eq 'pod') { return (@{metadata=@{name=$a[2];uid=$(if($global:AksRuntimeCase -eq 'pod-replaced'){'foreign-uid'}else{'created-pod'});labels=@{'nlzt-owner'=$owner;'nlzt-run'=$global:AksRuntimeCreatedRun}}}|ConvertTo-Json -Depth 8 -Compress) }
    $global:AksRuntimeMutations.Add(($a -join ' '))
    if ($a[0] -eq 'run') {
        if ($global:AksRuntimeCase -eq 'pod-collision') { $global:LASTEXITCODE=1; return 'AlreadyExists' }
        $labels=@($a|Where-Object {$_ -like '--labels=*'})[0]
        $global:AksRuntimeCreatedRun=($labels -split 'nlzt-run=')[1]
        return (@{metadata=@{name=$a[1];uid='created-pod';labels=@{'nlzt-owner'=$owner;'nlzt-run'=$global:AksRuntimeCreatedRun}}}|ConvertTo-Json -Depth 8 -Compress)
    }
    if ($a[0] -eq 'wait' -and $global:AksRuntimeCase -eq 'wait-failure') { $global:LASTEXITCODE=1 }
}
try {
    $state|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $statePath
    foreach ($global:AksRuntimeCase in @('server','ca','tenant','arm-uid','kube-uid','network-drift','foreign-namespace','foreign-pod')) {
        $global:AksRuntimeMutations=[Collections.Generic.List[string]]::new()
        $rejected=$false
        try { & (Join-Path $root 'scripts/Test-RuntimeSecurity.ps1') -SkipMalware -SkipGated *> $null } catch { $rejected=$true }
        if (-not $rejected -or $global:AksRuntimeMutations.Count) { throw "Unsafe ${global:AksRuntimeCase}: rejected=$rejected mutations=$($global:AksRuntimeMutations -join ';')" }
    }
    foreach ($global:AksRuntimeCase in @('pod-collision','pod-replaced','wait-failure')) {
        $global:AksRuntimeMutations=[Collections.Generic.List[string]]::new()
        $rejected=$false
        try { & (Join-Path $root 'scripts/Test-RuntimeSecurity.ps1') -SkipMalware -SkipGated *> $null } catch { $rejected=$true }
        if (-not $rejected -or @($global:AksRuntimeMutations | Where-Object {$_ -match '^(delete|exec) '}).Count) { throw "Unsafe pod creation/readiness path: $global:AksRuntimeCase" }
    }
    $global:AksRuntimeCase='owned'
    $global:AksRuntimeMutations=[Collections.Generic.List[string]]::new()
    & (Join-Path $root 'scripts/Test-RuntimeSecurity.ps1') -SkipMalware -SkipGated *> $null
    if ($global:AksRuntimeMutations -match '^delete ' -or @($global:AksRuntimeMutations|Where-Object {$_ -match '^run drift-test-[a-f0-9]+ '}).Count -ne 1 -or @($global:AksRuntimeMutations|Where-Object {$_ -match '^exec drift-test-'}).Count -ne 1) { throw 'Owned drift test did not create and execute only its unique pod.' }
    $global:AksRuntimeMutations=[Collections.Generic.List[string]]::new()
    & (Join-Path $root 'scripts/Test-RuntimeSecurity.ps1') -SkipDrift -SkipGated *> $null
    if (@($global:AksRuntimeMutations | Where-Object {$_ -match '^exec malware-test-'}).Count -ne 3 -or $global:AksRuntimeMutations -match '^delete ') { throw 'Owned malware test did not preserve its three execution stages.' }
    $global:AksRuntimeMutations=[Collections.Generic.List[string]]::new()
    & (Join-Path $root 'scripts/Test-RuntimeSecurity.ps1') -SkipDrift -SkipMalware *> $null
    if (@($global:AksRuntimeMutations | Where-Object {$_ -match '^run vuln-test-'}).Count -ne 1 -or $global:AksRuntimeMutations -match '^(delete|exec) ') { throw 'Gated scenario unexpectedly deleted or executed an existing pod.' }
    Write-Host 'PASS: 8 foreign-target refusal fixtures, 3 failed/replaced/unready pod fixtures, and 3 owned scenario fixtures.'
} finally {
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Remove-Item Function:\az,Function:\kubectl -ErrorAction SilentlyContinue
}
