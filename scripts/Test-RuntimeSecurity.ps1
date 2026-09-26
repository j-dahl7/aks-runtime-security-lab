#Requires -Version 7.6

<#
.SYNOPSIS
    Runs test scenarios against the AKS Runtime Security Lab.

.DESCRIPTION
    Exercises three runtime-security scenarios:
    1. Binary drift - copies and executes an ELF binary in the writable layer
    2. Anti-malware - writes and attempts to execute the EICAR test file
    3. Gated deployment - attempts the reviewed image supplied by the operator

    Results depend on enabled policies, sensor health, telemetry ingestion, and
    service-side processing. Gated-deployment decisions are reviewed in
    Admission Monitoring rather than inferred from an undocumented alert type.

.PARAMETER ProjectName
    Lab project name. Must match the AKS cluster the tests are allowed to touch.
    Defaults to the same value Deploy-Lab.ps1 uses.

.PARAMETER Namespace
    Dedicated owner-labeled namespace. Foreign namespaces or pods are refused.

.PARAMETER SkipDrift
    Skip the binary drift test.

.PARAMETER SkipMalware
    Skip the anti-malware test.

.PARAMETER SkipGated
    Skip the gated deployment test.

.PARAMETER GatedTestImage
    Image from a supported registry with reviewed, signed vulnerability findings.
    The default is an image shown in Microsoft's sample denial message; it is
    not a guaranteed test fixture for this subscription or policy.

.EXAMPLE
    ./Test-RuntimeSecurity.ps1
    Run all test scenarios.
#>

[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$')]
    [string]$ProjectName = 'aks-runtime-lab',
    [ValidatePattern('^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$')]
    [string]$Namespace = 'runtime-security-tests',
    [switch]$SkipDrift,
    [switch]$SkipMalware,
    [switch]$SkipGated,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9./:_@-]+$')]
    [ValidateLength(1, 512)]
    [string]$GatedTestImage = 'mcr.microsoft.com/mdc/dev/defender-admission-controller/test-images:one-high'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Cluster-Identity.ps1')

Write-Host "`n=== AKS Runtime Security Test Scenarios ===" -ForegroundColor Cyan
Write-Host "These tests exercise configured controls; they do not guarantee alerts or fixed latency.`n"

# ---------- Read-only ownership preflight ----------
$statePath = Join-Path (Split-Path -Parent $PSScriptRoot) ".aks-runtime-lab-state-$ProjectName.json"
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.version -ne 1 -or $state.projectName -ne $ProjectName -or $state.ownerToken -notmatch '^[a-f0-9]{32}$' -or
    -not $state.tenantId -or -not $state.runtimeProof) { throw 'A deployment manifest with recorded immutable cluster identity is required. Rerun the owned deployment.' }
$account = Invoke-LabJson -Command az -Arguments @('account', 'show', '-o', 'json')
$expectedRgId = "/subscriptions/$($account.id)/resourceGroups/$ProjectName-rg"
if ($state.subscriptionId -ne $account.id -or $state.tenantId -ne $account.tenantId -or $state.resourceGroupId -ne $expectedRgId) { throw 'Active Azure account does not match deployment provenance.' }
$group = Invoke-LabJson -Command az -Arguments @('group', 'show', '--name', "$ProjectName-rg", '--subscription', $account.id, '-o', 'json')
if ($group.id -ne $state.resourceGroupId -or $group.tags.'nlzt-owner' -ne $state.ownerToken) { throw 'Live resource group is not owned by this deployment.' }
$cluster = Invoke-LabJson -Command az -Arguments @('aks', 'show', '--resource-group', "$ProjectName-rg", '--name', $ProjectName, '--subscription', $account.id, '-o', 'json')
$identity = Get-KubeClusterProof -State $state -Cluster $cluster
$context = $identity.context
$ownerToken = [string]$state.ownerToken
$runId = [guid]::NewGuid().ToString('N')
$createdPods = @{}
$testNamespace = Invoke-LabJson -Command kubectl -Arguments @('--context', $context, 'get', 'namespace', $Namespace, '--ignore-not-found', '-o', 'json') -AllowEmpty
if ($testNamespace -and $testNamespace.metadata.labels.'nlzt-owner' -ne $ownerToken) { throw 'Refusing a foreign test namespace.' }
if ($testNamespace) {
    $pods = Invoke-LabJson -Command kubectl -Arguments @('--context', $context, 'get', 'pods', '-n', $Namespace, '-o', 'json')
    if ($null -eq $pods.items -or @($pods.items | Where-Object { $_.metadata.labels.'nlzt-owner' -ne $ownerToken }).Count) { throw 'Test namespace contains foreign pods or an unreadable inventory.' }
}
else {
    $namespaceJson = @{apiVersion='v1';kind='Namespace';metadata=@{name=$Namespace;labels=@{'nlzt-owner'=$ownerToken}}} | ConvertTo-Json -Depth 6 -Compress
    $created = $namespaceJson | kubectl --context $context create -f - -o json
    if ($LASTEXITCODE -ne 0) { throw 'Namespace create failed; existing namespaces are never adopted or overwritten.' }
    $testNamespace = ($created | Out-String) | ConvertFrom-Json
}
if (-not $testNamespace.metadata.uid -or $testNamespace.metadata.labels.'nlzt-owner' -ne $ownerToken) { throw 'Namespace creation did not return the expected ownership.' }
$namespaceUid = [string]$testNamespace.metadata.uid

function Assert-OwnedTestNamespace {
    $currentNamespace = Invoke-LabJson -Command kubectl -Arguments @('--context', $context, 'get', 'namespace', $Namespace, '-o', 'json')
    if ($currentNamespace.metadata.uid -ne $namespaceUid -or $currentNamespace.metadata.labels.'nlzt-owner' -ne $ownerToken) { throw 'Test namespace identity changed; refusing mutation.' }
}
function Assert-OwnedTestPod {
    param([string]$Name)
    Assert-OwnedTestNamespace
    $pod = Invoke-LabJson -Command kubectl -Arguments @('--context', $context, 'get', 'pod', $Name, '-n', $Namespace, '-o', 'json')
    if (-not $createdPods[$Name] -or $pod.metadata.uid -ne $createdPods[$Name] -or
        $pod.metadata.labels.'nlzt-owner' -ne $ownerToken -or $pod.metadata.labels.'nlzt-run' -ne $runId) { throw 'Test pod or namespace identity changed; refusing execution.' }
}
function New-OwnedTestPod {
    param([string]$Name, [string]$Image)
    Assert-OwnedTestNamespace
    $output = kubectl --context $context run $Name -n $Namespace --image=$Image --restart=Never --labels="nlzt-owner=$ownerToken,nlzt-run=$runId" -o json
    if ($LASTEXITCODE -ne 0) { throw 'Pod create failed; existing pods are never deleted or replaced.' }
    $pod = ($output | Out-String) | ConvertFrom-Json
    if ($pod.metadata.name -ne $Name -or -not $pod.metadata.uid -or $pod.metadata.labels.'nlzt-owner' -ne $ownerToken -or $pod.metadata.labels.'nlzt-run' -ne $runId) { throw 'Pod create returned unexpected ownership.' }
    $createdPods[$Name] = [string]$pod.metadata.uid
    Assert-OwnedTestPod $Name
    kubectl --context $context wait -n $Namespace --for=condition=Ready "pod/$Name" --timeout=120s
    if ($LASTEXITCODE -ne 0) { throw 'Owned test pod did not become ready; execution was not attempted.' }
}
Write-Host "Verified immutable cluster identity; test namespace: $Namespace; run: $runId`n"

# ---------- Test 1: Binary Drift ----------
# Reviewed Docker Hub multi-platform index digest, 2026-09-25. Refresh by
# checking the official library/nginx tag metadata and reviewing the image.
$testImage = 'nginx:1.30-alpine@sha256:985220252f3863977e468f611ef118ebd01421289dd86ee1ae99cb068c3bce2b'
if (-not $SkipDrift) {
    Write-Host "[Test 1/3] Binary Drift Detection" -ForegroundColor Yellow
    Write-Host "  Deploying clean nginx container..."

    $driftPod = "drift-test-$runId"
    New-OwnedTestPod $driftPod $testImage

    Write-Host "  Introducing binary drift (copying + executing an ELF in the writable layer)..."
    Assert-OwnedTestPod $driftPod
    kubectl --context $context exec $driftPod -n $Namespace -- /bin/sh -c 'mkdir /tmp/nlzt-drift && cp /bin/busybox /tmp/nlzt-drift/busybox && chmod +x /tmp/nlzt-drift/busybox && /tmp/nlzt-drift/busybox true'
    if ($LASTEXITCODE -ne 0) { throw 'Binary drift command failed; review the actual control evidence.' }

    Write-Host "  Binary drift activity submitted." -ForegroundColor Green
    Write-Host "  Review the configured drift action and Defender security alerts."
    Write-Host "  Detection/blocking and alert ingestion are asynchronous; no fixed latency is promised.`n"
}

# ---------- Test 2: Anti-Malware (EICAR) ----------
if (-not $SkipMalware) {
    Write-Host "[Test 2/3] Container Anti-Malware (EICAR)" -ForegroundColor Yellow
    Write-Host "  Deploying clean nginx container..."

    $malwarePod = "malware-test-$runId"
    New-OwnedTestPod $malwarePod $testImage

    Write-Host "  Writing EICAR test file into container..."
    # EICAR test string (base64-encoded to avoid shell escaping issues)
    # This is NOT malware, it's the standard 68-byte AV test file
    Assert-OwnedTestPod $malwarePod
    kubectl --context $context exec $malwarePod -n $Namespace -- /bin/sh -c "echo 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=' | base64 -d > /tmp/eicar.com"
    if ($LASTEXITCODE -ne 0) {
        throw 'Writing the EICAR test file failed; the execution stage was not attempted.'
    }

    Write-Host "  Marking the file executable and attempting execution..."
    Assert-OwnedTestPod $malwarePod
    kubectl --context $context exec $malwarePod -n $Namespace -- /bin/sh -c "chmod +x /tmp/eicar.com"
    if ($LASTEXITCODE -ne 0) {
        throw 'Making the EICAR test file executable failed; the execution stage was not attempted.'
    }
    Assert-OwnedTestPod $malwarePod
    $malwareResult = kubectl --context $context exec $malwarePod -n $Namespace -- /bin/sh -c "/tmp/eicar.com" 2>&1
    $malwareExitCode = $LASTEXITCODE
    Write-Host "  EICAR execution was attempted (container command exit $malwareExitCode)." -ForegroundColor Green
    Write-Host "  Runtime anti-malware evaluates execution, not the file write alone."
    Write-Host "  A nonzero command exit does not by itself prove Defender blocked it; inspect"
    Write-Host "  the configured anti-malware action and Defender security alerts. Policy updates"
    Write-Host "  can take up to 30 minutes to reach sensors, and alert latency varies.`n"
}

# ---------- Test 3: Gated Deployment ----------
if (-not $SkipGated) {
    Write-Host "[Test 3/3] Gated Deployment (Reviewed Image)" -ForegroundColor Yellow
    Write-Host "  Attempting image: $GatedTestImage"
    Write-Host "  Confirm this image has signed findings in a supported registry and matches the rule scope."
    Write-Host "  The default MCR sample does not guarantee a denial or vulnerability finding."

    $gatedPod = "vuln-test-$runId"

    # Deny mode returns an admission-webhook error. Audit mode allows the pod and
    # records the decision in Defender for Cloud Admission Monitoring.
    Assert-OwnedTestNamespace
    $result = kubectl --context $context run $gatedPod -n $Namespace --image=$gatedTestImage --restart=Never --labels="nlzt-owner=$ownerToken,nlzt-run=$runId" 2>&1
    $gatedExitCode = $LASTEXITCODE

    if ($gatedExitCode -ne 0 -and $result -match "admission webhook|denied|Forbidden|blocked") {
        Write-Host "  Admission request was denied by the webhook." -ForegroundColor Green
        Write-Host "  Confirm the matching rule and violations in Admission Monitoring."
    } elseif ($gatedExitCode -ne 0) {
        Write-Host "  kubectl failed without a recognizable gating decision (exit $gatedExitCode)." -ForegroundColor Yellow
        Write-Host "  Treat this run as inconclusive and inspect the command output and cluster state."
    } else {
        Write-Host "  Admission request was allowed." -ForegroundColor Yellow
        Write-Host "  This can mean Audit mode, no matching rule, missing findings artifacts, or"
        Write-Host "  incomplete gating prerequisites; Admission Monitoring is authoritative."
    }

    Write-Host "  Review: Defender for Cloud > Environment settings > Security rules >"
    Write-Host "          Gated deployment > Admission Monitoring`n"
}

# ---------- Summary ----------
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host @"

Selected scenarios were attempted. Review each control in its documented surface:

  1. Binary drift and anti-malware - Defender for Cloud > Security Alerts:
     https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/SecurityAlerts

  2. Gated deployment - Defender for Cloud > Environment settings >
     Security rules > Gated deployment > Admission Monitoring

  3. Defender XDR > Incidents:
     https://security.microsoft.com/incidents

  4. Sentinel > Incidents (after the runtime rules fire):
     https://security.microsoft.com/sentinel-incidents

  5. Runtime-alert KQL in Log Analytics:
     SecurityAlert
     | where TimeGenerated > ago(1h)
     | where ProductName in~ ("Azure Security Center", "Microsoft Defender for Cloud")
     | where AlertType has_any ("DriftDetection", "BinaryDrift", "MalwareDetected") or AlertName has_any ("drift", "malware")
     | project TimeGenerated, ProductName, AlertName, AlertSeverity, Description

Cleanup test pods:
  Review this run's pods before manual cleanup:
  kubectl --context $context get pods -n $Namespace -l nlzt-owner=$ownerToken,nlzt-run=$runId
  No existing pods were deleted or replaced by this helper.

"@
