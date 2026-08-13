#Requires -Version 7.0
<#
.SYNOPSIS
    Runs test scenarios against the AKS Runtime Security Lab.

.DESCRIPTION
    Exercises three runtime-security scenarios:
    1. Binary drift - drops and executes a script not in the original image
    2. Anti-malware - writes and attempts to execute the EICAR test file
    3. Gated deployment - attempts Microsoft's documented test image

    Results depend on enabled policies, sensor health, telemetry ingestion, and
    service-side processing. Gated-deployment decisions are reviewed in
    Admission Monitoring rather than inferred from an undocumented alert type.

.PARAMETER ProjectName
    Lab project name. Must match the AKS cluster the tests are allowed to touch.
    Defaults to the same value Deploy-Lab.ps1 uses.

.PARAMETER Namespace
    Namespace the test pods are created in and deleted with. Created if absent.

.PARAMETER SkipDrift
    Skip the binary drift test.

.PARAMETER SkipMalware
    Skip the anti-malware test.

.PARAMETER SkipGated
    Skip the gated deployment test.

.EXAMPLE
    ./Test-RuntimeSecurity.ps1
    Run all test scenarios.
#>

[CmdletBinding()]
param(
    [string]$ProjectName = 'aks-runtime-lab',
    [string]$Namespace = 'runtime-security-tests',
    [switch]$SkipDrift,
    [switch]$SkipMalware,
    [switch]$SkipGated
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== AKS Runtime Security Test Scenarios ===" -ForegroundColor Cyan
Write-Host "These tests exercise configured controls; they do not guarantee alerts or fixed latency.`n"

# ---------- Pre-flight ----------
$context = kubectl config current-context 2>$null
if (-not $context) {
    throw "No kubectl context set. Run: az aks get-credentials --resource-group $ProjectName-rg --name $ProjectName"
}
if ($context -ne $ProjectName) {
    throw @"
Refusing to run. The current kubectl context is '$context', not the lab cluster '$ProjectName'.
These tests execute a dropped binary and write and execute the EICAR test file inside a
running container, so they must never touch a cluster that is not the lab. Either switch context
with 'az aks get-credentials --resource-group $ProjectName-rg --name $ProjectName', or pass
-ProjectName if your lab cluster genuinely has a different name.
"@
}
Write-Host "kubectl context: $context"

kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f - | Out-Null
Write-Host "test namespace: $Namespace`n"

# ---------- Test 1: Binary Drift ----------
if (-not $SkipDrift) {
    Write-Host "[Test 1/3] Binary Drift Detection" -ForegroundColor Yellow
    Write-Host "  Deploying clean nginx container..."

    kubectl delete pod drift-test -n $Namespace --ignore-not-found=true --wait=true 2>$null
    kubectl run drift-test -n $Namespace --image=nginx:1.27-alpine --restart=Never --labels="test=drift" 2>$null
    kubectl wait -n $Namespace --for=condition=Ready pod/drift-test --timeout=120s

    Write-Host "  Introducing binary drift (creating + executing script not in image)..."
    kubectl exec drift-test -n $Namespace -- /bin/sh -c @"
cat > /tmp/drift-binary.sh << 'SCRIPT'
#!/bin/sh
echo 'This binary is not part of the original image'
hostname
whoami
SCRIPT
chmod +x /tmp/drift-binary.sh
/tmp/drift-binary.sh
"@

    Write-Host "  Binary drift activity submitted." -ForegroundColor Green
    Write-Host "  Review the configured drift action and Defender security alerts."
    Write-Host "  Detection/blocking and alert ingestion are asynchronous; no fixed latency is promised.`n"
}

# ---------- Test 2: Anti-Malware (EICAR) ----------
if (-not $SkipMalware) {
    Write-Host "[Test 2/3] Container Anti-Malware (EICAR)" -ForegroundColor Yellow
    Write-Host "  Deploying clean nginx container..."

    kubectl delete pod malware-test -n $Namespace --ignore-not-found=true --wait=true 2>$null
    kubectl run malware-test -n $Namespace --image=nginx:1.27-alpine --restart=Never --labels="test=malware" 2>$null
    kubectl wait -n $Namespace --for=condition=Ready pod/malware-test --timeout=120s

    Write-Host "  Writing EICAR test file into container..."
    # EICAR test string (base64-encoded to avoid shell escaping issues)
    # This is NOT malware, it's the standard 68-byte AV test file
    kubectl exec malware-test -n $Namespace -- /bin/sh -c "echo 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=' | base64 -d > /tmp/eicar.com"
    if ($LASTEXITCODE -ne 0) {
        throw 'Writing the EICAR test file failed; the execution stage was not attempted.'
    }

    Write-Host "  Marking the file executable and attempting execution..."
    kubectl exec malware-test -n $Namespace -- /bin/sh -c "chmod +x /tmp/eicar.com"
    if ($LASTEXITCODE -ne 0) {
        throw 'Making the EICAR test file executable failed; the execution stage was not attempted.'
    }
    $malwareResult = kubectl exec malware-test -n $Namespace -- /bin/sh -c "/tmp/eicar.com" 2>&1
    $malwareExitCode = $LASTEXITCODE
    Write-Host "  EICAR execution was attempted (container command exit $malwareExitCode)." -ForegroundColor Green
    Write-Host "  Runtime anti-malware evaluates execution, not the file write alone."
    Write-Host "  A nonzero command exit does not by itself prove Defender blocked it; inspect"
    Write-Host "  the configured anti-malware action and Defender security alerts. Policy updates"
    Write-Host "  can take up to 30 minutes to reach sensors, and alert latency varies.`n"
}

# ---------- Test 3: Gated Deployment ----------
if (-not $SkipGated) {
    Write-Host "[Test 3/3] Gated Deployment (Microsoft Test Image)" -ForegroundColor Yellow
    $gatedTestImage = 'mcr.microsoft.com/mdc/dev/defender-admission-controller/test-images:one-high'
    Write-Host "  Attempting Microsoft's documented gated-deployment test image:"
    Write-Host "  $gatedTestImage"

    kubectl delete pod vuln-test -n $Namespace --ignore-not-found=true --wait=true 2>$null

    # Deny mode returns an admission-webhook error. Audit mode allows the pod and
    # records the decision in Defender for Cloud Admission Monitoring.
    $result = kubectl run vuln-test -n $Namespace --image=$gatedTestImage --restart=Never --labels="test=gated" 2>&1
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
     | where ProductName == "Microsoft Defender for Cloud"
     | where AlertType has_any ("DriftDetection", "BinaryDrift", "MalwareDetected")
     | project TimeGenerated, AlertName, AlertSeverity, Description

Cleanup test pods:
  kubectl delete pod drift-test malware-test vuln-test -n $Namespace --ignore-not-found

"@
