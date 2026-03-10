#Requires -Version 7.0
<#
.SYNOPSIS
    Runs test scenarios against the AKS Runtime Security Lab.

.DESCRIPTION
    Executes three test scenarios to validate runtime security:
    1. Binary drift - drops and executes a script not in the original image
    2. Anti-malware - writes the EICAR test file into a container
    3. Gated deployment - attempts to deploy an image with known critical CVEs

    Each test generates alerts in Defender for Cloud (5-15 minute delay).

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
    [switch]$SkipDrift,
    [switch]$SkipMalware,
    [switch]$SkipGated
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== AKS Runtime Security Test Scenarios ===" -ForegroundColor Cyan
Write-Host "These tests generate real Defender alerts (5-15 min delay).`n"

# ---------- Pre-flight ----------
$context = kubectl config current-context 2>$null
if (-not $context) {
    Write-Error "No kubectl context set. Run: az aks get-credentials --resource-group aks-runtime-lab-rg --name aks-runtime-lab"
}
Write-Host "kubectl context: $context`n"

# ---------- Test 1: Binary Drift ----------
if (-not $SkipDrift) {
    Write-Host "[Test 1/3] Binary Drift Detection" -ForegroundColor Yellow
    Write-Host "  Deploying clean nginx container..."

    kubectl delete pod drift-test --ignore-not-found=true --wait=true 2>$null
    kubectl run drift-test --image=nginx:latest --restart=Never --labels="test=drift" 2>$null
    kubectl wait --for=condition=Ready pod/drift-test --timeout=120s

    Write-Host "  Introducing binary drift (creating + executing script not in image)..."
    kubectl exec drift-test -- /bin/sh -c @"
cat > /tmp/drift-binary.sh << 'SCRIPT'
#!/bin/sh
echo 'This binary is not part of the original image'
hostname
whoami
SCRIPT
chmod +x /tmp/drift-binary.sh
/tmp/drift-binary.sh
"@

    Write-Host "  Binary drift test complete." -ForegroundColor Green
    Write-Host "  Expected alert: 'Binary drift detected' (Medium/High severity)"
    Write-Host "  Alert delay: 5-15 minutes`n"
}

# ---------- Test 2: Anti-Malware (EICAR) ----------
if (-not $SkipMalware) {
    Write-Host "[Test 2/3] Container Anti-Malware (EICAR)" -ForegroundColor Yellow
    Write-Host "  Deploying clean nginx container..."

    kubectl delete pod malware-test --ignore-not-found=true --wait=true 2>$null
    kubectl run malware-test --image=nginx:latest --restart=Never --labels="test=malware" 2>$null
    kubectl wait --for=condition=Ready pod/malware-test --timeout=120s

    Write-Host "  Writing EICAR test file into container..."
    # EICAR test string (base64-encoded to avoid shell escaping issues)
    # This is NOT malware, it's the standard 68-byte AV test file
    kubectl exec malware-test -- /bin/sh -c "echo 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=' | base64 -d > /tmp/eicar.com"

    Write-Host "  EICAR test complete." -ForegroundColor Green
    Write-Host "  Expected alert: 'Malicious file detected' (High severity)"
    Write-Host "  In block mode, the write process may be killed."
    Write-Host "  Alert delay: 5-15 minutes`n"
}

# ---------- Test 3: Gated Deployment ----------
if (-not $SkipGated) {
    Write-Host "[Test 3/3] Gated Deployment (Vulnerable Image)" -ForegroundColor Yellow
    Write-Host "  Attempting to deploy nginx 1.14.0 (known critical CVEs)..."

    kubectl delete pod vuln-test --ignore-not-found=true --wait=true 2>$null

    # This may be blocked by the admission webhook if gated deployment is in Deny mode
    $result = kubectl run vuln-test --image=nginx:1.14.0 --restart=Never --labels="test=gated" 2>&1

    if ($result -match "denied|Forbidden|blocked") {
        Write-Host "  Deployment BLOCKED by gated deployment." -ForegroundColor Green
        Write-Host "  This is the expected behavior in Deny mode."
    } else {
        Write-Host "  Deployment succeeded (Audit mode or gated deployment not configured)." -ForegroundColor Yellow
        Write-Host "  Check Defender for Cloud > Recommendations for the audit finding."
    }

    Write-Host "  Alert delay: 5-15 minutes`n"
}

# ---------- Summary ----------
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host @"

All test scenarios executed. Monitor for alerts in:

  1. Defender for Cloud > Security Alerts:
     https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/SecurityAlerts

  2. Defender XDR > Incidents:
     https://security.microsoft.com/incidents

  3. Sentinel > Incidents (after analytics rules fire):
     https://security.microsoft.com/sentinel-incidents

  4. KQL query in Log Analytics:
     SecurityAlert
     | where TimeGenerated > ago(1h)
     | where ProductName == "Microsoft Defender for Cloud"
     | where AlertType has_any ("DriftDetection", "BinaryDrift", "MalwareDetected", "GatedDeployment")
     | project TimeGenerated, AlertName, AlertSeverity, Description

Cleanup test pods:
  kubectl delete pod drift-test malware-test vuln-test --ignore-not-found

"@
