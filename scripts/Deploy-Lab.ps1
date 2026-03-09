#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the AKS Runtime Security Lab.

.DESCRIPTION
    Deploys a complete AKS runtime security lab with Defender for Containers:
    1. AKS cluster with Defender sensor via Bicep
    2. Defender for Containers plan enablement
    3. Sentinel analytics rules (4 scheduled rules)
    4. Sentinel workbook (Container Runtime Security Dashboard)
    5. Optional: test workloads for validation

.PARAMETER Location
    Azure region for all resources. Default: eastus.

.PARAMETER ProjectName
    Project name used for resource naming. Default: aks-runtime-lab.

.PARAMETER SkipSentinel
    Skip deploying Sentinel analytics rules and workbook.

.PARAMETER Destroy
    Tear down the lab (delete resource group).

.PARAMETER WhatIf
    Preview all changes without deploying.

.EXAMPLE
    ./Deploy-Lab.ps1 -Location "eastus"
    Deploy the full lab to East US.

.EXAMPLE
    ./Deploy-Lab.ps1 -Location "eastus" -SkipSentinel
    Deploy infrastructure only, skip Sentinel rules.

.EXAMPLE
    ./Deploy-Lab.ps1 -Destroy
    Tear down the lab.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$Location = 'eastus',

    [Parameter()]
    [string]$ProjectName = 'aks-runtime-lab',

    [Parameter()]
    [switch]$SkipSentinel,

    [Parameter()]
    [switch]$Destroy
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Split-Path -Parent $ScriptDir
$ResourceGroup = "$ProjectName-rg"
$WorkspaceName = "$ProjectName-law"

Write-Host "`n=== AKS Runtime Security Lab ===" -ForegroundColor Cyan
Write-Host "Project:        $ProjectName"
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Location:       $Location"
Write-Host ""

# ---------- Destroy ----------
if ($Destroy) {
    Write-Host "[!] Destroying lab..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess($ResourceGroup, "Delete resource group")) {
        az group delete --name $ResourceGroup --yes --no-wait
        Write-Host "[+] Resource group deletion initiated: $ResourceGroup" -ForegroundColor Green
    }
    return
}

# ---------- Pre-flight checks ----------
Write-Host "[1/6] Pre-flight checks..." -ForegroundColor Yellow

$account = az account show --query '{id:id,name:name}' -o json | ConvertFrom-Json
Write-Host "  Subscription: $($account.name) ($($account.id))"

# Check required CLI tools
foreach ($tool in @('kubectl', 'helm')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "$tool is required but not installed. See https://kubernetes.io/docs/tasks/tools/"
    }
}

# ---------- Deploy Infrastructure ----------
Write-Host "`n[2/6] Deploying infrastructure (Bicep)..." -ForegroundColor Yellow

$bicepPath = Join-Path $LabRoot 'bicep/main.bicep'

if ($PSCmdlet.ShouldProcess("Subscription", "Deploy Bicep template")) {
    $deployment = az deployment sub create `
        --location $Location `
        --template-file $bicepPath `
        --parameters projectName=$ProjectName location=$Location `
        --query 'properties.outputs' -o json | ConvertFrom-Json

    $clusterName = $deployment.clusterName.value
    $workspaceId = $deployment.workspaceId.value

    Write-Host "  AKS Cluster:  $clusterName" -ForegroundColor Green
    Write-Host "  Workspace:    $WorkspaceName" -ForegroundColor Green
}

# ---------- Enable Defender for Containers ----------
Write-Host "`n[3/6] Enabling Defender for Containers plan..." -ForegroundColor Yellow

if ($PSCmdlet.ShouldProcess("Subscription", "Enable Defender for Containers")) {
    az security pricing create `
        --name Containers `
        --tier Standard `
        -o none 2>$null

    Write-Host "  Defender for Containers: Enabled" -ForegroundColor Green
}

# ---------- Get AKS Credentials ----------
Write-Host "`n[4/6] Getting AKS credentials..." -ForegroundColor Yellow

if ($PSCmdlet.ShouldProcess($clusterName, "Get AKS credentials")) {
    az aks get-credentials `
        --resource-group $ResourceGroup `
        --name $clusterName `
        --overwrite-existing

    Write-Host "  kubectl context set to: $clusterName" -ForegroundColor Green

    # Verify Defender sensor is running
    Write-Host "  Waiting for Defender sensor pods..." -ForegroundColor Gray
    $retries = 0
    $maxRetries = 12
    while ($retries -lt $maxRetries) {
        $defenderPods = kubectl get pods -n kube-system -l app=microsoft-defender -o name 2>$null
        if ($defenderPods) {
            Write-Host "  Defender sensor: Running" -ForegroundColor Green
            break
        }
        $retries++
        Start-Sleep -Seconds 10
    }
    if ($retries -eq $maxRetries) {
        Write-Host "  [!] Defender sensor not yet detected. It may take a few minutes to initialize." -ForegroundColor Yellow
    }
}

# ---------- Deploy Sentinel Rules ----------
if (-not $SkipSentinel) {
    Write-Host "`n[5/6] Deploying Sentinel analytics rules..." -ForegroundColor Yellow

    $subscriptionId = $account.id
    $apiVersion = '2024-03-01'
    $baseUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules"

    # Enable Defender for Cloud data connector (creates SecurityAlert table)
    $connectorUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/dataConnectors/defender-for-cloud-connector?api-version=$apiVersion"
    $connectorBody = @{
        kind       = 'AzureSecurityCenter'
        properties = @{
            dataTypes = @{
                alerts = @{ state = 'Enabled' }
            }
            subscriptionId = $subscriptionId
        }
    } | ConvertTo-Json -Depth 5
    az rest --method PUT --url $connectorUrl --body $connectorBody --headers 'Content-Type=application/json' -o none 2>$null
    Write-Host "  Defender for Cloud data connector: Enabled" -ForegroundColor Green

    # Rule definitions
    $rules = @(
        @{
            id       = 'aks-binary-drift-prod'
            name     = 'LAB - Binary Drift in Production Namespace'
            severity = 'High'
            query    = @'
SecurityAlert
| where AlertType == "K8S.NODE_BinaryDrift" or AlertName has "Binary drift"
| extend ParsedEntities = parse_json(Entities)
| mv-expand Entity = ParsedEntities
| extend Namespace = tostring(Entity.Namespace)
| extend ClusterName = tostring(Entity.ClusterName)
| extend ContainerName = tostring(Entity.ContainerName)
| extend PodName = tostring(Entity.PodName)
| extend DriftedBinary = tostring(Entity.FilePath)
| where Namespace in ("default", "production", "kube-system")
| where isnotempty(ContainerName)
| project TimeGenerated, AlertSeverity, ClusterName, Namespace, PodName, ContainerName, DriftedBinary
'@
            tactics  = @('Execution')
            techniques = @('T1059')
        },
        @{
            id       = 'aks-container-malware'
            name     = 'LAB - Container Malware Detected'
            severity = 'High'
            query    = @'
SecurityAlert
| where AlertType has "K8S.NODE_Malware" or AlertName has_any ("malware", "Malicious file")
| extend ParsedEntities = parse_json(Entities)
| mv-expand Entity = ParsedEntities
| extend ContainerName = tostring(Entity.ContainerName)
| extend PodName = tostring(Entity.PodName)
| extend Namespace = tostring(Entity.Namespace)
| extend ClusterName = tostring(Entity.ClusterName)
| extend MalwareName = tostring(Entity.MalwareName)
| extend FilePath = tostring(Entity.FilePath)
| extend ActionTaken = tostring(Entity.ActionTaken)
| where isnotempty(ContainerName)
| project TimeGenerated, AlertSeverity, MalwareName, FilePath, ActionTaken, ClusterName, Namespace, PodName, ContainerName
'@
            tactics  = @('Execution')
            techniques = @('T1204')
        },
        @{
            id       = 'aks-gated-deployment-block'
            name     = 'LAB - Vulnerable Image Deployment Attempted'
            severity = 'Medium'
            query    = @'
SecurityAlert
| where AlertType has "GatedDeployment" or AlertName has_any ("deployment was blocked", "vulnerable image")
| extend ParsedEntities = parse_json(Entities)
| mv-expand Entity = ParsedEntities
| extend ImageName = tostring(Entity.ImageName)
| extend ClusterName = tostring(Entity.ClusterName)
| extend Namespace = tostring(Entity.Namespace)
| extend VulnCount = tostring(Entity.VulnerabilityCount)
| where isnotempty(ImageName)
| project TimeGenerated, AlertSeverity, ImageName, ClusterName, Namespace, VulnCount, Description
'@
            tactics  = @('InitialAccess')
            techniques = @('T1190')
        },
        @{
            id       = 'aks-kubectl-exec'
            name     = 'LAB - Suspicious kubectl exec into Container'
            severity = 'Medium'
            query    = @'
AzureDiagnostics
| where Category == "kube-audit"
| extend RequestObject = parse_json(log_s)
| extend Verb = tostring(RequestObject.verb)
| extend RequestURI = tostring(RequestObject.requestURI)
| extend UserAgent = tostring(RequestObject.userAgent)
| extend SourceIP = tostring(RequestObject.sourceIPs[0])
| extend Username = tostring(RequestObject.user.username)
| where Verb == "create"
| where RequestURI has "/exec"
| where RequestURI !has "kube-system"
| extend PodName = extract(@"/pods/([^/]+)/exec", 1, RequestURI)
| extend Namespace = extract(@"namespaces/([^/]+)/", 1, RequestURI)
| project TimeGenerated, Username, SourceIP, PodName, Namespace, UserAgent, RequestURI
'@
            tactics  = @('Execution')
            techniques = @('T1609')
        }
    )

    foreach ($rule in $rules) {
        $ruleId = $rule.id
        $ruleUrl = "$baseUrl/${ruleId}?api-version=$apiVersion"

        $body = @{
            kind       = 'Scheduled'
            properties = @{
                displayName          = $rule.name
                description          = "AKS Runtime Security Lab - $($rule.name)"
                severity             = $rule.severity
                enabled              = $true
                query                = $rule.query
                queryFrequency       = 'PT5M'
                queryPeriod          = 'PT1H'
                triggerOperator      = 'GreaterThan'
                triggerThreshold     = 0
                suppressionEnabled   = $false
                suppressionDuration  = 'PT5H'
                tactics              = $rule.tactics
                techniques           = $rule.techniques
            }
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess($rule.name, "Create Sentinel analytics rule")) {
            $result = az rest --method PUT --url $ruleUrl --body $body --headers 'Content-Type=application/json' -o none 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Rule: $($rule.name)" -ForegroundColor Green
            } else {
                Write-Host "  [!] Rule: $($rule.name) - Failed (SecurityAlert table may not exist yet)" -ForegroundColor Yellow
                Write-Host "      Re-run after test scenarios generate alerts (~15 min)" -ForegroundColor Gray
            }
        }
    }

    # Deploy workbook
    Write-Host "`n[6/6] Deploying Sentinel workbook..." -ForegroundColor Yellow

    $workbookPath = Join-Path $LabRoot 'workbook/container-runtime-workbook.json'
    if (Test-Path $workbookPath) {
        $workbookContent = Get-Content $workbookPath -Raw
        $workbookId = [guid]::NewGuid().ToString()
        $workbookUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01"

        $workbookBody = @{
            location   = $Location
            kind       = 'shared'
            properties = @{
                displayName    = 'Container Runtime Security Dashboard'
                category       = 'sentinel'
                sourceId       = $workspaceId
                serializedData = $workbookContent
            }
            tags = @{
                'hidden-title' = 'Container Runtime Security Dashboard'
            }
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess("Container Runtime Security Dashboard", "Create workbook")) {
            az rest --method PUT --url $workbookUrl --body $workbookBody --headers 'Content-Type=application/json' -o none 2>$null
            Write-Host "  Workbook: Container Runtime Security Dashboard" -ForegroundColor Green
        }
    } else {
        Write-Host "  [!] Workbook template not found at $workbookPath, skipping." -ForegroundColor Yellow
    }
} else {
    Write-Host "`n[5/6] Skipping Sentinel rules (--SkipSentinel)." -ForegroundColor Gray
    Write-Host "[6/6] Skipping workbook (--SkipSentinel)." -ForegroundColor Gray
}

# ---------- Summary ----------
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host @"

Resources deployed:
  - AKS Cluster:    $clusterName (1 node, Standard_D4s_v3)
  - Defender:       Defender for Containers enabled
  - Workspace:      $WorkspaceName (Container Insights + Sentinel)
  - Sentinel:       4 analytics rules + 1 workbook

Next steps:
  1. Verify Defender sensor:
     kubectl get pods -n kube-system -l app=microsoft-defender

  2. Run the test scenarios:
     ./scripts/Test-RuntimeSecurity.ps1

  3. View alerts in Defender for Cloud:
     https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/SecurityAlerts

  4. View Sentinel incidents:
     https://security.microsoft.com/sentinel-incidents

Cleanup:
  ./Deploy-Lab.ps1 -Destroy

"@
