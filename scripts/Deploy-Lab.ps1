#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the AKS Runtime Security Lab.

.DESCRIPTION
    Deploys a complete AKS runtime security lab with Defender for Containers:
    1. AKS cluster via Bicep (no Defender security profile)
    2. Defender for Containers plan enablement (with AntiMalware extension)
    3. Defender sensor via Helm chart (v0.10.2+ with anti-malware collector)
    4. Sentinel analytics rules (4 scheduled rules)
    5. Sentinel workbook (Container Runtime Security Dashboard)

    NOTE: Binary drift policy must be configured manually in the Azure portal
    (Defender for Cloud > Environment Settings > Containers drift policy).
    The default is "Ignore drift detection" — there is no REST API for this.

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
Write-Host "[1/7] Pre-flight checks..." -ForegroundColor Yellow

$account = az account show --query '{id:id,name:name}' -o json | ConvertFrom-Json
Write-Host "  Subscription: $($account.name) ($($account.id))"

# Check required CLI tools
foreach ($tool in @('kubectl', 'helm')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "$tool is required but not installed. See https://kubernetes.io/docs/tasks/tools/"
    }
}

# ---------- Deploy Infrastructure ----------
Write-Host "`n[2/7] Deploying infrastructure (Bicep)..." -ForegroundColor Yellow

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
Write-Host "`n[3/7] Enabling Defender for Containers plan..." -ForegroundColor Yellow

if ($PSCmdlet.ShouldProcess("Subscription", "Enable Defender for Containers")) {
    az security pricing create `
        --name Containers `
        --tier Standard `
        -o none 2>$null

    # Enable AntiMalware on the ContainerSensor extension (defaults to False)
    $subscriptionId = $account.id
    az rest --method PUT `
        --url "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Security/pricings/Containers?api-version=2024-01-01" `
        --body '{"properties":{"pricingTier":"Standard","extensions":[{"name":"ContainerSensor","isEnabled":"True","additionalExtensionProperties":{"AntiMalwareEnabled":"True","SecurityGatingEnabled":"True"}},{"name":"ContainerRegistriesVulnerabilityAssessments","isEnabled":"True"},{"name":"AgentlessDiscoveryForKubernetes","isEnabled":"True"},{"name":"ContainerIntegrityContribution","isEnabled":"True"}]}}' `
        --headers 'Content-Type=application/json' `
        -o none 2>$null

    Write-Host "  Defender for Containers: Enabled (with AntiMalware)" -ForegroundColor Green
}

# ---------- Get AKS Credentials ----------
Write-Host "`n[4/7] Getting AKS credentials..." -ForegroundColor Yellow

if ($PSCmdlet.ShouldProcess($clusterName, "Get AKS credentials")) {
    az aks get-credentials `
        --resource-group $ResourceGroup `
        --name $clusterName `
        --overwrite-existing

    Write-Host "  kubectl context set to: $clusterName" -ForegroundColor Green
}

# ---------- Deploy Defender Sensor via Helm ----------
Write-Host "`n[5/7] Deploying Defender sensor via Helm (with anti-malware)..." -ForegroundColor Yellow

if ($PSCmdlet.ShouldProcess($clusterName, "Deploy Defender sensor via Helm")) {
    $clusterId = az aks show --resource-group $ResourceGroup --name $clusterName --query id -o tsv

    # Download the official Microsoft install script
    $installScriptUrl = 'https://raw.githubusercontent.com/microsoft/Microsoft-Defender-For-Containers/main/scripts/install_defender_sensor_aks.sh'
    $installScriptPath = Join-Path ([System.IO.Path]::GetTempPath()) 'install_defender_sensor_aks.sh'
    Invoke-WebRequest -Uri $installScriptUrl -OutFile $installScriptPath -UseBasicParsing

    # Run the install script with anti-malware enabled
    bash $installScriptPath --id $clusterId --version latest --antimalware
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Defender sensor: Deployed via Helm (with anti-malware)" -ForegroundColor Green
    } else {
        Write-Host "  [!] Helm deployment failed. Check errors above." -ForegroundColor Yellow
        Write-Host "      Manual install: bash install_defender_sensor_aks.sh --id '$clusterId' --version latest --antimalware" -ForegroundColor Gray
    }

    # Wait for sensor pods to come up
    Write-Host "  Waiting for Defender sensor pods..." -ForegroundColor Gray
    $retries = 0
    $maxRetries = 12
    while ($retries -lt $maxRetries) {
        $defenderPods = kubectl get pods -n mdc -o name 2>$null | Select-String 'microsoft-defender'
        if ($defenderPods) {
            Write-Host "  Defender sensor pods: Running" -ForegroundColor Green
            break
        }
        $retries++
        Start-Sleep -Seconds 10
    }
    if ($retries -eq $maxRetries) {
        Write-Host "  [!] Defender sensor pods not yet detected. They may take a few minutes to initialize." -ForegroundColor Yellow
    }
}

# ---------- Deploy Sentinel Rules ----------
if (-not $SkipSentinel) {
    Write-Host "`n[6/7] Deploying Sentinel analytics rules..." -ForegroundColor Yellow

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
union isfuzzy=true (datatable(TimeGenerated:datetime,AlertType:string,AlertName:string,Entities:string,ExtendedProperties:string,CompromisedEntity:string,AlertSeverity:string)[]), (SecurityAlert)
| where AlertType has_any ("DriftDetection", "BinaryDrift") or AlertName has "drift"
| extend ParsedEntities = parse_json(Entities)
| extend ExtProps = parse_json(ExtendedProperties)
| mv-expand Entity = ParsedEntities
| where tostring(Entity.Type) == "container"
| extend ContainerName = tostring(Entity.Name)
| extend PodName = tostring(Entity.Pod.Name)
| extend Namespace = tostring(Entity.Pod.Namespace.Name)
| extend ClusterName = CompromisedEntity
| extend DriftedBinary = tostring(ExtProps["Suspicious Process"])
| where Namespace in ("default", "production", "kube-system")
| where isnotempty(ContainerName)
| project TimeGenerated, AlertSeverity, ClusterName, Namespace, PodName, ContainerName, DriftedBinary
'@
            tactics  = @('Execution', 'CommandAndControl')
            techniques = @('T1059', 'T1105')
        },
        @{
            id       = 'aks-container-malware'
            name     = 'LAB - Container Malware Detected'
            severity = 'High'
            query    = @'
union isfuzzy=true (datatable(TimeGenerated:datetime,AlertType:string,AlertName:string,Entities:string,ExtendedProperties:string,CompromisedEntity:string,AlertSeverity:string)[]), (SecurityAlert)
| where AlertType has "MalwareDetected" or AlertName has_any ("malware", "Malicious file")
| extend ParsedEntities = parse_json(Entities)
| extend ExtProps = parse_json(ExtendedProperties)
| mv-expand Entity = ParsedEntities
| where tostring(Entity.Type) == "container"
| extend ContainerName = tostring(Entity.Name)
| extend PodName = tostring(Entity.Pod.Name)
| extend Namespace = tostring(Entity.Pod.Namespace.Name)
| extend ClusterName = CompromisedEntity
| extend MalwareName = tostring(ExtProps["Malware Name"])
| extend FilePath = tostring(ExtProps["Suspicious Process"])
| extend ActionTaken = tostring(ExtProps["Action Taken"])
| where isnotempty(ContainerName)
| project TimeGenerated, AlertSeverity, MalwareName, FilePath, ActionTaken, ClusterName, Namespace, PodName, ContainerName
'@
            tactics  = @('Execution', 'CommandAndControl')
            techniques = @('T1204', 'T1105')
        },
        @{
            id       = 'aks-gated-deployment-block'
            name     = 'LAB - Vulnerable Image Deployment Attempted'
            severity = 'Medium'
            query    = @'
union isfuzzy=true (datatable(TimeGenerated:datetime,AlertType:string,AlertName:string,ExtendedProperties:string,CompromisedEntity:string,AlertSeverity:string,Description:string)[]), (SecurityAlert)
| where AlertType has "GatedDeployment" or AlertName has_any ("deployment was blocked", "vulnerable image")
| extend ExtProps = parse_json(ExtendedProperties)
| extend ImageName = coalesce(tostring(ExtProps["Image Name"]), tostring(ExtProps["ImageName"]), extract(@"[Ii]mage[:\s]+([^\s,]+)", 1, Description))
| extend ClusterName = CompromisedEntity
| extend VulnCount = coalesce(tostring(ExtProps["Vulnerability Count"]), extract(@"(\d+)\s+vulnerabilit", 1, Description))
| where isnotempty(ImageName)
| project TimeGenerated, AlertSeverity, ImageName, ClusterName, VulnCount, Description
'@
            tactics  = @('InitialAccess', 'Execution')
            techniques = @('T1190', 'T1610')
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
| where Verb in ("create", "get")
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
    Write-Host "`n[7/7] Deploying Sentinel workbook..." -ForegroundColor Yellow

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
    Write-Host "`n[6/7] Skipping Sentinel rules (--SkipSentinel)." -ForegroundColor Gray
    Write-Host "[7/7] Skipping workbook (--SkipSentinel)." -ForegroundColor Gray
}

# ---------- Summary ----------
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host @"

Resources deployed:
  - AKS Cluster:    $clusterName (1 node, Standard_D4s_v3)
  - Defender:       Defender for Containers enabled (with AntiMalware extension)
  - Sensor:         Helm chart v0.10.2+ (anti-malware collector enabled)
  - Workspace:      $WorkspaceName (Container Insights + Sentinel)
  - Sentinel:       4 analytics rules + 1 workbook

IMPORTANT - Manual step required:
  Configure binary drift policy in the Azure portal:
  Defender for Cloud > Environment Settings > Containers drift policy
  Change default from "Ignore drift detection" to "Drift detection alert"
  (No REST API exists for this setting)

Next steps:
  1. Configure drift policy (see above)

  2. Verify Defender sensor:
     kubectl get pods -n mdc

  3. Run the test scenarios:
     ./scripts/Test-RuntimeSecurity.ps1

  4. View alerts in Defender for Cloud:
     https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/SecurityAlerts

  5. View Sentinel incidents:
     https://security.microsoft.com/sentinel-incidents

Cleanup:
  ./Deploy-Lab.ps1 -Destroy

"@
