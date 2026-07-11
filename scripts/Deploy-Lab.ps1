#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the AKS Runtime Security Lab.

.DESCRIPTION
    Deploys a complete AKS runtime security lab with Defender for Containers:
    1. AKS cluster via Bicep (no Defender security profile)
    2. Defender for Containers plan enablement (with AntiMalware extension)
    3. Defender sensor via Helm chart (pinned 0.11.4 with anti-malware collector)
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
$DefenderPolicyDefinitionId = '64def556-fbad-4622-930e-72d1d5589bf5'
$DefenderHelmReleaseName = 'defender-k8s'
$DefenderHelmChart = 'oci://mcr.microsoft.com/azuredefender/microsoft-defender-for-containers'
$DefenderHelmChartVersion = '0.11.4'
$DefenderExclusionTag = 'ms_defender_e2e_discovery_exclude'

function Assert-LastExitCode {
    param(
        [Parameter(Mandatory)]
        [string]$Action
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed with exit code $LASTEXITCODE."
    }
}

function New-OwnerOnlyTempDirectory {
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("nine-lives-defender-{0}" -f [guid]::NewGuid().ToString('N'))
    $directory = [System.IO.Directory]::CreateDirectory($path)

    try {
        if ($IsWindows) {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $acl = [System.Security.AccessControl.DirectorySecurity]::new()
            $acl.SetOwner($identity.User)
            $acl.SetAccessRuleProtection($true, $false)
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $identity.User,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $null = $acl.AddAccessRule($rule)
            [System.IO.FileSystemAclExtensions]::SetAccessControl($directory, $acl)
        }
        else {
            [System.IO.File]::SetUnixFileMode(
                $path,
                [System.IO.UnixFileMode]::UserRead -bor
                [System.IO.UnixFileMode]::UserWrite -bor
                [System.IO.UnixFileMode]::UserExecute
            )
        }

        return $path
    }
    catch {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function New-SecureHelmValuesFile {
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $directory = New-OwnerOnlyTempDirectory
    $path = Join-Path $directory 'values.json'

    try {
        [System.IO.File]::WriteAllText($path, $Content, [System.Text.UTF8Encoding]::new($false))

        if ($IsWindows) {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $acl = [System.Security.AccessControl.FileSecurity]::new()
            $acl.SetOwner($identity.User)
            $acl.SetAccessRuleProtection($true, $false)
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $identity.User,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $null = $acl.AddAccessRule($rule)
            [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]::new($path), $acl)
        }
        else {
            [System.IO.File]::SetUnixFileMode(
                $path,
                [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
            )
        }

        return [pscustomobject]@{
            Directory = $directory
            Path      = $path
        }
    }
    catch {
        Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Remove-SecureHelmValuesFile {
    param(
        [Parameter(Mandatory)]
        [object]$TemporaryValues
    )

    if (Test-Path -LiteralPath $TemporaryValues.Path) {
        Remove-Item -LiteralPath $TemporaryValues.Path -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $TemporaryValues.Directory) {
        Remove-Item -LiteralPath $TemporaryValues.Directory -Recurse -Force -ErrorAction Stop
    }
}

function Get-ConflictingDefenderPolicyAssignments {
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [Parameter(Mandatory)]
        [string]$ResourceGroupName
    )

    $assignments = @()
    $scopeArgumentSets = @(
        @('--scope', "/subscriptions/$SubscriptionId"),
        @('--resource-group', $ResourceGroupName)
    )

    foreach ($scopeArguments in $scopeArgumentSets) {
        $json = az policy assignment list @scopeArguments --output json
        Assert-LastExitCode -Action 'Defender auto-provision policy lookup'
        if (-not [string]::IsNullOrWhiteSpace(($json -join "`n"))) {
            $assignments += @(($json -join "`n") | ConvertFrom-Json)
        }
    }

    return @(
        $assignments |
            Where-Object { $_.policyDefinitionId -like "*$DefenderPolicyDefinitionId*" } |
            Sort-Object -Property id -Unique
    )
}

function Get-StaleDefenderClusterResources {
    $resourceSelectors = @(
        @{ Kind = 'crd'; Name = 'policies.defender.microsoft.com' },
        @{ Kind = 'crd'; Name = 'runtimepolicies.defender.microsoft.com' },
        @{ Kind = 'crd'; Name = 'securityartifactpolicies.defender.microsoft.com' },
        @{ Kind = 'clusterrole'; Name = 'defender-admission-controller-cluster-role' },
        @{ Kind = 'clusterrole'; Name = 'defender-admission-controller-resource-cluster-role' },
        @{ Kind = 'clusterrolebinding'; Name = 'defender-admission-controller-cluster-role-binding' },
        @{ Kind = 'clusterrolebinding'; Name = 'defender-admission-controller-cluster-resource-role-binding' }
    )

    $existing = @()
    foreach ($selector in $resourceSelectors) {
        $result = kubectl get $selector.Kind $selector.Name --ignore-not-found --output name 2>$null
        Assert-LastExitCode -Action "Kubernetes preflight for $($selector.Kind)/$($selector.Name)"
        if (-not [string]::IsNullOrWhiteSpace(($result -join "`n"))) {
            $existing += $selector
        }
    }
    return $existing
}

function Restore-ClusterProtectionState {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$ClusterName,

        [Parameter(Mandatory)]
        [string]$ClusterId,

        [Parameter(Mandatory)]
        [bool]$DefenderWasEnabled,

        [Parameter()]
        [string]$DefenderWorkspaceId,

        [Parameter(Mandatory)]
        [bool]$ExclusionTagExisted,

        [Parameter()]
        [string]$ExclusionTagValue
    )

    $rollbackErrors = @()

    if ($DefenderWasEnabled) {
        $enableArguments = @(
            'aks', 'update',
            '--resource-group', $ResourceGroupName,
            '--name', $ClusterName,
            '--enable-defender',
            '--output', 'none'
        )
        if ($DefenderWorkspaceId) {
            $enableArguments += @('--defender-config', "logAnalyticsWorkspaceResourceId=$DefenderWorkspaceId")
        }

        az @enableArguments 2>$null
        if ($LASTEXITCODE -ne 0) {
            $rollbackErrors += 'failed to re-enable the prior AKS Defender profile'
        }
    }

    if ($ExclusionTagExisted) {
        az tag update `
            --resource-id $ClusterId `
            --operation merge `
            --tags "${DefenderExclusionTag}=$ExclusionTagValue" `
            --output none
    }
    else {
        az tag update `
            --resource-id $ClusterId `
            --operation delete `
            --tags $DefenderExclusionTag `
            --output none
    }
    if ($LASTEXITCODE -ne 0) {
        $rollbackErrors += 'failed to restore the prior Defender auto-provision exclusion tag state'
    }

    if ($rollbackErrors.Count -gt 0) {
        throw ('Cluster protection rollback was incomplete: {0}.' -f ($rollbackErrors -join '; '))
    }
}

Write-Host "`n=== AKS Runtime Security Lab ===" -ForegroundColor Cyan
Write-Host "Project:        $ProjectName"
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Location:       $Location"
Write-Host ""

# ---------- Pre-flight checks ----------
Write-Host "[1/7] Pre-flight checks..." -ForegroundColor Yellow

$requiredTools = if ($Destroy -or $WhatIfPreference) { @('az') } else { @('az', 'kubectl', 'helm') }
$toolInstallLinks = @{
    az      = 'https://learn.microsoft.com/cli/azure/install-azure-cli'
    kubectl = 'https://kubernetes.io/docs/tasks/tools/'
    helm    = 'https://helm.sh/docs/intro/install/'
}
foreach ($tool in $requiredTools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is required but not installed. See $($toolInstallLinks[$tool])"
    }
}

$account = az account show --query '{id:id,name:name}' --output json | ConvertFrom-Json
Assert-LastExitCode -Action 'Azure account lookup'
if (-not $account.id) {
    throw "Azure CLI is not signed in. Run 'az login' and select the intended subscription."
}
Write-Host "  Subscription: $($account.name) ($($account.id))"

# ---------- Destroy ----------
if ($Destroy) {
    Write-Host "[!] Destroying lab..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess($ResourceGroup, 'Delete resource group')) {
        az group delete --name $ResourceGroup --yes --no-wait
        Assert-LastExitCode -Action "Resource-group deletion for $ResourceGroup"
        Write-Host "[+] Resource group deletion initiated: $ResourceGroup" -ForegroundColor Green
    }
    return
}

if ($WhatIfPreference) {
    $sentinelPreview = if ($SkipSentinel) { 'Skip Sentinel rules and workbook' } else { 'Create or update 4 Sentinel rules and 1 workbook' }
    Write-Host "`n=== Deployment Preview Only ===" -ForegroundColor Yellow
    Write-Host @"

No Azure, Kubernetes, Helm, kubeconfig, or local secret-file mutations were performed.

Planned changes:
  - Deploy AKS cluster: $ProjectName (Kubernetes 1.35, 1 node, Standard_D4s_v3)
  - Deploy workspace:   $WorkspaceName
  - Enable the subscription-level Defender for Containers plan
  - Replace the managed AKS Defender profile with Helm chart $DefenderHelmChartVersion
  - Enable the Helm anti-malware collector
  - $sentinelPreview

Manual step after a real deployment:
  Configure the binary drift policy in Defender for Cloud.
"@
    return
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
    Assert-LastExitCode -Action 'AKS lab infrastructure deployment'

    $clusterName = $deployment.clusterName.value
    $workspaceId = $deployment.workspaceId.value
    if (-not $clusterName -or -not $workspaceId) {
        throw 'The infrastructure deployment did not return the expected cluster and workspace outputs.'
    }

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
    Assert-LastExitCode -Action 'Defender for Containers plan enablement'

    # Enable AntiMalware on the ContainerSensor extension (defaults to False)
    $subscriptionId = $account.id
    az rest --method PUT `
        --url "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Security/pricings/Containers?api-version=2024-01-01" `
        --body '{"properties":{"pricingTier":"Standard","extensions":[{"name":"ContainerSensor","isEnabled":"True","additionalExtensionProperties":{"AntiMalwareEnabled":"True","SecurityGatingEnabled":"True"}},{"name":"ContainerRegistriesVulnerabilityAssessments","isEnabled":"True"},{"name":"AgentlessDiscoveryForKubernetes","isEnabled":"True"},{"name":"ContainerIntegrityContribution","isEnabled":"True"}]}}' `
        --headers 'Content-Type=application/json' `
        -o none 2>$null
    Assert-LastExitCode -Action 'Defender for Containers extension configuration'

    Write-Host "  Defender for Containers: Enabled (with AntiMalware)" -ForegroundColor Green
}

# ---------- Get AKS Credentials ----------
Write-Host "`n[4/7] Getting AKS credentials..." -ForegroundColor Yellow

if ($PSCmdlet.ShouldProcess($clusterName, "Get AKS credentials")) {
    az aks get-credentials `
        --resource-group $ResourceGroup `
        --name $clusterName `
        --overwrite-existing
    Assert-LastExitCode -Action 'AKS kubeconfig update'

    Write-Host "  kubectl context set to: $clusterName" -ForegroundColor Green
}

# ---------- Deploy Defender Sensor via Helm ----------
Write-Host "`n[5/7] Deploying Defender sensor via Helm (with anti-malware)..." -ForegroundColor Yellow

if ($PSCmdlet.ShouldProcess($clusterName, "Deploy Defender sensor via Helm")) {
    $subscriptionId = $account.id
    $clusterJson = az aks show `
        --resource-group $ResourceGroup `
        --name $clusterName `
        --output json
    Assert-LastExitCode -Action 'AKS cluster state lookup'
    $cluster = ($clusterJson -join "`n") | ConvertFrom-Json
    $clusterRegion = [string]$cluster.location
    $clusterId = [string]$cluster.id
    if (-not $clusterRegion -or -not $clusterId) {
        throw 'AKS cluster state did not include its location and resource ID.'
    }

    $priorDefenderEnabled = $false
    if ($null -ne $cluster.securityProfile.defender.securityMonitoring.enabled) {
        $priorDefenderEnabled = [bool]$cluster.securityProfile.defender.securityMonitoring.enabled
    }
    $priorDefenderWorkspaceId = [string]$cluster.securityProfile.defender.logAnalyticsWorkspaceResourceId

    $priorExclusionTag = $null
    if ($cluster.tags) {
        $priorExclusionTag = $cluster.tags.PSObject.Properties[$DefenderExclusionTag]
    }
    $priorExclusionTagExisted = $null -ne $priorExclusionTag
    $priorExclusionTagValue = if ($priorExclusionTagExisted) { [string]$priorExclusionTag.Value } else { $null }

    # Microsoft's Helm flow stops before mutation when the auto-provisioning
    # policy could redeploy a competing managed sensor.
    $conflictingPolicies = @(Get-ConflictingDefenderPolicyAssignments `
        -SubscriptionId $subscriptionId `
        -ResourceGroupName $ResourceGroup)
    if ($conflictingPolicies.Count -gt 0) {
        $policySummary = $conflictingPolicies | ForEach-Object {
            '{0} ({1})' -f $_.name, $_.scope
        }
        throw ('Conflicting Defender auto-provision policy assignments found: {0}. Remove or exempt the lab scope before installing the Helm-managed sensor.' -f ($policySummary -join '; '))
    }

    $helmReleaseJson = helm list --all --namespace mdc --output json
    Assert-LastExitCode -Action 'Existing Defender Helm release lookup'
    $helmReleases = if ([string]::IsNullOrWhiteSpace(($helmReleaseJson -join "`n"))) {
        @()
    }
    else {
        @((($helmReleaseJson -join "`n") | ConvertFrom-Json))
    }
    $defenderReleases = @($helmReleases | Where-Object {
        $_.chart -like 'microsoft-defender-for-containers-*'
    })
    $conflictingReleases = @($defenderReleases | Where-Object {
        $_.name -ne $DefenderHelmReleaseName
    })
    if ($conflictingReleases.Count -gt 0) {
        throw ('A Defender Helm release already exists under a different name: {0}. Reuse or remove that release before continuing.' -f (($conflictingReleases.name | Sort-Object -Unique) -join ', '))
    }

    $currentReleaseExists = @($defenderReleases | Where-Object {
        $_.name -eq $DefenderHelmReleaseName
    }).Count -gt 0
    $staleClusterResources = if ($currentReleaseExists) {
        @()
    }
    else {
        @(Get-StaleDefenderClusterResources)
    }
    if ($staleClusterResources.Count -gt 0) {
        Write-Host "  Found $($staleClusterResources.Count) stale managed-sensor cluster resource(s); exact known resources will be removed before Helm." -ForegroundColor Yellow
    }

    $workspaceCustomerId = az monitor log-analytics workspace show `
        --resource-group $ResourceGroup `
        --workspace-name $WorkspaceName `
        --query customerId `
        --output tsv
    Assert-LastExitCode -Action 'Log Analytics workspace ID lookup'
    $workspaceCustomerId = [string](($workspaceCustomerId | Select-Object -First 1)).Trim()

    $workspaceSharedKey = az monitor log-analytics workspace get-shared-keys `
        --resource-group $ResourceGroup `
        --workspace-name $WorkspaceName `
        --query primarySharedKey `
        --output tsv
    Assert-LastExitCode -Action 'Log Analytics workspace key lookup'
    $workspaceSharedKey = [string](($workspaceSharedKey | Select-Object -First 1)).Trim()
    if (-not $workspaceCustomerId -or -not $workspaceSharedKey) {
        throw 'Log Analytics returned an empty workspace ID or shared key; refusing to deploy a sensor that cannot publish telemetry.'
    }

    # JSON is valid YAML. Keeping every Helm value in a locked-down file avoids
    # exposing the workspace key through the process command line.
    $helmValuesObject = @{
        global = @{
            cloudIdentifiers = @{
                Azure = @{
                    subscriptionId  = $subscriptionId
                    resourceGroupName = $ResourceGroup
                    clusterName     = $clusterName
                    region          = $clusterRegion
                }
            }
        }
        'microsoft-defender-for-containers-sensor' = @{
            antimalwareCollector = @{
                enabled = $true
            }
            omsagent = @{
                secret = @{
                    wsid = $workspaceCustomerId
                    key  = $workspaceSharedKey
                }
            }
        }
    }
    $helmValuesJson = $helmValuesObject | ConvertTo-Json -Depth 10 -Compress
    $temporaryValues = New-SecureHelmValuesFile -Content $helmValuesJson
    $helmValuesObject = $null
    $helmValuesJson = $null

    try {
        try {
            # A Helm-managed sensor must not coexist with the AKS Defender profile.
            az aks update `
                --resource-group $ResourceGroup `
                --name $clusterName `
                --disable-defender `
                --output none 2>$null
            Assert-LastExitCode -Action 'Disabling the automatically managed Defender profile'

            # Exclude this cluster from automatic rediscovery while the sensor is Helm-managed.
            az tag update `
                --resource-id $clusterId `
                --operation merge `
                --tags "${DefenderExclusionTag}=true" `
                --output none
            Assert-LastExitCode -Action 'Applying the Defender Helm-management exclusion tag'

            foreach ($resource in $staleClusterResources) {
                kubectl delete $resource.Kind $resource.Name --ignore-not-found 2>$null
                Assert-LastExitCode -Action "Removing stale $($resource.Kind)/$($resource.Name)"
            }

            helm upgrade --install $DefenderHelmReleaseName `
                $DefenderHelmChart `
                --version $DefenderHelmChartVersion `
                --namespace mdc `
                --create-namespace `
                --values $temporaryValues.Path `
                --atomic `
                --wait `
                --timeout 10m
            Assert-LastExitCode -Action 'Defender sensor Helm deployment'
        }
        catch {
            $deploymentError = $_
            Write-Warning 'Defender Helm deployment failed. Restoring the cluster protection state captured before installation.'
            try {
                Restore-ClusterProtectionState `
                    -ResourceGroupName $ResourceGroup `
                    -ClusterName $clusterName `
                    -ClusterId $clusterId `
                    -DefenderWasEnabled $priorDefenderEnabled `
                    -DefenderWorkspaceId $priorDefenderWorkspaceId `
                    -ExclusionTagExisted $priorExclusionTagExisted `
                    -ExclusionTagValue $priorExclusionTagValue
            }
            catch {
                throw ('Defender Helm deployment failed: {0} Rollback also failed: {1}' -f $deploymentError.Exception.Message, $_.Exception.Message)
            }
            throw ('Defender Helm deployment failed; the prior Defender profile and exclusion-tag state were restored. Cause: {0}' -f $deploymentError.Exception.Message)
        }
    }
    finally {
        $workspaceSharedKey = $null
        Remove-SecureHelmValuesFile -TemporaryValues $temporaryValues
    }

    Write-Host "  Defender sensor: Deployed via Helm chart $DefenderHelmChartVersion (with anti-malware)" -ForegroundColor Green

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
    if ($PSCmdlet.ShouldProcess('Defender for Cloud data connector', 'Create or update Sentinel data connector')) {
        az rest --method PUT --url $connectorUrl --body $connectorBody --headers 'Content-Type=application/json' -o none 2>$null
        Assert-LastExitCode -Action 'Defender for Cloud data-connector deployment'
        Write-Host "  Defender for Cloud data connector: Enabled" -ForegroundColor Green
    }

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
        $workbookDisplayName = 'Container Runtime Security Dashboard'
        $existingWorkbook = @(
            az resource list `
                --resource-group $ResourceGroup `
                --resource-type Microsoft.Insights/workbooks `
                2>$null | ConvertFrom-Json
        ) | Where-Object {
            $_.tags.'hidden-title' -eq $workbookDisplayName
        } | Select-Object -First 1
        $workbookId = if ($existingWorkbook) { $existingWorkbook.name } else { [guid]::NewGuid().ToString() }
        $workbookUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01"

        $workbookBody = @{
            location   = $Location
            kind       = 'shared'
            properties = @{
                displayName    = $workbookDisplayName
                category       = 'sentinel'
                sourceId       = $workspaceId
                serializedData = $workbookContent
            }
            tags = @{
                'hidden-title' = $workbookDisplayName
            }
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess($workbookDisplayName, "Create or update workbook")) {
            az rest --method PUT --url $workbookUrl --body $workbookBody --headers 'Content-Type=application/json' -o none 2>$null
            Assert-LastExitCode -Action 'Sentinel workbook deployment'
            Write-Host "  Workbook: $workbookDisplayName" -ForegroundColor Green
        }
    } else {
        Write-Host "  [!] Workbook template not found at $workbookPath, skipping." -ForegroundColor Yellow
    }
} else {
    Write-Host "`n[6/7] Skipping Sentinel rules (--SkipSentinel)." -ForegroundColor Gray
    Write-Host "[7/7] Skipping workbook (--SkipSentinel)." -ForegroundColor Gray
}

# ---------- Summary ----------
$sentinelSummary = if ($SkipSentinel) { 'Skipped by request' } else { '4 analytics rules + 1 workbook' }
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host @"

Resources deployed:
  - AKS Cluster:    $clusterName (Kubernetes 1.35, 1 node, Standard_D4s_v3)
  - Defender:       Defender for Containers enabled (with AntiMalware extension)
  - Sensor:         Helm chart $DefenderHelmChartVersion (anti-malware collector enabled)
  - Workspace:      $WorkspaceName (Container Insights + Sentinel)
  - Sentinel:       $sentinelSummary

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
