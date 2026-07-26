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
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$')]
    [string]$ProjectName = 'aks-runtime-lab',

    [Parameter()]
    [switch]$SkipSentinel,

    [Parameter()]
    [switch]$EnableSentinelRules,

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
$OwnershipTagName = 'nlzt-owner'
$StatePath = Join-Path $LabRoot ".aks-runtime-lab-state-$ProjectName.json"
$PricingApiVersion = '2024-01-01'
$script:PricingRollbackContext = $null

function Assert-LastExitCode {
    param(
        [Parameter(Mandatory)]
        [string]$Action
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed with exit code $LASTEXITCODE."
    }
}

function Invoke-AzJson {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$NotFoundIsNull
    )

    $output = & az @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        if ($NotFoundIsNull -and $text -match '(?i)(ResourceGroupNotFound|ResourceNotFound|not found|could not be found|status code.?404|HTTP 404)') {
            return $null
        }
        throw "Azure CLI command failed: $text"
    }
    if (-not $text) { return $null }
    return $text | ConvertFrom-Json
}

function Read-LabState {
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        return $null
    }
    try {
        return Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Ownership manifest is invalid JSON: $StatePath"
    }
}

function Write-LabState {
    param([Parameter(Mandatory)]$State)

    if (-not $PSCmdlet.ShouldProcess($StatePath, 'Write ownership and rollback manifest before cloud mutation')) {
        return
    }

    $temporary = "$StatePath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $State | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $temporary -Encoding utf8NoBOM
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
            [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]::new($temporary), $acl)
        }
        else {
            [System.IO.File]::SetUnixFileMode(
                $temporary,
                [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
            )
        }
        Move-Item -LiteralPath $temporary -Destination $StatePath -Force
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Assert-LabStateContext {
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ExpectedResourceGroupId
    )

    if ($State.version -ne 1 -or -not $State.ownerToken) {
        throw 'Ownership manifest has an unsupported version or no owner token.'
    }
    if ($State.subscriptionId -ne $SubscriptionId -or $State.resourceGroupId -ne $ExpectedResourceGroupId) {
        throw 'Ownership manifest belongs to a different subscription or resource group.'
    }
}

function Get-StableGuid {
    param([Parameter(Mandatory)][string]$Value)
    $bytes = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($Value)
    )[0..15]
    return ([guid]::new([byte[]]$bytes)).ToString()
}

function ConvertTo-CanonicalValue {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object)) {
            $result[[string]$key] = ConvertTo-CanonicalValue $Value[$key]
        }
        return $result
    }
    if ($Value -is [pscustomobject]) {
        $result = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties | Sort-Object Name)) {
            $result[$property.Name] = ConvertTo-CanonicalValue $property.Value
        }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @($Value | ForEach-Object { ConvertTo-CanonicalValue $_ })
        if ($items.Count -gt 0 -and @($items | Where-Object {
            $_ -isnot [System.Collections.IDictionary] -or -not $_.Contains('name')
        }).Count -eq 0) {
            $items = @($items | Sort-Object { [string]$_['name'] })
        }
        return ,$items
    }
    return $Value
}

function Get-WritablePricingProperties {
    param([Parameter(Mandatory)]$Properties)

    $writable = @('pricingTier', 'subPlan', 'enforce', 'extensions', 'securityOperatorResourceId')
    $readOnly = @('freeTrialRemainingTime', 'inherited', 'inheritedFrom', 'resourcesCoverageStatus', 'deprecated', 'replacedBy')
    $unknown = @($Properties.PSObject.Properties.Name | Where-Object { $_ -notin $writable -and $_ -notin $readOnly })
    if ($unknown.Count -gt 0) {
        throw "Defender pricing contains unrecognized properties that this lab will not risk dropping: $($unknown -join ', ')"
    }

    $result = [ordered]@{}
    foreach ($name in $writable) {
        $property = $Properties.PSObject.Properties[$name]
        if ($property -and $null -ne $property.Value) {
            $result[$name] = $property.Value
        }
    }
    if (-not $result.Contains('pricingTier')) {
        throw 'Defender pricing state did not contain pricingTier.'
    }
    return [pscustomobject]$result
}

function New-DesiredPricingProperties {
    param([Parameter(Mandatory)]$CurrentProperties)

    $desired = Get-WritablePricingProperties $CurrentProperties
    $desired.pricingTier = 'Standard'
    $extensions = @($desired.extensions)
    $duplicateNames = @($extensions | Group-Object name | Where-Object Count -gt 1)
    if ($duplicateNames.Count -gt 0) {
        throw "Defender pricing contains duplicate extensions: $($duplicateNames.Name -join ', ')"
    }

    $required = @(
        'ContainerSensor',
        'ContainerRegistriesVulnerabilityAssessments',
        'AgentlessDiscoveryForKubernetes',
        'ContainerIntegrityContribution'
    )
    $merged = [System.Collections.Generic.List[object]]::new()
    foreach ($extension in $extensions) {
        $copy = ($extension | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
        if ($copy.name -in $required) {
            $copy.isEnabled = 'True'
            if ($copy.name -eq 'ContainerSensor') {
                if (-not $copy.additionalExtensionProperties) {
                    $copy | Add-Member -MemberType NoteProperty -Name additionalExtensionProperties -Value ([pscustomobject]@{})
                }
                foreach ($setting in @('AntiMalwareEnabled', 'SecurityGatingEnabled')) {
                    $existing = $copy.additionalExtensionProperties.PSObject.Properties[$setting]
                    if ($existing) { $existing.Value = 'True' }
                    else { $copy.additionalExtensionProperties | Add-Member -MemberType NoteProperty -Name $setting -Value 'True' }
                }
            }
        }
        $merged.Add($copy)
    }

    foreach ($name in $required) {
        if (-not ($merged | Where-Object name -eq $name)) {
            if ($name -eq 'ContainerSensor') {
                $merged.Add([pscustomobject][ordered]@{
                    name = $name
                    isEnabled = 'True'
                    additionalExtensionProperties = [pscustomobject][ordered]@{
                        AntiMalwareEnabled = 'True'
                        SecurityGatingEnabled = 'True'
                    }
                })
            }
            else {
                $merged.Add([pscustomobject][ordered]@{ name = $name; isEnabled = 'True' })
            }
        }
    }

    if ($desired.PSObject.Properties['extensions']) {
        $desired.extensions = @($merged)
    }
    else {
        $desired | Add-Member -MemberType NoteProperty -Name extensions -Value @($merged)
    }
    return $desired
}

function Get-PricingFingerprint {
    param([Parameter(Mandatory)]$Properties)
    $writable = Get-WritablePricingProperties $Properties
    $canonical = ConvertTo-CanonicalValue $writable
    return $canonical | ConvertTo-Json -Depth 30 -Compress
}

function Set-PricingProperties {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)]$Properties,
        [Parameter(Mandatory)][string]$Action
    )
    $body = @{ properties = $Properties } | ConvertTo-Json -Depth 30 -Compress
    az rest --method PUT --url $Url --body $body --headers 'Content-Type=application/json' --output none 2>$null
    Assert-LastExitCode -Action $Action
}

function Restore-PricingIfUnchanged {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Reason
    )

    $current = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--url', $Context.url, '--only-show-errors', '--output', 'json')
    if ((Get-PricingFingerprint $current.properties) -ne (Get-PricingFingerprint $Context.desired)) {
        throw "Refusing to restore Defender pricing after $Reason because the shared setting changed after this lab wrote it."
    }
    Set-PricingProperties -Url $Context.url -Properties $Context.before -Action "Defender pricing restore after $Reason"
}

trap {
    $original = $_
    if ($script:PricingRollbackContext) {
        try {
            Restore-PricingIfUnchanged -Context $script:PricingRollbackContext -Reason 'deployment failure'
            $script:PricingRollbackContext = $null
        }
        catch {
            throw "Deployment failed: $($original.Exception.Message) Automatic Defender pricing restore also failed: $($_.Exception.Message)"
        }
    }
    throw $original
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

$account = Invoke-AzJson -Arguments @('account', 'show', '--query', '{id:id,name:name}', '--output', 'json')
if (-not $account.id) {
    throw "Azure CLI is not signed in. Run 'az login' and select the intended subscription."
}
Write-Host "  Subscription: $($account.name) ($($account.id))"

$subscriptionId = [string]$account.id
$resourceGroupId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup"
$workspaceId = "$resourceGroupId/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
$pricingUrl = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Security/pricings/Containers?api-version=$PricingApiVersion"
$state = Read-LabState
$existingResourceGroup = Invoke-AzJson -Arguments @('group', 'show', '--name', $ResourceGroup, '--output', 'json') -NotFoundIsNull

if ($state) {
    Assert-LabStateContext -State $state -SubscriptionId $subscriptionId -ExpectedResourceGroupId $resourceGroupId
    if ($state.projectName -ne $ProjectName -or $state.workspaceId -ne $workspaceId) {
        throw 'Ownership manifest does not match this project and workspace.'
    }
    if ($existingResourceGroup -and [string]$existingResourceGroup.tags.$OwnershipTagName -ne [string]$state.ownerToken) {
        throw "Refusing to use resource group '$ResourceGroup': its ownership tag does not match the manifest."
    }
}
elseif ($existingResourceGroup) {
    throw "Refusing to adopt pre-existing resource group '$ResourceGroup' without this lab's ownership manifest."
}

# ---------- Destroy ----------
if ($Destroy) {
    if (-not $state) {
        throw "Cleanup requires the exact ownership manifest: $StatePath"
    }

    $pricingCurrent = $null
    if ([bool]$state.pricingChanged) {
        $pricingCurrent = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--url', $pricingUrl, '--only-show-errors', '--output', 'json')
        if ((Get-PricingFingerprint $pricingCurrent.properties) -ne (Get-PricingFingerprint $state.pricingDesired)) {
            throw 'Refusing cleanup because the shared Defender pricing setting changed after this lab configured it.'
        }
    }

    Write-Host "[!] Destroying exact manifest-owned lab resources..." -ForegroundColor Yellow
    if ([bool]$state.pricingChanged -and $PSCmdlet.ShouldProcess('Defender for Containers pricing', 'Restore captured pre-lab shared setting')) {
        Set-PricingProperties -Url $pricingUrl -Properties $state.pricingBefore -Action 'Defender for Containers pricing restore'
    }
    if ($existingResourceGroup -and $PSCmdlet.ShouldProcess($resourceGroupId, 'Delete exact manifest-owned resource group')) {
        az group delete --name $ResourceGroup --yes
        Assert-LastExitCode -Action "Resource-group deletion for $ResourceGroup"
    }
    if (-not $WhatIfPreference) {
        $remainingGroup = Invoke-AzJson -Arguments @('group', 'show', '--name', $ResourceGroup, '--output', 'json') -NotFoundIsNull
        if ($remainingGroup) {
            throw "Resource group '$ResourceGroup' still exists; the manifest was retained for a safe retry."
        }
        if ($PSCmdlet.ShouldProcess($StatePath, 'Remove ownership manifest after verified cleanup')) {
            Remove-Item -LiteralPath $StatePath -Force
        }
        Write-Host '[+] Shared pricing restored and exact owned resource group removed.' -ForegroundColor Green
    }
    else {
        Write-Host '[+] Cleanup preview complete; no changes were made.' -ForegroundColor Cyan
    }
    return
}

$currentPricingResource = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--url', $pricingUrl, '--only-show-errors', '--output', 'json')
$currentPricing = Get-WritablePricingProperties $currentPricingResource.properties

if ($state) {
    $pricingBefore = $state.pricingBefore
    $desiredPricing = $state.pricingDesired
    $currentFingerprint = Get-PricingFingerprint $currentPricing
    $beforeFingerprint = Get-PricingFingerprint $pricingBefore
    $desiredFingerprint = Get-PricingFingerprint $desiredPricing
    if ($currentFingerprint -ne $beforeFingerprint -and $currentFingerprint -ne $desiredFingerprint) {
        throw 'Shared Defender pricing drifted from both the captured before-state and this lab desired-state.'
    }
    $defenderPlanNeedsUpdate = $currentFingerprint -ne $desiredFingerprint
    $ownerToken = [string]$state.ownerToken
}
else {
    $pricingBefore = $currentPricing
    $desiredPricing = New-DesiredPricingProperties $currentPricingResource.properties
    $defenderPlanNeedsUpdate = (Get-PricingFingerprint $pricingBefore) -ne (Get-PricingFingerprint $desiredPricing)
    $ownerToken = [guid]::NewGuid().ToString('N')
    $ruleSlugs = @('binary-drift-prod', 'container-malware', 'gated-deployment-block', 'kubectl-exec')
    $state = [ordered]@{
        version = 1
        projectName = $ProjectName
        ownerToken = $ownerToken
        subscriptionId = $subscriptionId
        resourceGroupId = $resourceGroupId
        workspaceId = $workspaceId
        pricingChanged = $defenderPlanNeedsUpdate
        pricingBefore = $pricingBefore
        pricingDesired = $desiredPricing
        sentinelRules = @($ruleSlugs | ForEach-Object {
            [ordered]@{ slug = $_; id = Get-StableGuid "$ownerToken|$workspaceId|rule|$_" }
        })
        sentinelWorkbookId = Get-StableGuid "$ownerToken|$workspaceId|workbook"
    }
}

if ($WhatIfPreference) {
    $sentinelPreview = if ($SkipSentinel) { 'Skip Sentinel rules and workbook' } else { 'Preflight and deploy 4 owned Sentinel rules and 1 owned workbook' }
    Write-Host "`n=== Deployment Preview Only ===" -ForegroundColor Yellow
    Write-Host @"

No Azure, Kubernetes, Helm, kubeconfig, or local secret-file mutations were performed.

Planned changes:
  - Deploy AKS cluster: $ProjectName (Kubernetes 1.35, 1 node, Standard_D4s_v3)
  - Deploy workspace:   $WorkspaceName
  - Merge required Defender for Containers settings while preserving other extensions/properties
  - Replace the managed AKS Defender profile with Helm chart $DefenderHelmChartVersion
  - Enable the Helm anti-malware collector
  - $sentinelPreview

Manual step after a real deployment:
  Configure the binary drift policy in Defender for Cloud.
"@
    return
}

if (
    $defenderPlanNeedsUpdate -and
    $env:CONFIRM_SUBSCRIPTION_SCOPE -ne 'ENABLE-DEFENDER-FOR-CONTAINERS'
) {
    throw @'
This deployment would enable or change paid Defender for Containers settings at subscription scope.
Review the active subscription and pricing, then set CONFIRM_SUBSCRIPTION_SCOPE=ENABLE-DEFENDER-FOR-CONTAINERS to continue.
No deployment changes were made.
'@
}

if (-not (Test-Path -LiteralPath $StatePath)) {
    Write-LabState -State $state
}

# ---------- Deploy Infrastructure ----------
Write-Host "`n[2/7] Deploying infrastructure (Bicep)..." -ForegroundColor Yellow

$bicepPath = Join-Path $LabRoot 'bicep/main.bicep'

if ($PSCmdlet.ShouldProcess("Subscription", "Deploy Bicep template")) {
    $deployment = az deployment sub create `
        --location $Location `
        --template-file $bicepPath `
        --parameters projectName=$ProjectName location=$Location ownerToken=$ownerToken `
        --query 'properties.outputs' -o json | ConvertFrom-Json
    Assert-LastExitCode -Action 'AKS lab infrastructure deployment'

    $clusterName = $deployment.clusterName.value
    $deployedWorkspaceId = $deployment.workspaceId.value
    $deployedResourceGroupId = $deployment.resourceGroupId.value
    if (-not $clusterName -or $deployedWorkspaceId -ne $workspaceId -or $deployedResourceGroupId -ne $resourceGroupId) {
        throw 'The infrastructure deployment did not return the expected cluster and workspace outputs.'
    }

    $ownedResourceGroup = Invoke-AzJson -Arguments @('group', 'show', '--name', $ResourceGroup, '--output', 'json')
    if ([string]$ownedResourceGroup.tags.$OwnershipTagName -ne $ownerToken) {
        throw 'Resource group deployment did not preserve the manifest ownership token.'
    }

    Write-Host "  AKS Cluster:  $clusterName" -ForegroundColor Green
    Write-Host "  Workspace:    $WorkspaceName" -ForegroundColor Green
}

# ---------- Enable Defender for Containers ----------
Write-Host "`n[3/7] Enabling Defender for Containers plan..." -ForegroundColor Yellow

if ($defenderPlanNeedsUpdate -and $PSCmdlet.ShouldProcess("Subscription", "Enable Defender for Containers")) {
    $script:PricingRollbackContext = [pscustomobject]@{
        url = $pricingUrl
        before = $pricingBefore
        desired = $desiredPricing
    }
    Set-PricingProperties -Url $pricingUrl -Properties $desiredPricing -Action 'Defender for Containers configuration'
    $writtenPricing = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--url', $pricingUrl, '--only-show-errors', '--output', 'json')
    if ((Get-PricingFingerprint $writtenPricing.properties) -ne (Get-PricingFingerprint $desiredPricing)) {
        throw 'Defender for Containers did not persist the exact merged desired state.'
    }

    Write-Host "  Defender for Containers: Enabled (with AntiMalware)" -ForegroundColor Green
}
elseif (-not $defenderPlanNeedsUpdate) {
    Write-Host "  Defender for Containers: Required subscription settings already enabled" -ForegroundColor Green
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
        $podJson = kubectl get pods -n mdc -o json 2>$null
        Assert-LastExitCode -Action 'Defender sensor readiness lookup'
        $defenderPods = @((($podJson -join "`n") | ConvertFrom-Json).items | Where-Object {
            $_.metadata.name -match '(?i)(microsoft-defender|defender)'
        })
        $unreadyPods = @($defenderPods | Where-Object {
            $_.status.phase -ne 'Running' -or
            @($_.status.containerStatuses).Count -eq 0 -or
            @($_.status.containerStatuses | Where-Object { -not $_.ready }).Count -gt 0
        })
        if ($defenderPods.Count -gt 0 -and $unreadyPods.Count -eq 0) {
            Write-Host "  Defender sensor pods: Ready" -ForegroundColor Green
            break
        }
        $retries++
        Start-Sleep -Seconds 10
    }
    if ($retries -eq $maxRetries) {
        throw 'Defender sensor pods did not reach Running/Ready state before the deployment timeout.'
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
    # The connector, every rule, and the workbook are all preflighted before
    # the first Sentinel write below.

    # Rule definitions
    $rules = @(
        @{
            slug     = 'binary-drift-prod'
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
            slug     = 'container-malware'
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
            slug     = 'gated-deployment-block'
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
            slug     = 'kubectl-exec'
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

    $listedRulesResponse = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--url', "$baseUrl`?api-version=$apiVersion", '--only-show-errors', '--output', 'json')
    $listedRules = @($listedRulesResponse.value)
    foreach ($rule in $rules) {
        $manifestRule = @($state.sentinelRules | Where-Object slug -eq $rule.slug)
        if ($manifestRule.Count -ne 1) {
            throw "Ownership manifest has no unique Sentinel rule ID for '$($rule.slug)'."
        }
        $ruleId = [string]$manifestRule[0].id
        $ruleUrl = "$baseUrl/${ruleId}?api-version=$apiVersion"
        $rule['id'] = $ruleId
        $rule['url'] = $ruleUrl
        $exactRule = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--url', $ruleUrl, '--only-show-errors', '--output', 'json') -NotFoundIsNull
        if ($exactRule -and (
            $exactRule.properties.displayName -ne $rule.name -or
            $exactRule.properties.description -notmatch [regex]::Escape("[Owner: $ownerToken]")
        )) {
            throw "Refusing to overwrite Sentinel rule '$ruleId': provenance does not match."
        }
        $nameCollisions = @($listedRules | Where-Object {
            $_.properties.displayName -eq $rule.name -and $_.name -ne $ruleId
        })
        if ($nameCollisions.Count -gt 0) {
            throw "Refusing to deploy '$($rule.name)': another rule already uses that display name."
        }
    }

    $existingConnector = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--url', $connectorUrl, '--only-show-errors', '--output', 'json') -NotFoundIsNull
    if ($existingConnector -and (
        $existingConnector.kind -ne 'AzureSecurityCenter' -or
        [string]$existingConnector.properties.subscriptionId -ne $subscriptionId -or
        [string]$existingConnector.properties.dataTypes.alerts.state -ne 'Enabled'
    )) {
        throw 'The deterministic Defender for Cloud connector ID is occupied by an incompatible resource.'
    }

    Write-Host "`n[7/7] Preflighting Sentinel workbook..." -ForegroundColor Yellow
    $workbookPath = Join-Path $LabRoot 'workbook/container-runtime-workbook.json'
    if (-not (Test-Path -LiteralPath $workbookPath -PathType Leaf)) {
        throw "Workbook template is missing: $workbookPath"
    }
    $workbookContent = Get-Content -LiteralPath $workbookPath -Raw
    $workbookDisplayName = 'Container Runtime Security Dashboard'
    $workbookId = [string]$state.sentinelWorkbookId
    $workbookUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01"
    $existingWorkbook = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--url', $workbookUrl, '--only-show-errors', '--output', 'json') -NotFoundIsNull
    if ($existingWorkbook -and (
        $existingWorkbook.properties.displayName -ne $workbookDisplayName -or
        [string]$existingWorkbook.tags.$OwnershipTagName -ne $ownerToken
    )) {
        throw "Refusing to overwrite workbook '$workbookId': provenance does not match."
    }
    $listedWorkbooks = @(Invoke-AzJson -Arguments @(
        'resource', 'list', '--resource-group', $ResourceGroup,
        '--resource-type', 'Microsoft.Insights/workbooks', '--output', 'json'
    ))
    $workbookCollisions = @($listedWorkbooks | Where-Object {
        $_.name -ne $workbookId -and $_.tags.'hidden-title' -eq $workbookDisplayName
    })
    if ($workbookCollisions.Count -gt 0) {
        throw "Refusing to deploy workbook: another resource already uses '$workbookDisplayName'."
    }

    if (-not $existingConnector -and $PSCmdlet.ShouldProcess('Defender for Cloud data connector', 'Create exact compatible Sentinel data connector')) {
        az rest --method PUT --url $connectorUrl --body $connectorBody --headers 'Content-Type=application/json' -o none 2>$null
        Assert-LastExitCode -Action 'Defender for Cloud data-connector deployment'
        Write-Host '  Defender for Cloud data connector: Created' -ForegroundColor Green
    }
    elseif ($existingConnector) {
        Write-Host '  Defender for Cloud data connector: Reused without overwrite' -ForegroundColor Green
    }

    foreach ($rule in $rules) {
        $body = @{
            kind       = 'Scheduled'
            properties = @{
                displayName          = $rule.name
                description          = "AKS Runtime Security Lab - $($rule.name)`n`n[Owner: $ownerToken]"
                severity             = $rule.severity
                enabled              = [bool]$EnableSentinelRules
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

        if ($PSCmdlet.ShouldProcess($rule.name, 'Create or update exact owned Sentinel analytics rule')) {
            az rest --method PUT --url $rule.url --body $body --headers 'Content-Type=application/json' -o none 2>$null
            Assert-LastExitCode -Action "Sentinel rule deployment for $($rule.name)"
            Write-Host "  Rule: $($rule.name)" -ForegroundColor Green
        }
    }

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
            $OwnershipTagName = $ownerToken
        }
    } | ConvertTo-Json -Depth 10

    if ($PSCmdlet.ShouldProcess($workbookDisplayName, 'Create or update exact owned workbook')) {
        az rest --method PUT --url $workbookUrl --body $workbookBody --headers 'Content-Type=application/json' -o none 2>$null
        Assert-LastExitCode -Action 'Sentinel workbook deployment'
        Write-Host "  Workbook: $workbookDisplayName" -ForegroundColor Green
    }
} else {
    Write-Host "`n[6/7] Skipping Sentinel rules (--SkipSentinel)." -ForegroundColor Gray
    Write-Host "[7/7] Skipping workbook (--SkipSentinel)." -ForegroundColor Gray
}

# ---------- Summary ----------
$script:PricingRollbackContext = $null
$sentinelSummary = if ($SkipSentinel) {
    'Skipped by request'
}
elseif ($EnableSentinelRules) {
    '4 enabled owned analytics rules + 1 owned workbook'
}
else {
    '4 disabled owned analytics rules + 1 owned workbook (review before enabling)'
}
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
  ./Deploy-Lab.ps1 -ProjectName '$ProjectName' -Destroy -WhatIf
  ./Deploy-Lab.ps1 -ProjectName '$ProjectName' -Destroy

"@
