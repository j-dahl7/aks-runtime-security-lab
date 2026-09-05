#Requires -Version 7.0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$DeployScript = Join-Path $Root 'scripts/Deploy-Lab.ps1'
$RuntimeTestScript = Join-Path $Root 'scripts/Test-RuntimeSecurity.ps1'
$AnalyticsRules = Join-Path $Root 'detection/analytics-rules.kql'
$Workbook = Join-Path $Root 'workbook/container-runtime-workbook.json'
$StatePath = Join-Path $Root '.aks-runtime-lab-state-aks-runtime-lab.json'
if (Test-Path -LiteralPath $StatePath) {
    throw 'Refusing to run the mocked safety harness over an existing ownership manifest. Use a fresh checkout.'
}
$global:AksMockSubscriptionId = '00000000-0000-0000-0000-000000000000'
$global:AksMockResourceGroupId = "/subscriptions/$global:AksMockSubscriptionId/resourceGroups/aks-runtime-lab-rg"
$global:AksMockWorkspaceResourceId = "$global:AksMockResourceGroupId/providers/Microsoft.OperationalInsights/workspaces/aks-runtime-lab-law"
$global:AksMockWorkspaceCustomerId = '11111111-1111-1111-1111-111111111111'
$global:AksMockWorkspaceKey = 'TEST-ONLY-NOT-A-REAL-WORKSPACE-KEY'
$OriginalSubscriptionConfirmation = $env:CONFIRM_SUBSCRIPTION_SCOPE
# 1.1.1.1/32 is synthetic input for mocked Azure responses, never contacted.

function Assert-Condition {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function New-MockPricingProperties {
    param([bool]$Configured)
    if (-not $Configured) {
        return [pscustomobject]@{ pricingTier = 'Free'; extensions = @() }
    }
    return [pscustomobject]@{
        pricingTier = 'Standard'
        enforce = 'False'
        extensions = @(
            [pscustomobject]@{
                name = 'UnrelatedFutureExtension'
                isEnabled = 'False'
                additionalExtensionProperties = [pscustomobject]@{ PreserveMe = 'yes' }
            },
            [pscustomobject]@{
                name = 'ContainerSensor'
                isEnabled = 'True'
                additionalExtensionProperties = [pscustomobject]@{
                    AntiMalwareEnabled = 'True'
                    SecurityGatingEnabled = 'True'
                    PreserveSensorSetting = 'yes'
                }
            },
            [pscustomobject]@{ name = 'ContainerRegistriesVulnerabilityAssessments'; isEnabled = 'True' },
            [pscustomobject]@{ name = 'AgentlessDiscoveryForKubernetes'; isEnabled = 'True' },
            [pscustomobject]@{ name = 'ContainerIntegrityContribution'; isEnabled = 'True' }
        )
    }
}

function Reset-MockState {
    param([bool]$PricingConfigured = $false)
    Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    $global:AksMockExternalCalls = [System.Collections.Generic.List[string]]::new()
    $global:AksMockMutationCalls = [System.Collections.Generic.List[string]]::new()
    $global:AksMockHelmShouldFail = $false
    $global:AksMockPodsReady = $true
    $global:AksMockRulePutShouldFail = $false
    $global:AksMockForeignWorkbook = $false
    $global:AksMockLegacyGatedRuleId = $null
    $global:AksMockLegacyGatedRuleExists = $false
    $global:AksMockResourceGroupExists = $false
    $global:AksMockOwnerToken = $null
    $global:AksMockValuesFilePath = $null
    $global:AksMockValuesDirectory = $null
    $global:AksMockPricingProperties = New-MockPricingProperties -Configured $PricingConfigured
    $global:AksMockPolicyTemplateExists = $false
    $global:AksMockGroupDeleteShouldFail = $false
    $global:AksMockPricingPutShouldFail = $false
    $global:AksMockGroupExistsShouldFail = $false
}

function Add-MockCall {
    param([Parameter(Mandatory)][string]$Command, [switch]$Mutation)
    $global:AksMockExternalCalls.Add($Command)
    if ($Mutation) { $global:AksMockMutationCalls.Add($Command) }
}

function global:az {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $command = 'az ' + ($arguments -join ' ')
    $methodIndex = [Array]::IndexOf($arguments, '--method')
    $restMethod = if ($methodIndex -ge 0) { $arguments[$methodIndex + 1] } else { '' }
    $isMutation =
        ($arguments[0] -eq 'deployment' -and $arguments[2] -eq 'create') -or
        ($arguments[0] -eq 'rest' -and $restMethod -in @('PUT', 'POST', 'PATCH', 'DELETE')) -or
        ($arguments[0] -eq 'aks' -and $arguments[1] -in @('get-credentials', 'update')) -or
        ($arguments[0] -eq 'tag' -and $arguments[1] -eq 'update') -or
        ($arguments[0] -eq 'group' -and $arguments[1] -eq 'delete')
    Add-MockCall -Command $command -Mutation:$isMutation
    $global:LASTEXITCODE = 0

    if ($arguments[0] -eq 'account' -and $arguments[1] -eq 'show') {
        return (@{ id = $global:AksMockSubscriptionId; tenantId = '11111111-1111-1111-1111-111111111111'; name = 'Mock Subscription' } | ConvertTo-Json -Compress)
    }
    if ($arguments[0] -eq 'group' -and $arguments[1] -eq 'exists') {
        if ($global:AksMockGroupExistsShouldFail) { $global:LASTEXITCODE = 1; return 'authorization context not found' }
        return ($global:AksMockResourceGroupExists | ConvertTo-Json -Compress)
    }
    if ($arguments[0] -eq 'group' -and $arguments[1] -eq 'show') {
        if (-not $global:AksMockResourceGroupExists) {
            $global:LASTEXITCODE = 3
            return 'ResourceGroupNotFound'
        }
        return (@{
            id = $global:AksMockResourceGroupId
            name = 'aks-runtime-lab-rg'
            tags = @{ 'nlzt-owner' = $global:AksMockOwnerToken }
        } | ConvertTo-Json -Compress)
    }
    if ($arguments[0] -eq 'group' -and $arguments[1] -eq 'delete') {
        if ($global:AksMockGroupDeleteShouldFail) { $global:LASTEXITCODE = 42; return 'simulated delete failure' }
        $global:AksMockResourceGroupExists = $false
        return
    }
    if ($arguments[0] -eq 'deployment' -and $arguments[1] -eq 'sub') {
        $ownerArgument = @($arguments | Where-Object { $_ -like 'ownerToken=*' })
        if ($ownerArgument.Count -ne 1) { throw 'Bicep deployment did not receive one ownerToken parameter.' }
        $global:AksMockOwnerToken = $ownerArgument[0].Substring('ownerToken='.Length)
        $global:AksMockResourceGroupExists = $true
        return (@{
            clusterName = @{ value = 'aks-runtime-lab' }
            workspaceId = @{ value = $global:AksMockWorkspaceResourceId }
            resourceGroupId = @{ value = $global:AksMockResourceGroupId }
        } | ConvertTo-Json -Compress)
    }
    if ($arguments[0] -eq 'rest') {
        $urlIndex = [Array]::IndexOf($arguments, '--url')
        $url = if ($urlIndex -ge 0) { $arguments[$urlIndex + 1] } else { '' }
        if ($restMethod -eq 'GET' -and $url -match '/Microsoft.Security/pricings/Containers') {
            return (@{ properties = $global:AksMockPricingProperties } | ConvertTo-Json -Depth 30 -Compress)
        }
        if ($restMethod -eq 'PUT' -and $url -match '/Microsoft.Security/pricings/Containers') {
            if ($global:AksMockPricingPutShouldFail) { $global:LASTEXITCODE = 43; return 'simulated pricing failure' }
            $bodyIndex = [Array]::IndexOf($arguments, '--body')
            $global:AksMockPricingProperties = ($arguments[$bodyIndex + 1] | ConvertFrom-Json).properties
            return
        }
        if ($restMethod -eq 'GET' -and $url -match '/alertRules\?') {
            return '{"value":[]}'
        }
        if (
            $restMethod -eq 'GET' -and
            $global:AksMockLegacyGatedRuleExists -and
            $global:AksMockLegacyGatedRuleId -and
            $url -match "/alertRules/$([regex]::Escape($global:AksMockLegacyGatedRuleId))\?"
        ) {
            return (@{
                name = $global:AksMockLegacyGatedRuleId
                properties = @{
                    displayName = 'LAB - Vulnerable Image Deployment Attempted'
                    description = "deprecated [Owner: $global:AksMockOwnerToken]"
                }
            } | ConvertTo-Json -Depth 5 -Compress)
        }
        if (
            $restMethod -eq 'DELETE' -and
            $global:AksMockLegacyGatedRuleId -and
            $url -match "/alertRules/$([regex]::Escape($global:AksMockLegacyGatedRuleId))\?"
        ) {
            $global:AksMockLegacyGatedRuleExists = $false
            return
        }
        if ($restMethod -eq 'GET' -and $url -match '/workbooks/' -and $global:AksMockForeignWorkbook) {
            return '{"name":"foreign","properties":{"displayName":"Foreign"},"tags":{"nlzt-owner":"foreign"}}'
        }
        if ($restMethod -eq 'GET') {
            $global:LASTEXITCODE = 3
            return 'ResourceNotFound'
        }
        if ($restMethod -eq 'PUT' -and $url -match '/alertRules/' -and $global:AksMockRulePutShouldFail) {
            $global:LASTEXITCODE = 42
            return 'simulated rule failure'
        }
        return
    }
    if ($arguments[0] -eq 'aks' -and $arguments[1] -eq 'show') {
        return (@{
            id = "$global:AksMockResourceGroupId/providers/Microsoft.ContainerService/managedClusters/aks-runtime-lab"
            resourceUid = 'immutable-arm-id'
            fqdn = 'owned.eastus.azmk8s.io'
            apiServerAccessProfile = @{ authorizedIpRanges = @('1.1.1.1/32') }
            location = 'eastus'
            tags = @{}
            securityProfile = @{
                defender = @{
                    logAnalyticsWorkspaceResourceId = $global:AksMockWorkspaceResourceId
                    securityMonitoring = @{ enabled = $true }
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress)
    }
    if ($arguments[0] -eq 'policy' -and $arguments[1] -eq 'assignment') { return '[]' }
    if ($arguments[0] -eq 'monitor' -and $arguments[1] -eq 'log-analytics') {
        if ($arguments -contains 'get-shared-keys') { return $global:AksMockWorkspaceKey }
        return $global:AksMockWorkspaceCustomerId
    }
    if ($arguments[0] -eq 'resource' -and $arguments[1] -eq 'list') {
        if ($global:AksMockForeignWorkbook) {
            return '[{"name":"foreign-workbook","tags":{"hidden-title":"Container Runtime Security Dashboard"}}]'
        }
        return '[]'
    }
}

function global:kubectl {
    $arguments = @($args | ForEach-Object { [string]$_ })
    if ($arguments[0] -eq '--context') { $arguments = $arguments[2..($arguments.Count-1)] }
    Add-MockCall -Command ('kubectl ' + ($arguments -join ' ')) -Mutation:($arguments[0] -eq 'delete')
    $global:LASTEXITCODE = 0
    if ($arguments[0] -eq 'config') {
        if ($arguments[1] -eq 'current-context') { return 'aks-runtime-lab' }
        if (($arguments -join ' ') -match 'certificate-authority-data') { return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('mock-ca')) }
        if (($arguments -join ' ') -match 'insecure-skip-tls') { return 'false' }
        return 'https://owned.eastus.azmk8s.io:443'
    }
    if ($arguments[0] -eq 'get' -and $arguments[1] -eq 'namespace' -and $arguments[2] -eq 'kube-system') { return '{"metadata":{"uid":"immutable-kube-id"}}' }
    if ($arguments[1] -eq 'crd' -and $arguments[2] -eq 'policytemplates.defender.microsoft.com') {
        if ($arguments[0] -eq 'get' -and $global:AksMockPolicyTemplateExists) {
            return 'customresourcedefinition.apiextensions.k8s.io/policytemplates.defender.microsoft.com'
        }
        if ($arguments[0] -eq 'delete') { $global:AksMockPolicyTemplateExists = $false }
        return
    }
    if ($arguments[0] -eq 'get' -and $arguments[1] -eq 'pods') {
        $ready = [bool]$global:AksMockPodsReady
        $phase = if ($ready) { 'Running' } else { 'Pending' }
        return (@{
            items = @(@{
                metadata = @{ name = 'microsoft-defender-publisher-test' }
                status = @{
                    phase = $phase
                    containerStatuses = @(@{ name = 'sensor'; ready = $ready })
                }
            })
        } | ConvertTo-Json -Depth 8 -Compress)
    }
}

function global:helm {
    $arguments = @($args | ForEach-Object { [string]$_ })
    Add-MockCall -Command ('helm ' + ($arguments -join ' ')) -Mutation:($arguments[0] -eq 'upgrade')
    $global:LASTEXITCODE = 0
    if ($arguments[0] -eq 'list') { return '[]' }
    if ($arguments[0] -ne 'upgrade') { return }

    $valuesIndex = [Array]::IndexOf($arguments, '--values')
    if ($valuesIndex -lt 0) { throw 'Helm was not given a values file.' }
    $valuesPath = $arguments[$valuesIndex + 1]
    $global:AksMockValuesFilePath = $valuesPath
    $global:AksMockValuesDirectory = Split-Path -Parent $valuesPath
    if (-not (Test-Path -LiteralPath $valuesPath)) { throw 'Helm values file did not exist.' }
    if (($arguments -join ' ') -like "*$global:AksMockWorkspaceKey*") { throw 'Workspace key leaked into process arguments.' }
    if ($arguments -notcontains '--atomic') { throw 'Helm did not use --atomic.' }
    $values = Get-Content -LiteralPath $valuesPath -Raw | ConvertFrom-Json
    $sensorValues = $values.'microsoft-defender-for-containers-sensor'
    if (-not $sensorValues.omsagent.secret.wsid -or -not $sensorValues.omsagent.secret.key) {
        throw 'Secure values file was incomplete.'
    }
    if ($global:AksMockHelmShouldFail) { $global:LASTEXITCODE = 42 }
}

function global:Start-Sleep { param() }

try {
    $enableHelp = Get-Help $DeployScript -Parameter EnableSentinelRules | Out-String
    Assert-Condition ($enableHelp -match 'Without this switch' -and $enableHelp -match 'disabled') 'Get-Help does not explain default-disabled Sentinel rules.'
    $runtimeSource = Get-Content -LiteralPath $RuntimeTestScript -Raw
    $analyticsSource = Get-Content -LiteralPath $AnalyticsRules -Raw
    $workbookSource = Get-Content -LiteralPath $Workbook -Raw
    Assert-Condition ($runtimeSource -match "\[string\]\`$ProjectName\s*=\s*'aks-runtime-lab'") 'Runtime helper lacks ProjectName boundary.'
    Assert-Condition ($runtimeSource -match "\[string\]\`$Namespace\s*=\s*'runtime-security-tests'") 'Runtime helper lacks namespace boundary.'
    Assert-Condition ($runtimeSource -match 'chmod \+x /tmp/eicar\.com' -and $runtimeSource -match '"/tmp/eicar\.com"') 'Anti-malware test does not attempt EICAR execution.'
    Assert-Condition ($runtimeSource -match 'mcr\.microsoft\.com/mdc/dev/defender-admission-controller/test-images:one-high') 'Gated deployment does not use Microsoft''s documented test image.'
    Assert-Condition ($runtimeSource -match 'Admission Monitoring') 'Gated deployment results are not routed to Admission Monitoring.'
    Assert-Condition ($runtimeSource -notmatch 'nginx:1\.14\.0') 'Runtime helper still relies on a stale arbitrary image tag.'
    Assert-Condition ($analyticsSource -notmatch 'GatedDeployment|Vulnerable Image Deployment Attempted') 'Standalone rules still invent a gated-deployment SecurityAlert schema.'
    Assert-Condition ($workbookSource -notmatch '"GatedDeployment"') 'Workbook still queries an undocumented gated-deployment alert type.'
    Assert-Condition ($analyticsSource -notmatch 'RequestURI !has "kube-system"') 'Interactive kube-system execution is still suppressed.'
    $null = $workbookSource | ConvertFrom-Json

    Reset-MockState -PricingConfigured $true
    $rangeError = $null
    try { & $DeployScript -SkipSentinel *> $null } catch { $rangeError = $_ }
    Assert-Condition ($rangeError.Exception.Message -match 'explicit API server authorized') 'First deployment did not require explicit API server ranges.'
    Assert-Condition ($global:AksMockMutationCalls.Count -eq 0 -and -not (Test-Path -LiteralPath $StatePath)) 'Missing ranges allowed a mutation.'
    foreach ($badRange in @('0.0.0.0/0', '8.8.8.0/23', '999.1.1.1/32', '10.0.0.1/32', '8.8.8.7/24', '::1/128',
        '192.0.2.1/32', '198.51.100.0/24', '203.0.113.255/32', '198.18.0.0/24', '198.19.255.255/32', '192.0.0.9/32', '192.88.99.0/24')) {
        $rangeError = $null
        try { & $DeployScript -ApiServerAuthorizedIpRanges @($badRange) -SkipSentinel *> $null } catch { $rangeError = $_ }
        Assert-Condition ($null -ne $rangeError -and $global:AksMockMutationCalls.Count -eq 0) "Unsafe range was accepted: $badRange"
    }

    Reset-MockState
    $global:AksMockPolicyTemplateExists = $true
    $preview = & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -WhatIf -SkipSentinel 6>&1 | Out-String
    Assert-Condition ($global:AksMockMutationCalls.Count -eq 0) "WhatIf mutated state: $($global:AksMockMutationCalls -join '; ')"
    Assert-Condition ($preview -match 'Deployment Preview Only' -and $preview -notmatch 'Deployment Complete') 'Preview output was misleading.'
    Assert-Condition (-not (Test-Path -LiteralPath $StatePath)) 'WhatIf wrote a manifest.'
    Assert-Condition $global:AksMockPolicyTemplateExists 'WhatIf removed a stale CRD.'

    $destroyRejected = $false
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -Destroy -WhatIf *> $null } catch { $destroyRejected = $_.Exception.Message -match 'requires the exact ownership manifest' }
    Assert-Condition $destroyRejected 'Destroy preview without a manifest was not rejected.'

    Reset-MockState
    Remove-Item Env:\CONFIRM_SUBSCRIPTION_SCOPE -ErrorAction SilentlyContinue
    $billingError = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -SkipSentinel *> $null } catch { $billingError = $_ }
    Assert-Condition ($billingError.Exception.Message -match 'CONFIRM_SUBSCRIPTION_SCOPE=ENABLE-DEFENDER-FOR-CONTAINERS') 'Paid-plan gate did not fail closed.'
    Assert-Condition ($global:AksMockMutationCalls.Count -eq 0) 'Paid-plan gate allowed a mutation.'
    Assert-Condition (-not (Test-Path -LiteralPath $StatePath)) 'Paid-plan gate wrote a manifest.'

    Reset-MockState -PricingConfigured $true
    $global:AksMockPolicyTemplateExists = $true
    $configuredOutput = & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -SkipSentinel 6>&1 | Out-String
    Assert-Condition ($configuredOutput -match 'Deployment Complete') 'Configured deployment did not complete.'
    Assert-Condition (($global:AksMockMutationCalls -join "`n") -notmatch 'pricings/Containers') 'Configured pricing was rewritten.'
    Assert-Condition (Test-Path -LiteralPath $StatePath) 'Deployment did not retain its ownership manifest.'
    $recordedIdentity = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    Assert-Condition ($recordedIdentity.runtimeProof.clusterResourceUid -eq 'immutable-arm-id' -and $recordedIdentity.runtimeProof.kubeSystemUid -eq 'immutable-kube-id') 'Deployment did not record both immutable cluster IDs.'
    $beforeRerun = $global:AksMockMutationCalls.Count
    $rangeError = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.2/32') -SkipSentinel *> $null } catch { $rangeError = $_ }
    Assert-Condition ($rangeError.Exception.Message -match 'exact recorded' -and $global:AksMockMutationCalls.Count -eq $beforeRerun) 'Owned rerun silently changed network boundaries.'
    & $DeployScript -SkipSentinel *> $null
    $rerunIdentity = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    Assert-Condition ($rerunIdentity.apiServerAuthorizedIpRanges[0] -eq '1.1.1.1/32') 'Owned rerun did not reuse recorded ranges.'
    Assert-Condition ($configuredOutput -match 'Found 1 stale managed-sensor cluster resource') 'The policytemplates-only leftover was not inventoried.'
    $crdDeletes = @($global:AksMockMutationCalls | Where-Object { $_ -like 'kubectl delete *' })
    Assert-Condition ($crdDeletes.Count -eq 1 -and $crdDeletes[0] -match 'crd policytemplates\.defender\.microsoft\.com --ignore-not-found') 'Cleanup did not target exactly the known policytemplates CRD.'
    Assert-Condition (-not $global:AksMockPolicyTemplateExists) 'The stale policytemplates CRD was not removed before Helm.'
    $beforePreviewMutationCount = $global:AksMockMutationCalls.Count
    $cleanupPreview = & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -Destroy -WhatIf 6>&1 | Out-String
    Assert-Condition ($global:AksMockMutationCalls.Count -eq $beforePreviewMutationCount) 'Destroy WhatIf performed a mutation.'
    Assert-Condition ($cleanupPreview -match 'Cleanup preview complete') 'Destroy WhatIf lacked preview-only output.'

    Reset-MockState
    $env:CONFIRM_SUBSCRIPTION_SCOPE = 'ENABLE-DEFENDER-FOR-CONTAINERS'
    & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -SkipSentinel *> $null
    $global:AksMockGroupDeleteShouldFail = $true
    $cleanupFailure = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -Destroy *> $null } catch { $cleanupFailure = $_ }
    Assert-Condition ($null -ne $cleanupFailure) 'Failed group deletion was not surfaced.'
    Assert-Condition $global:AksMockResourceGroupExists 'Failed deletion unexpectedly removed the group.'
    Assert-Condition ($global:AksMockPricingProperties.pricingTier -eq 'Standard') 'Failed deletion downgraded the still-running cluster shared protection.'
    Assert-Condition (Test-Path -LiteralPath $StatePath) 'Failed deletion discarded retry provenance.'
    $global:AksMockGroupDeleteShouldFail = $false
    $global:AksMockPricingPutShouldFail = $true
    $cleanupFailure = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -Destroy *> $null } catch { $cleanupFailure = $_ }
    Assert-Condition ($null -ne $cleanupFailure -and -not $global:AksMockResourceGroupExists) 'Pricing restore failure did not occur after deletion.'
    Assert-Condition (Test-Path -LiteralPath $StatePath) 'Pricing restore failure discarded retry provenance.'
    $global:AksMockGroupExistsShouldFail = $true
    $beforeFailedLookup = $global:AksMockMutationCalls.Count
    $lookupFailure = $null
    try { & $DeployScript -Destroy *> $null } catch { $lookupFailure = $_ }
    Assert-Condition ($null -ne $lookupFailure -and $global:AksMockMutationCalls.Count -eq $beforeFailedLookup) 'Lookup failure was treated as absence and allowed pricing mutation.'
    $global:AksMockGroupExistsShouldFail = $false
    $global:AksMockPricingPutShouldFail = $false
    & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -Destroy *> $null
    Assert-Condition ($global:AksMockPricingProperties.pricingTier -eq 'Free' -and -not (Test-Path -LiteralPath $StatePath)) 'Retry failed to restore shared pricing and finish cleanup.'

    Reset-MockState -PricingConfigured $true
    $global:AksMockResourceGroupExists = $true
    $global:AksMockOwnerToken = 'foreign-owner'
    $global:AksMockPolicyTemplateExists = $true
    $foreignGroupError = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -SkipSentinel *> $null } catch { $foreignGroupError = $_ }
    Assert-Condition ($foreignGroupError.Exception.Message -match 'without this lab.s ownership manifest') 'Foreign resource group was not refused.'
    Assert-Condition ($global:AksMockMutationCalls.Count -eq 0) 'Foreign ownership allowed cloud or CRD mutation.'
    Assert-Condition $global:AksMockPolicyTemplateExists 'Foreign cluster CRD was removed.'

    Reset-MockState
    $env:CONFIRM_SUBSCRIPTION_SCOPE = 'ENABLE-DEFENDER-FOR-CONTAINERS'
    $global:AksMockHelmShouldFail = $true
    $helmError = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -SkipSentinel *> $null } catch { $helmError = $_ }
    Assert-Condition ($helmError.Exception.Message -match 'prior Defender profile') 'Forced Helm failure did not surface rollback.'
    Assert-Condition ([string]$global:AksMockPricingProperties.pricingTier -eq 'Free') 'Deployment failure did not restore prior shared pricing.'
    Assert-Condition (-not (Test-Path -LiteralPath $global:AksMockValuesFilePath)) 'Secret values file survived failure.'

    Reset-MockState -PricingConfigured $true
    $global:AksMockPodsReady = $false
    $readinessError = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') -SkipSentinel *> $null } catch { $readinessError = $_ }
    Assert-Condition ($readinessError.Exception.Message -match 'Running/Ready') 'Unready sensor pods did not fail deployment.'

    Reset-MockState -PricingConfigured $true
    $sentinelOutput = & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') 6>&1 | Out-String
    $sentinelMutations = @($global:AksMockMutationCalls | Where-Object { $_ -match 'alertRules/.+--body' })
    Assert-Condition ($sentinelMutations.Count -eq 3) "Expected three rule writes, found $($sentinelMutations.Count)."
    Assert-Condition ($sentinelOutput -match '3 disabled owned analytics rules') 'Default rule state was not reported as disabled.'
    Assert-Condition (($global:AksMockMutationCalls -join "`n") -match 'workbooks/.+--method PUT|--method PUT.+workbooks/') 'Owned workbook was not written.'

    $legacyState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    $global:AksMockLegacyGatedRuleId = '22222222-2222-2222-2222-222222222222'
    $global:AksMockLegacyGatedRuleExists = $true
    $legacyState.sentinelRules = @($legacyState.sentinelRules) + @(
        [pscustomobject]@{ slug = 'gated-deployment-block'; id = $global:AksMockLegacyGatedRuleId }
    )
    $legacyState | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $StatePath -Encoding utf8NoBOM
    $beforeMigrationCallCount = $global:AksMockMutationCalls.Count
    $migrationOutput = & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') 6>&1 | Out-String
    $migrationCalls = @($global:AksMockMutationCalls | Select-Object -Skip $beforeMigrationCallCount)
    Assert-Condition (($migrationCalls -join "`n") -match "--method DELETE.+alertRules/$global:AksMockLegacyGatedRuleId") 'Manifest-owned legacy gated rule was not deleted.'
    Assert-Condition ($migrationOutput -match 'Deprecated gated-deployment Sentinel rule: Removed') 'Legacy-rule migration was not reported.'
    $migratedState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    Assert-Condition (@($migratedState.sentinelRules | Where-Object slug -eq 'gated-deployment-block').Count -eq 0) 'Legacy rule remained in the ownership manifest.'

    Reset-MockState -PricingConfigured $true
    $global:AksMockRulePutShouldFail = $true
    $ruleError = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') *> $null } catch { $ruleError = $_ }
    Assert-Condition ($ruleError.Exception.Message -match 'Sentinel rule deployment') 'Rule PUT failure was not fatal.'

    Reset-MockState -PricingConfigured $true
    $global:AksMockForeignWorkbook = $true
    $collisionError = $null
    try { & $DeployScript -ApiServerAuthorizedIpRanges @('1.1.1.1/32') *> $null } catch { $collisionError = $_ }
    Assert-Condition ($collisionError.Exception.Message -match 'Refusing to overwrite workbook|another resource already uses') 'Foreign workbook collision was not rejected.'
    $postCollisionSentinelWrites = @($global:AksMockMutationCalls | Where-Object { $_ -match 'dataConnectors|alertRules|workbooks' -and $_ -match '--method PUT' })
    Assert-Condition ($postCollisionSentinelWrites.Count -eq 0) 'Workbook collision allowed a partial Sentinel write.'

    Write-Host 'PASS: ownership, pricing rollback, readiness, and Sentinel fail-closed tests passed.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    if ($null -eq $OriginalSubscriptionConfirmation) { Remove-Item Env:\CONFIRM_SUBSCRIPTION_SCOPE -ErrorAction SilentlyContinue }
    else { $env:CONFIRM_SUBSCRIPTION_SCOPE = $OriginalSubscriptionConfirmation }
    foreach ($name in @('az', 'kubectl', 'helm', 'Start-Sleep')) { Remove-Item "Function:\global:$name" -ErrorAction SilentlyContinue }
    foreach ($name in @(Get-Variable -Scope Global -Name 'AksMock*' -ErrorAction SilentlyContinue).Name) {
        Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue
    }
}
