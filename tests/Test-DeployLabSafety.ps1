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
$global:AksMockSubscriptionId = '00000000-0000-0000-0000-000000000000'
$global:AksMockResourceGroupId = "/subscriptions/$global:AksMockSubscriptionId/resourceGroups/aks-runtime-lab-rg"
$global:AksMockWorkspaceResourceId = "$global:AksMockResourceGroupId/providers/Microsoft.OperationalInsights/workspaces/aks-runtime-lab-law"
$global:AksMockWorkspaceCustomerId = '11111111-1111-1111-1111-111111111111'
$global:AksMockWorkspaceKey = 'TEST-ONLY-NOT-A-REAL-WORKSPACE-KEY'
$OriginalSubscriptionConfirmation = $env:CONFIRM_SUBSCRIPTION_SCOPE

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
        return (@{ id = $global:AksMockSubscriptionId; name = 'Mock Subscription' } | ConvertTo-Json -Compress)
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
    Add-MockCall -Command ('kubectl ' + ($arguments -join ' ')) -Mutation:($arguments[0] -eq 'delete')
    $global:LASTEXITCODE = 0
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
    $null = $workbookSource | ConvertFrom-Json

    Reset-MockState
    $preview = & $DeployScript -WhatIf -SkipSentinel 6>&1 | Out-String
    Assert-Condition ($global:AksMockMutationCalls.Count -eq 0) "WhatIf mutated state: $($global:AksMockMutationCalls -join '; ')"
    Assert-Condition ($preview -match 'Deployment Preview Only' -and $preview -notmatch 'Deployment Complete') 'Preview output was misleading.'
    Assert-Condition (-not (Test-Path -LiteralPath $StatePath)) 'WhatIf wrote a manifest.'

    $destroyRejected = $false
    try { & $DeployScript -Destroy -WhatIf *> $null } catch { $destroyRejected = $_.Exception.Message -match 'requires the exact ownership manifest' }
    Assert-Condition $destroyRejected 'Destroy preview without a manifest was not rejected.'

    Reset-MockState
    Remove-Item Env:\CONFIRM_SUBSCRIPTION_SCOPE -ErrorAction SilentlyContinue
    $billingError = $null
    try { & $DeployScript -SkipSentinel *> $null } catch { $billingError = $_ }
    Assert-Condition ($billingError.Exception.Message -match 'CONFIRM_SUBSCRIPTION_SCOPE=ENABLE-DEFENDER-FOR-CONTAINERS') 'Paid-plan gate did not fail closed.'
    Assert-Condition ($global:AksMockMutationCalls.Count -eq 0) 'Paid-plan gate allowed a mutation.'
    Assert-Condition (-not (Test-Path -LiteralPath $StatePath)) 'Paid-plan gate wrote a manifest.'

    Reset-MockState -PricingConfigured $true
    $configuredOutput = & $DeployScript -SkipSentinel 6>&1 | Out-String
    Assert-Condition ($configuredOutput -match 'Deployment Complete') 'Configured deployment did not complete.'
    Assert-Condition (($global:AksMockMutationCalls -join "`n") -notmatch 'pricings/Containers') 'Configured pricing was rewritten.'
    Assert-Condition (Test-Path -LiteralPath $StatePath) 'Deployment did not retain its ownership manifest.'
    $beforePreviewMutationCount = $global:AksMockMutationCalls.Count
    $cleanupPreview = & $DeployScript -Destroy -WhatIf 6>&1 | Out-String
    Assert-Condition ($global:AksMockMutationCalls.Count -eq $beforePreviewMutationCount) 'Destroy WhatIf performed a mutation.'
    Assert-Condition ($cleanupPreview -match 'Cleanup preview complete') 'Destroy WhatIf lacked preview-only output.'

    Reset-MockState
    $env:CONFIRM_SUBSCRIPTION_SCOPE = 'ENABLE-DEFENDER-FOR-CONTAINERS'
    $global:AksMockHelmShouldFail = $true
    $helmError = $null
    try { & $DeployScript -SkipSentinel *> $null } catch { $helmError = $_ }
    Assert-Condition ($helmError.Exception.Message -match 'prior Defender profile') 'Forced Helm failure did not surface rollback.'
    Assert-Condition ([string]$global:AksMockPricingProperties.pricingTier -eq 'Free') 'Deployment failure did not restore prior shared pricing.'
    Assert-Condition (-not (Test-Path -LiteralPath $global:AksMockValuesFilePath)) 'Secret values file survived failure.'

    Reset-MockState -PricingConfigured $true
    $global:AksMockPodsReady = $false
    $readinessError = $null
    try { & $DeployScript -SkipSentinel *> $null } catch { $readinessError = $_ }
    Assert-Condition ($readinessError.Exception.Message -match 'Running/Ready') 'Unready sensor pods did not fail deployment.'

    Reset-MockState -PricingConfigured $true
    $sentinelOutput = & $DeployScript 6>&1 | Out-String
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
    $migrationOutput = & $DeployScript 6>&1 | Out-String
    $migrationCalls = @($global:AksMockMutationCalls | Select-Object -Skip $beforeMigrationCallCount)
    Assert-Condition (($migrationCalls -join "`n") -match "--method DELETE.+alertRules/$global:AksMockLegacyGatedRuleId") 'Manifest-owned legacy gated rule was not deleted.'
    Assert-Condition ($migrationOutput -match 'Deprecated gated-deployment Sentinel rule: Removed') 'Legacy-rule migration was not reported.'
    $migratedState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    Assert-Condition (@($migratedState.sentinelRules | Where-Object slug -eq 'gated-deployment-block').Count -eq 0) 'Legacy rule remained in the ownership manifest.'

    Reset-MockState -PricingConfigured $true
    $global:AksMockRulePutShouldFail = $true
    $ruleError = $null
    try { & $DeployScript *> $null } catch { $ruleError = $_ }
    Assert-Condition ($ruleError.Exception.Message -match 'Sentinel rule deployment') 'Rule PUT failure was not fatal.'

    Reset-MockState -PricingConfigured $true
    $global:AksMockForeignWorkbook = $true
    $collisionError = $null
    try { & $DeployScript *> $null } catch { $collisionError = $_ }
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
