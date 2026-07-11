#Requires -Version 7.0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$DeployScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/Deploy-Lab.ps1'
$MockSubscriptionId = '00000000-0000-0000-0000-000000000000'
$MockWorkspaceResourceId = "/subscriptions/$MockSubscriptionId/resourceGroups/aks-runtime-lab-rg/providers/Microsoft.OperationalInsights/workspaces/aks-runtime-lab-law"
$MockWorkspaceCustomerId = '11111111-1111-1111-1111-111111111111'
$MockWorkspaceKey = 'TEST-ONLY-NOT-A-REAL-WORKSPACE-KEY'

function Assert-Condition {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Reset-MockState {
    $global:MockExternalCalls = [System.Collections.Generic.List[string]]::new()
    $global:MockMutationCalls = [System.Collections.Generic.List[string]]::new()
    $global:MockHelmShouldFail = $false
    $global:MockValuesFilePath = $null
    $global:MockValuesDirectory = $null
}

function Add-MockCall {
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [Parameter()]
        [switch]$Mutation
    )

    $global:MockExternalCalls.Add($Command)
    if ($Mutation) {
        $global:MockMutationCalls.Add($Command)
    }
}

function global:az {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $command = 'az ' + ($arguments -join ' ')
    $isMutation =
        ($arguments[0] -eq 'deployment' -and $arguments[2] -eq 'create') -or
        ($arguments[0] -eq 'security' -and $arguments[2] -eq 'create') -or
        ($arguments[0] -eq 'rest' -and $arguments -contains 'PUT') -or
        ($arguments[0] -eq 'aks' -and $arguments[1] -in @('get-credentials', 'update')) -or
        ($arguments[0] -eq 'tag' -and $arguments[1] -eq 'update') -or
        ($arguments[0] -eq 'group' -and $arguments[1] -eq 'delete')
    Add-MockCall -Command $command -Mutation:$isMutation
    $global:LASTEXITCODE = 0

    if ($arguments[0] -eq 'account' -and $arguments[1] -eq 'show') {
        return (@{
            id   = $MockSubscriptionId
            name = 'Mock Subscription'
        } | ConvertTo-Json -Compress)
    }

    if ($arguments[0] -eq 'deployment' -and $arguments[1] -eq 'sub') {
        return (@{
            clusterName = @{ value = 'aks-runtime-lab' }
            workspaceId = @{ value = $MockWorkspaceResourceId }
        } | ConvertTo-Json -Compress)
    }

    if ($arguments[0] -eq 'aks' -and $arguments[1] -eq 'show') {
        return (@{
            id       = "/subscriptions/$MockSubscriptionId/resourceGroups/aks-runtime-lab-rg/providers/Microsoft.ContainerService/managedClusters/aks-runtime-lab"
            location = 'eastus'
            tags     = @{}
            securityProfile = @{
                defender = @{
                    logAnalyticsWorkspaceResourceId = $MockWorkspaceResourceId
                    securityMonitoring = @{ enabled = $true }
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress)
    }

    if ($arguments[0] -eq 'policy' -and $arguments[1] -eq 'assignment') {
        return '[]'
    }

    if ($arguments[0] -eq 'monitor' -and $arguments[1] -eq 'log-analytics') {
        if ($arguments -contains 'get-shared-keys') {
            return $MockWorkspaceKey
        }
        return $MockWorkspaceCustomerId
    }

    if ($arguments[0] -eq 'resource' -and $arguments[1] -eq 'list') {
        return '[]'
    }
}

function global:kubectl {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $command = 'kubectl ' + ($arguments -join ' ')
    $isMutation = $arguments[0] -eq 'delete'
    Add-MockCall -Command $command -Mutation:$isMutation
    $global:LASTEXITCODE = 0

    if ($arguments[0] -eq 'get' -and $arguments[1] -eq 'pods') {
        return 'pod/microsoft-defender-publisher-test'
    }
}

function global:helm {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $command = 'helm ' + ($arguments -join ' ')
    $isMutation = $arguments[0] -eq 'upgrade'
    Add-MockCall -Command $command -Mutation:$isMutation
    $global:LASTEXITCODE = 0

    if ($arguments[0] -eq 'list') {
        return '[]'
    }

    if ($arguments[0] -eq 'upgrade') {
        $valuesIndex = [Array]::IndexOf($arguments, '--values')
        if ($valuesIndex -lt 0 -or $valuesIndex + 1 -ge $arguments.Count) {
            throw 'Helm was not given a values file.'
        }

        $valuesPath = $arguments[$valuesIndex + 1]
        $global:MockValuesFilePath = $valuesPath
        $global:MockValuesDirectory = Split-Path -Parent $valuesPath
        if (-not (Test-Path -LiteralPath $valuesPath)) {
            throw 'The Helm values file did not exist when Helm was invoked.'
        }
        if (($arguments -join ' ') -like "*$MockWorkspaceKey*") {
            throw 'The Log Analytics key leaked into Helm process arguments.'
        }
        if ($arguments -notcontains '--atomic') {
            throw 'Helm was not invoked with --atomic.'
        }

        $values = Get-Content -LiteralPath $valuesPath -Raw | ConvertFrom-Json
        $sensorValues = $values.'microsoft-defender-for-containers-sensor'
        if (-not $sensorValues.omsagent.secret.wsid -or -not $sensorValues.omsagent.secret.key) {
            throw 'The Helm values file contained an empty Log Analytics workspace ID or key.'
        }

        if ($IsWindows) {
            $fileInfo = [System.IO.FileInfo]::new($valuesPath)
            $acl = [System.IO.FileSystemAclExtensions]::GetAccessControl($fileInfo)
            if (-not $acl.AreAccessRulesProtected) {
                throw 'The Helm values file ACL still inherited permissions.'
            }
            $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $unexpectedAllowRules = @($acl.Access | Where-Object {
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $_.IdentityReference.Value -ne $currentSid
            })
            if ($unexpectedAllowRules.Count -gt 0) {
                throw 'The Helm values file granted access to an identity other than its owner.'
            }
        }
        else {
            $mode = [System.IO.File]::GetUnixFileMode($valuesPath)
            $expectedMode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
            if ($mode -ne $expectedMode) {
                throw "The Helm values file mode was $mode instead of owner read/write only."
            }
        }

        if ($global:MockHelmShouldFail) {
            $global:LASTEXITCODE = 42
        }
    }
}

try {
    # Scenario 1: -WhatIf may read account context, but it must not perform any
    # Azure, kubeconfig, Kubernetes, Helm, or temporary-secret mutation.
    Reset-MockState
    $previewOutput = & $DeployScript -WhatIf -SkipSentinel 6>&1 | Out-String
    Assert-Condition ($global:MockMutationCalls.Count -eq 0) "-WhatIf performed mutations: $($global:MockMutationCalls -join '; ')"
    Assert-Condition ($previewOutput -match 'Deployment Preview Only') '-WhatIf did not emit the preview-only summary.'
    Assert-Condition ($previewOutput -notmatch 'Deployment Complete') '-WhatIf falsely emitted the deployment-complete summary.'

    Reset-MockState
    $null = & $DeployScript -Destroy -WhatIf 6>&1 | Out-String
    Assert-Condition ($global:MockMutationCalls.Count -eq 0) "-Destroy -WhatIf performed mutations: $($global:MockMutationCalls -join '; ')"

    # Scenario 2: force Helm to fail after Defender was disabled and the
    # exclusion tag was added. The script must restore both prior states and
    # remove its owner-only secret values file in a finally block.
    Reset-MockState
    $global:MockHelmShouldFail = $true
    $caught = $null
    try {
        & $DeployScript -SkipSentinel *> $null
    }
    catch {
        $caught = $_
    }

    Assert-Condition ($null -ne $caught) 'The forced Helm failure did not fail the deployment.'
    Assert-Condition ($caught.Exception.Message -match 'prior Defender profile and exclusion-tag state were restored') 'The deployment did not report successful protection rollback.'

    $mutations = $global:MockMutationCalls -join "`n"
    Assert-Condition ($mutations -match 'az aks update .*--disable-defender') 'The test never reached managed Defender disablement.'
    Assert-Condition ($mutations -match 'helm upgrade .*--atomic') 'The Helm mutation did not use --atomic.'
    Assert-Condition ($mutations -match 'az aks update .*--enable-defender') 'Rollback did not re-enable the prior Defender profile.'
    Assert-Condition ($mutations -match [regex]::Escape("--defender-config logAnalyticsWorkspaceResourceId=$MockWorkspaceResourceId")) 'Rollback did not restore the prior Defender workspace.'
    Assert-Condition ($mutations -match 'az tag update .*--operation delete .*--tags ms_defender_e2e_discovery_exclude') 'Rollback did not remove the newly introduced exclusion tag.'
    Assert-Condition (-not (Test-Path -LiteralPath $global:MockValuesFilePath)) 'The temporary Helm values file survived the failed deployment.'
    Assert-Condition (-not (Test-Path -LiteralPath $global:MockValuesDirectory)) 'The temporary Helm values directory survived the failed deployment.'

    # Scenario 3: the same secret file must also be removed after success.
    Reset-MockState
    $successOutput = & $DeployScript -SkipSentinel 6>&1 | Out-String
    Assert-Condition ($successOutput -match 'Deployment Complete') 'The successful mocked deployment did not complete.'
    Assert-Condition (-not (Test-Path -LiteralPath $global:MockValuesFilePath)) 'The temporary Helm values file survived a successful deployment.'
    Assert-Condition (-not (Test-Path -LiteralPath $global:MockValuesDirectory)) 'The temporary Helm values directory survived a successful deployment.'

    Write-Host 'PASS: deploy/destroy -WhatIf performed zero mutations and emitted preview-only output.' -ForegroundColor Green
    Write-Host 'PASS: forced Helm failure restored Defender/tag state and removed the secure values file.' -ForegroundColor Green
    Write-Host 'PASS: successful Helm deployment also removed the secure values file.' -ForegroundColor Green
}
finally {
    Remove-Item Function:\global:az -ErrorAction SilentlyContinue
    Remove-Item Function:\global:kubectl -ErrorAction SilentlyContinue
    Remove-Item Function:\global:helm -ErrorAction SilentlyContinue
}
