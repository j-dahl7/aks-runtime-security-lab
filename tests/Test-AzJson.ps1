#Requires -Version 7.6
# Exercise native stderr/argument handling with PowerShell itself, never Azure.
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '../scripts/Deploy-Lab.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-AzJson' }, $false)
. ([scriptblock]::Create($function.Extent.Text))
$nativePowerShell = (Microsoft.PowerShell.Core\Get-Command pwsh -CommandType Application | Select-Object -First 1).Source
function Get-Command {
    param($Name, $ErrorAction)
    if ($Name -ne 'az') { throw 'Only the synthetic az command may be resolved in this test.' }
    return [pscustomobject]@{ CommandType = 'Application'; Source = $nativePowerShell }
}

$json = Invoke-AzJson -Arguments @('-NoProfile', '-Command', '[Console]::Error.WriteLine("nonfatal warning"); ''{"valid":true}''')
if ($json.valid -ne $true) { throw 'Native warning contaminated JSON stdout.' }
$argument = 'https://example.invalid/path?a=1&b=quoted-value'
$json = Invoke-AzJson -Arguments @('-NoProfile', '-CommandWithArgs', '$args[0] | ConvertTo-Json -Compress', $argument)
if ($json -cne $argument) { throw 'Native argument boundaries changed.' }
$missing = Invoke-AzJson -Arguments @('-NoProfile', '-Command', '[Console]::Error.WriteLine("ERROR: (ResourceNotFound) absent"); exit 3') -NotFoundIsNull
if ($null -ne $missing) { throw 'Exact provider not-found code did not normalize to null.' }
$caught = $null
try {
    Invoke-AzJson -Arguments @('-NoProfile', '-Command', '[Console]::Error.WriteLine("ERROR: (AuthorizationFailed) tracking-aa404c-secret"); exit 1') -NotFoundIsNull
}
catch { $caught = $_.Exception.Message }
if ($caught -notmatch 'AuthorizationFailed' -or $caught -match 'tracking|secret') { throw 'Failure classification lost the code or disclosed the response body.' }
Write-Host 'PASS: native JSON stdout, stderr separation, argument boundaries, and exact error classification.'
