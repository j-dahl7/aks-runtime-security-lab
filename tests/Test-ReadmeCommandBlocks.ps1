#Requires -Version 7.6
# Read README.md the way a reader copies it: one fenced block at a time. GitHub
# puts a copy button on every code block, and a multi-line block pasted into
# PowerShell runs every line without a stop: PSReadLine's Paste (Ctrl+V) parses
# the whole block on one Enter, and a console right-click paste runs each line
# as its newline arrives (about_PSReadLine_Functions). So a block that holds a
# -WhatIf preview and a real run, two state-changing lab-script runs (such as
# the deployment and its later -EnableSentinelRules step), or the paid-plan
# confirmation and a run starts the later step before the reader has read the
# earlier output. Offline: the lab scripts are parsed, never run.

[CmdletBinding()]
param(
    # Check another copy of the README, such as an earlier revision.
    [string]$ReadmePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'README.md')
)

$ErrorActionPreference = 'Stop'
$ScriptsRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts'
# Get-Command reads each param block (names and aliases such as -wi for
# -WhatIf) without running the script.
$LabScriptParameters = @{}
foreach ($name in @('Deploy-Lab.ps1', 'Test-RuntimeSecurity.ps1')) {
    $LabScriptParameters[$name] = (Get-Command -Name (Join-Path $ScriptsRoot $name)).Parameters
}
$LabScriptPattern = '(?:^|[\\/])(Deploy-Lab\.ps1|Test-RuntimeSecurity\.ps1)$'
$PowerShellHosts = '^(?:pwsh|powershell)(?:\.exe)?$'

function Get-FencedBlock {
    # Fences of three or more backticks or tildes, at any indentation so a block
    # inside a list item counts. The same character, at least as many times,
    # closes the block; an unclosed block runs to the end of the file.
    param([string]$Markdown)
    $open = $null
    $lines = $Markdown -split '\r?\n'
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if (-not $open) {
            $fence = [regex]::Match($lines[$index], '^(\s*)(`{3,}|~{3,})(.*)$')
            if ($fence.Success -and -not ($fence.Groups[2].Value.StartsWith('`') -and $fence.Groups[3].Value.Contains('`'))) {
                $open = [pscustomobject]@{
                    Line = $index + 1
                    Language = ([string]($fence.Groups[3].Value.Trim() -split '\s+')[0]).ToLowerInvariant()
                    Indent = $fence.Groups[1].Value.Length
                    Fence = $fence.Groups[2].Value
                    Body = [System.Collections.Generic.List[string]]::new()
                }
            }
        }
        elseif ($lines[$index] -match "^\s*$([regex]::Escape($open.Fence[0])){$($open.Fence.Length),}\s*$") {
            $open
            $open = $null
        }
        else {
            $open.Body.Add(($lines[$index] -replace "^\s{0,$($open.Indent)}", ''))
        }
    }
    if ($open) { $open }
}

function Resolve-LabParameter {
    # PowerShell binds an exact name or alias first, then an unambiguous prefix.
    param($Parameters, [string]$Name)
    $found = @($Parameters.Values | Where-Object { $_.Name -eq $Name -or $_.Aliases -contains $Name })
    if (-not $found.Count) { $found = @($Parameters.Values | Where-Object { $_.Name -like "$Name*" }) }
    if ($found.Count -eq 1) { $found[0].Name }
}

function Get-CommandBlockReport {
    param([string]$Markdown)
    $issues = [System.Collections.Generic.List[string]]::new()
    $previewCount = 0
    $runCount = 0
    foreach ($block in @(Get-FencedBlock $Markdown)) {
        $text = $block.Body -join "`n"
        $at = "The block at line $($block.Line)"
        if ($block.Language -notin @('powershell', 'pwsh', 'ps1', 'ps', 'posh')) {
            # The lab scripts are PowerShell; a run in a block tagged otherwise
            # would escape the parser below.
            $commands = ($text -replace '[\\`]\n', ' ') -replace '(?m)(?:^|\s)#.*$', ''
            if ($commands -match '(?m)^\s*(?:(?:pwsh|powershell)(?:\.exe)?\s+(?:-\S+\s+)*)?(?:[&.]\s+)?[''"]?(?:[^\s''"|]*[\\/])?(?:Deploy-Lab|Test-RuntimeSecurity)\.ps1\b') {
                $issues.Add("$at runs a lab script but is not tagged powershell, so this check cannot parse it.")
            }
            continue
        }

        # The PowerShell parser joins continued lines and drops comments.
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        if ($errors.Count) {
            $issues.Add("$at does not parse as PowerShell, so this check cannot classify it: $($errors[0].Message)")
            continue
        }
        $runs = @(foreach ($command in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $elements = @($command.CommandElements)
            $scriptAt = -1
            for ($i = 0; $i -lt $elements.Count -and $scriptAt -lt 0; $i++) {
                if ($elements[$i] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $elements[$i].Value -match $LabScriptPattern) { $scriptAt = $i }
            }
            # A lab script runs when it is the command, or the file pwsh is given.
            if ($scriptAt -lt 0 -or ($scriptAt -gt 0 -and $command.GetCommandName() -notmatch $PowerShellHosts)) { continue }
            $labScript = [regex]::Match($elements[$scriptAt].Value, $LabScriptPattern, 'IgnoreCase').Groups[1].Value
            $named = @(foreach ($parameter in @($elements | Select-Object -Skip ($scriptAt + 1))) {
                if ($parameter -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
                $name = Resolve-LabParameter $LabScriptParameters[$labScript] $parameter.ParameterName
                if (-not $name) {
                    $issues.Add("$at passes -$($parameter.ParameterName) to $labScript, which has no single parameter of that name.")
                    continue
                }
                # -Switch:$false leaves the switch off.
                if ($null -eq $parameter.Argument -or $parameter.Argument.Extent.Text -ne '$false') { $name }
            })
            [pscustomobject]@{
                Line = $block.Line + $command.Extent.StartLineNumber
                Script = $labScript
                Preview = $named -contains 'WhatIf'
                Enables = @($named -like 'Enable*')
            }
        })

        $previews = @($runs | Where-Object Preview)
        $real = @($runs | Where-Object { -not $_.Preview })
        $previewCount += $previews.Count
        $runCount += $real.Count
        if ($previews.Count -and $real.Count) {
            $issues.Add("$at holds a -WhatIf preview (line $($previews.Line -join ', line ')) and a real run (line $($real.Line -join ', line ')); give the preview its own block.")
        }
        if ($real.Count -gt 1) {
            $deploys = @($real | Where-Object Script -eq 'Deploy-Lab.ps1')
            $enabled = @($deploys | Where-Object { $_.Enables.Count })
            $detail = if ($enabled.Count -and $enabled.Count -lt $deploys.Count) {
                ", Deploy-Lab.ps1 both without and with -$(@($enabled.Enables | Sort-Object -Unique) -join '/-')"
            }
            $issues.Add("$at holds $($real.Count) state-changing runs (line $($real.Line -join ', line '))$detail; give each its own block.")
        }
        $confirmation = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -eq 'env:CONFIRM_SUBSCRIPTION_SCOPE'
        }, $true)
        if ($confirmation -and $real.Count) {
            $issues.Add("$at sets CONFIRM_SUBSCRIPTION_SCOPE and also runs (line $($real.Line -join ', line ')); set the paid-plan confirmation in its own block.")
        }
    }
    [pscustomobject]@{ Issues = @($issues); Previews = $previewCount; Runs = $runCount }
}

# Prove the parser on known blocks first, so a parsing fault cannot let the
# README pass by finding nothing.
$fixtures = @(
    @{ Expect = 'holds a -WhatIf preview \(line 2\) and a real run \(line 3\)'; Markdown = @'
```powershell
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" -Destroy -WhatIf
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" -Destroy
```
'@ }
    @{ Expect = 'holds 2 state-changing runs \(line 2, line 3\), Deploy-Lab\.ps1 both without and with -EnableSentinelRules;'; Markdown = @'
```powershell
./scripts/Deploy-Lab.ps1 -Location "eastus" -ApiServerAuthorizedIpRanges $operatorEgress
./scripts/Deploy-Lab.ps1 -Location "eastus" -EnableSentinelRules
```
'@ }
    @{ Expect = 'holds 2 state-changing runs \(line 2, line 3\); give each'; Markdown = @'
```powershell
pwsh -NoProfile -File ./scripts/Deploy-Lab.ps1 -Location "eastus" -EnableSentinelRules
./scripts/Test-RuntimeSecurity.ps1 -ProjectName "aks-runtime-lab"
```
'@ }
    @{ Expect = 'sets CONFIRM_SUBSCRIPTION_SCOPE and also runs \(line 3\)'; Markdown = @'
```powershell
$env:CONFIRM_SUBSCRIPTION_SCOPE = 'ENABLE-DEFENDER-FOR-CONTAINERS'
./scripts/Deploy-Lab.ps1 -Location "eastus" -ApiServerAuthorizedIpRanges $operatorEgress
```
'@ }
    # A continued line, the -wi alias, and the call operator still read as one
    # preview and one real run.
    @{ Expect = 'holds a -WhatIf preview \(line 3\) and a real run \(line 5\)'; Markdown = @'
Text before the block.
```pwsh
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" `
    -Destroy -wi
& ./scripts/Deploy-Lab.ps1 -Destroy -WhatIf:$false
```
'@ }
    @{ Expect = 'passes -EnableRules to Deploy-Lab\.ps1, which has no single parameter'; Markdown = @'
```powershell
./scripts/Deploy-Lab.ps1 -Location "eastus" -EnableRules
```
'@ }
    @{ Expect = 'does not parse as PowerShell'; Markdown = @'
```powershell
./scripts/Deploy-Lab.ps1 -ProjectName 'unterminated
```
'@ }
    @{ Expect = 'runs a lab script but is not tagged powershell'; Markdown = @'
```bash
pwsh -NoProfile -File ./scripts/Deploy-Lab.ps1 -Destroy
```
'@ }
    # Comments, a repository tree, a block inside a list item, and previews kept
    # apart from the real runs are clean.
    @{ Expect = $null; Previews = 2; Runs = 2; Markdown = @'
```powershell
# Not a run: ./scripts/Deploy-Lab.ps1 -Destroy
$operatorEgress = @('<your-public-egress-ip>/32') # Replace; -EnableSentinelRules runs later
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" `
    -ApiServerAuthorizedIpRanges $operatorEgress -WhatIf
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" -Destroy -WhatIf
```

Read the preview output, then deploy:

```powershell
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" -ApiServerAuthorizedIpRanges $operatorEgress
```

1. Run the tests:

   ```powershell
   ./scripts/Test-RuntimeSecurity.ps1 -ProjectName "aks-runtime-lab"
   ```

```
|   |-- Deploy-Lab.ps1                   # One-command deployment
```
'@ }
)

foreach ($fixture in $fixtures) {
    $report = Get-CommandBlockReport -Markdown $fixture.Markdown
    if ($null -eq $fixture.Expect) {
        if ($report.Issues.Count -or $report.Previews -ne $fixture.Previews -or $report.Runs -ne $fixture.Runs) {
            throw "Clean fixture misread: previews=$($report.Previews) runs=$($report.Runs) issues=$($report.Issues -join ' | ')"
        }
    }
    elseif ($report.Issues.Count -ne 1 -or $report.Issues[0] -notmatch $fixture.Expect) {
        throw "Fixture expecting '$($fixture.Expect)' produced: $($report.Issues -join ' | ')"
    }
}

$readme = Get-CommandBlockReport -Markdown (Get-Content -LiteralPath $ReadmePath -Raw)
if (-not $readme.Previews -or -not $readme.Runs) {
    throw "Found no Deploy-Lab.ps1 -WhatIf preview or real run in ${ReadmePath}; the block parser or the README layout changed."
}
if ($readme.Issues.Count) {
    throw "$ReadmePath has command blocks that one paste would run past a step the reader must check first:`n  $($readme.Issues -join "`n  ")"
}
Write-Host "PASS: $($fixtures.Count) parser fixtures; no README.md block mixes its $($readme.Previews) -WhatIf previews with a real run, holds more than one of its $($readme.Runs) state-changing lab-script runs, or sets the paid-plan confirmation beside a run."
