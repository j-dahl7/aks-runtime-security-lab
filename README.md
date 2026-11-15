# AKS Runtime Security Lab

Prepare a dedicated AKS lab for three layers of Microsoft Defender for Cloud controls:

| Layer | Feature | Status | What It Does |
|---|---|---|---|
| **Deploy-time gate** | Gated Deployment | GA | Evaluates images at admission; configured rules can audit or deny matching images |
| **Runtime detection** | Binary Drift | GA | Detects or blocks executables that differ from the original container image |
| **Runtime protection** | Container Anti-Malware | GA | Real-time malware detection and blocking inside running containers |

Companion lab for the blog post: [AKS Runtime Security: Binary Drift, Anti-Malware & Gated Deployment with Defender for Cloud](https://nineliveszerotrust.com/blog/aks-runtime-security-defender/)

## Validation Boundary

Offline checks only, November 14, 2026: this revision changes the layout of
this README's command blocks and adds a check for it. Each `-WhatIf` preview,
real deployment, paid-plan confirmation, rule enablement, and cleanup step now
has its own block, so one paste cannot run a later step before the reader has
read the earlier output. No README command, script, template, query, or
workbook changed; `validate.yml` now also runs the README check. It was checked
with Bicep compilation (Bicep CLI 0.45.6), PowerShell parsing, the README check,
and the three mocked safety/rollback suites below; no tenant, cluster, or cloud
test was run.

Offline checks only, November 13, 2026: the revision before this one made the
Defender Helm chart version selectable, so a first deployment installs `0.11.9`
by default instead of the fixed `0.11.5`. It was checked with Bicep compilation
(Bicep CLI 0.45.6), PowerShell parsing, and the three mocked safety/rollback
suites below. Helm was not installed where those checks ran. Chart `0.11.9`
was not pulled, inspected, or deployed, and no tenant, cluster, or cloud test
was run.

The September 25, 2026 repair revision was checked the same way: Bicep
compilation, PowerShell parsing, and mocked safety/rollback tests. None of
these revisions was freshly deployed to Azure, and no live AKS, Defender, Helm,
Sentinel, or alert-ingestion validation was performed for any of them. Feature
availability, policy behavior, chart availability, and alert latency can vary
by subscription, region, and cluster version.

Run the offline deployment-safety harness from a fresh checkout:

```powershell
pwsh -NoProfile -File tests/Test-DeployLabSafety.ps1
pwsh -NoProfile -File tests/Test-RuntimeSafety.ps1
pwsh -NoProfile -File tests/Test-AzJson.ps1
```

It mocks Azure CLI, Kubernetes, and Helm to exercise ownership refusal, exact
stale-resource cleanup, `-WhatIf`, pricing/profile rollback, readiness,
Defender chart-version selection and refusal of unpublished tags, and
default-disabled/explicitly-enabled rules. Its mocked registry serves the GA
`0.11` chart tags listed below and never contacts MCR. It refuses to run over
an existing ownership manifest. Passing this harness is not a live cluster or
sensor test.

The README check reads this file one fenced block at a time, as a reader copies
it. It fails if a block holds a `-WhatIf` preview with a real run, more than one
state-changing run of `Deploy-Lab.ps1` or `Test-RuntimeSecurity.ps1`, or the
paid-plan confirmation with a run. It reads the scripts' parameters but never
runs them:

```powershell
pwsh -NoProfile -File tests/Test-ReadmeCommandBlocks.ps1
```

The separate `validate.yml` pull-request workflow compiles Bicep and runs these
mocks and the README check without cloud credentials, deployment steps, or
schedules.

## Prerequisites

- Azure subscription with **Owner** or **Contributor + User Access Administrator** role
- Tenant **Security Admin** or the higher role specified by Microsoft for
  creating drift, antimalware, and gated-deployment security policies; Azure
  resource deployment permissions alone do not grant this policy authority
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) v2.60+
- [kubectl](https://kubernetes.io/docs/tasks/tools/) compatible with the
  exact Kubernetes version selected for this deployment
- [Helm](https://helm.sh/docs/intro/install/) 4 recommended; supported Helm 3 releases remain compatible until their security-support end on February 10, 2027
- [PowerShell 7.6 LTS or later](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) (enforced before either entry point runs; required for the supported .NET APIs)

This lab can enable or change the paid Defender for Containers plan and its
extensions at subscription scope. If the required state is not already active,
the real deployment requires the exact environment confirmation
`CONFIRM_SUBSCRIPTION_SCOPE=ENABLE-DEFENDER-FOR-CONTAINERS`.

The script installs Defender's OCI Helm chart at the version selected by
`-DefenderHelmChartVersion`. When the parameter is omitted, a first deployment
installs `0.11.9`, and a rerun keeps the chart version of the existing
`defender-k8s` release, so a changed script default never moves an owned
sensor. An owned lab deployed by an earlier revision (which pinned `0.11.4`
from July 26, 2026 and `0.11.5` from September 25, 2026) therefore stays on
that chart, without the later security updates, until you choose otherwise.
Pass the parameter to choose another published version, on a first deployment
or on a rerun that should move the existing release:

```powershell
# First deployment on 0.11.5, the last chart whose archive this lab reviewed
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -ApiServerAuthorizedIpRanges '<your-public-egress-ip>/32' -DefenderHelmChartVersion 0.11.5
```

On an owned rerun, the same parameter moves the existing release:

```powershell
# Owned rerun that moves the existing release to 0.11.9
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -DefenderHelmChartVersion 0.11.9
```

Every run without `-SkipSentinel`, a rerun included, writes the lab's three
Sentinel rules again from the script, with their stored queries. If you enabled
the rules, add `-EnableSentinelRules` to the rerun, or they return to disabled.
Add `-SkipSentinel` instead to leave the rules and the workbook as they are.

The default is the newest `0.11` chart tag the registry listed on November 13,
2026. That is not a claim that it stays the newest release or is compatible
with every future AKS/Defender combination. It was chosen from Microsoft's
documentation and the registry's tag list, not from a deployment:

- Microsoft's [sensor changelog](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-sensor-change-log)
  (page updated October 26, 2026) lists `0.11.6`, `0.11.7`, and `0.11.8` as
  security and dependency updates, and `0.11.9`, released in October 2026, as
  removing trust in certificate authorities affected by the eMudhra compromise.
  It names no change to chart values or installation steps after `0.11.5`.
- The values this script sets, `global.cloudIdentifiers.Azure.*` and
  `microsoft-defender-for-containers-sensor.antimalwareCollector.enabled`, are
  the ones Microsoft's current [Helm](https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-helm)
  and [anti-malware](https://learn.microsoft.com/en-us/azure/defender-for-cloud/anti-malware)
  guidance documents.
- MCR's tag list, read on November 13, 2026, served these 0.11 chart tags:
  `0.11.3-preview`, `0.11.4`, `0.11.5`, `0.11.8`, and `0.11.9`. Sensor `0.11.6`
  and `0.11.7` are in the changelog but were not among the chart tags, so
  choose a version from the tag list, not from the changelog alone.

This lab's own tests did not deploy `0.11.9`, and its chart archive was not
pulled or inspected: this review could not connect to MCR directly and read
the tag list through a hosted fetch service. The last chart whose archive was
source-reviewed is `0.11.5`. The September 25, 2026 review checked that
retained archive against OCI layer digest
`sha256:30a95ffed15dcd07b5789bb53c8ab6ae4f93946e16beee075375ecf7c8f08c9a`;
its helpers explicitly make workspace ID/key optional. Pass
`-DefenderHelmChartVersion 0.11.5` on a first deployment to use that reviewed
chart instead, which lacks the later security updates.

Before a live run, list the published tags, confirm that the publisher still
serves the version you chose, and review its supported Kubernetes/Defender
matrix:

```powershell
curl https://mcr.microsoft.com/v2/azuredefender/microsoft-defender-for-containers/tags/list
helm show chart oci://mcr.microsoft.com/azuredefender/microsoft-defender-for-containers --version 0.11.9
```

A real deployment runs the same `helm show chart` lookup and stops if the
registry does not serve the version. The lookup happens before the first cloud
write when the version is already known (a first deployment, or an explicit
`-DefenderHelmChartVersion`), and otherwise before the sensor is changed.
`-WhatIf` does not contact the registry. If a version change fails, the
script's Helm rollback flag and protection-state restore apply; Microsoft's
Helm guidance covers upgrade failures caused by resource conflicts.

A Helm-managed sensor is not upgraded automatically; the operator owns chart
review and upgrades. Microsoft also notes that the portal can label a
Helm-installed subscription `not supported for Gated deployment`. If the gated
rule flow offers to auto-install components, choose **Skip** so it does not
conflict with the existing Helm deployment. This lab uses standard AKS and the
`mdc` namespace; AKS Automatic has separate `kube-system` requirements. Review
[Microsoft's current Helm guidance](https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-helm)
before a live run.

The node template currently selects Azure Linux 3. An AKS-supported node OS is
not automatically a Defender-sensor-verified host OS. Check Microsoft's current
sensor host-OS support list before deploying this combination; the offline
tests do not establish sensor compatibility on it. This update does not silently
replace the OS of an existing node pool.

## Quick Start

```bash
git clone https://github.com/j-dahl7/aks-runtime-security-lab.git
cd aks-runtime-security-lab
```

Preview the deployment:

```powershell
# Read-only preview. This reports intended operations and performs no Azure,
# Kubernetes, Helm, kubeconfig, or local secret-file mutations.
$operatorEgress = @('<your-public-egress-ip>/32') # Replace; do not use a sample IP.
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -ApiServerAuthorizedIpRanges $operatorEgress -WhatIf
```

Verify the active subscription and current shared plan before the real run:

```powershell
az account show --query '{subscription:name,id:id}' -o table
az security pricing show --name Containers -o json
```

Set the paid-plan confirmation only when it is required:

```powershell
# Required only when the script reports that the shared plan/extensions need
# to change:
$env:CONFIRM_SUBSCRIPTION_SCOPE = 'ENABLE-DEFENDER-FOR-CONTAINERS'
```

Read the preview output, then deploy:

```powershell
# Live deployment: AKS + Defender + Helm sensor + disabled Sentinel rules + workbook
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -ApiServerAuthorizedIpRanges $operatorEgress
```

The confirmation authorizes a live subscription-level change; it is not a
preview. A real deployment also updates kubeconfig, writes cluster resources,
and briefly materializes an owner-only Helm values file containing cloud
identifiers and sensor options. No Log Analytics shared key is retrieved or
passed to Helm. The script removes the file after success or failure and uses
Helm 3 `--atomic` or Helm 4 `--rollback-on-failure`. It attempts to restore the
prior cluster Defender/profile-tag state if chart deployment fails. Old Helm
release history may still contain credentials from previous lab versions;
review retained release records as part of operator cleanup. Workspace local
(shared-key) authentication is disabled by the current template.

First deployment requires 1-20 explicit public operator-egress IPv4 CIDRs, each
/24 through /32; broad, private, documentation, benchmark, protocol-assignment,
deprecated-relay, malformed, noncanonical, or duplicate ranges are rejected.
This input validation cannot prove an address is your actual egress.
Obtain the correct VPN/NAT egress from your network owner; the
script does not discover it or silently allow every address. Owned reruns reuse
the exact saved ranges when omitted and refuse changed inputs or live range
drift. See [Microsoft's authorized IP range guidance](https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges),
including connectivity propagation and egress requirements. The API endpoint
remains public behind that IP allowlist, and this lab retains its existing local
Kubernetes authentication. It is not a private or Entra-only cluster deployment.

Review the queries, then enable the rules:

```powershell
# After reviewing the queries, explicitly enable the three rules.
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -EnableSentinelRules
```

Run the test scenarios after the ownership-verified deployment:

```powershell
./scripts/Test-RuntimeSecurity.ps1 -ProjectName "aks-runtime-lab" -Namespace "runtime-security-tests"
```

Deployment parameters are `-Location`, `-ProjectName`, `-ApiServerAuthorizedIpRanges`,
`-KubernetesVersion`, `-DefenderHelmChartVersion`, `-SkipSentinel`, `-EnableSentinelRules`,
`-Destroy`, and PowerShell's common `-WhatIf` switch. The test helper accepts
`-ProjectName`, `-Namespace`, `-SkipDrift`, `-SkipMalware`, `-SkipGated`, and `-GatedTestImage`.

The test helper verifies the active tenant/subscription, resource-group owner,
ARM resource ID and immutable resourceUID, API allowlist, kubeconfig server/CA,
and recorded kube-system namespace UID before creating anything. A matching
context alias alone is insufficient. A foreign namespace or foreign pod in the
test namespace is refused. Every run creates uniquely named, owner-labeled pods;
it never pre-deletes or replaces existing pods and verifies pod UID before exec.
Deployment and cleanup Azure CLI calls use the captured subscription, and
post-verification Kubernetes/Helm calls use the captured kubeconfig context.
The output lists the run selector for review before manual cleanup. Use a
dedicated lab and avoid concurrent kubeconfig, namespace, or pod administration
during a run; Kubernetes exec does not expose an atomic UID precondition.

Legacy manifests must be refreshed by an owned deployment with explicit API
ranges before runtime testing. Existing recorded identity mismatches (including
certificate rotation or cluster recreation) fail closed and require independent
operator verification; deleting the ownership manifest is not a recovery step.
The local manifest is trusted operator state, not a tamper-proof attestation.

> **Portal steps required before testing:** Configure the **binary drift policy** in Defender for Cloud > Environment Settings > Containers drift policy. The default is "Ignore drift detection"; change it to "Drift detection alert" or "Drift detection blocking". Review the anti-malware rules and chosen Alert/Block action; Microsoft says policy changes can take up to 30 minutes to reach sensors. Then create a gated-deployment vulnerability-assessment rule under Environment Settings > Security Rules. Start with **Audit**, validate its decisions in **Gated deployment > Admission Monitoring**, and move to **Deny** only when the intended scope and thresholds are correct. The deployment script does not create these policies.

Gated deployment requires Kubernetes 1.31 or later, OIDC on AKS, Defender
sensor with Security Gating, Registry access with Security findings, and
vulnerability findings artifacts for evaluated images. The lab deploys AKS on
a supported GA version with OIDC, but you must verify every service-side prerequisite and artifact
before attributing an allow/deny result to a policy.

## What Gets Deployed

| Resource | Type | Purpose |
|---|---|---|
| `aks-runtime-lab` | AKS Cluster | Single-node cluster (Standard_D4s_v3) |
| Defender Sensor | Helm Chart | Release `defender-k8s`: chart `0.11.9` on a first deployment unless `-DefenderHelmChartVersion` selects another; reruns keep the installed chart. Anti-malware collector enabled (`mdc` namespace) |
| `aks-runtime-lab-law` | Log Analytics | Container Insights + Microsoft Sentinel |
| Defender for Containers | Security Plan | Subscription-level enablement |
| 3 Analytics Rules | Sentinel | Binary drift, malware, kubectl exec |
| 1 Workbook | Sentinel | Container Runtime Security Dashboard |

## Repository Structure

```
.
|-- .github/
|   `-- workflows/
|       `-- validate.yml                 # Offline CI: Bicep build, parsing, mocked tests
|-- bicep/
|   |-- main.bicep                       # Subscription-scoped orchestrator
|   `-- modules/
|       |-- aks.bicep                    # AKS cluster + diagnostics (sensor via Helm)
|       `-- monitoring.bicep             # Log Analytics + Sentinel + Container Insights
|-- detection/
|   |-- analytics-rules.kql              # 3 Sentinel analytics rules
|   `-- hunting-queries.kql              # 3 proactive hunting queries
|-- scripts/
|   |-- Cluster-Identity.ps1             # Shared ownership and cluster-identity checks
|   |-- Deploy-Lab.ps1                   # One-command deployment
|   `-- Test-RuntimeSecurity.ps1         # 3 test scenarios
|-- tests/
|   |-- Test-AzJson.ps1                  # Offline Azure CLI output and error-handling checks
|   |-- Test-DeployLabSafety.ps1         # Offline Azure/Kubernetes/Helm safety mocks
|   |-- Test-ReadmeCommandBlocks.ps1     # Offline check of README copy-paste blocks
|   `-- Test-RuntimeSafety.ps1           # Offline ownership mocks for the test helper
|-- workbook/
|   `-- container-runtime-workbook.json  # Container Runtime Security Dashboard
|-- .gitignore                           # Keeps local ownership manifests out of Git
|-- LICENSE
`-- README.md
```

First deployment resolves an exact patch from the region's default GA AKS
version, or validates an explicit `-KubernetesVersion` against regional GA
availability. New deployments require at least 1.32 for this template's Azure
Linux 3 selection (the gated feature itself requires 1.31). The exact version is recorded in the
manifest and reused on reruns; a changing regional default never upgrades an
owned cluster. Older manifests use the live cluster's exact version. Plan
cluster upgrades separately before that version leaves support.

## Test Scenarios

### Test 1: Binary Drift

Copies the existing BusyBox ELF to a new path in the writable container layer
and executes its harmless `true` applet. Running a newly written shell script
alone can execute only the in-image interpreter and is not equivalent evidence.
Drift and malware pods use a reviewed nginx 1.30-alpine image index digest.

```powershell
./scripts/Test-RuntimeSecurity.ps1 -SkipMalware -SkipGated
```

**Validation boundary:** the activity should be evaluated when binary drift is
enabled, but the observed alert/block behavior depends on the selected policy.
Alert generation and ingestion are asynchronous and are not guaranteed within
a fixed window.

### Test 2: Anti-Malware (EICAR)

Writes the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/), marks it executable, and attempts to execute it in a running container. Runtime anti-malware evaluates executable launch; writing the file alone is not the documented trigger.

```powershell
./scripts/Test-RuntimeSecurity.ps1 -SkipDrift -SkipGated
```

**Validation boundary:** EICAR is a harmless industry-standard test string, not
malware. A nonzero container command does not by itself prove Defender blocked
execution. Inspect the configured anti-malware action and Defender security
alerts. Policy propagation can take up to 30 minutes, and subsequent alert
delivery has variable latency.

### Test 3: Gated Deployment

The default image is shown in Microsoft's sample denial message; Microsoft
does not promise it is a test fixture for your subscription. For a controlled
validation, pass `-GatedTestImage` with a reviewed image in a supported registry
that has registry access/security findings enabled. Confirm the signed findings
artifact and matching policy scope before interpreting the admission result.

```powershell
./scripts/Test-RuntimeSecurity.ps1 -SkipDrift -SkipMalware
```

**Validation boundary:** an effective matching Deny rule returns an admission-
webhook denial; Audit allows the request. Review the authoritative decision,
triggered rule, image digest, violations, and exemptions under Defender for
Cloud > Environment settings > Security rules > Gated deployment > Admission
Monitoring. An allowed pod can also mean a scope mismatch, missing findings
artifacts, or incomplete prerequisites.

## Sentinel Analytics Rules

| Rule | Severity | MITRE | Table |
|---|---|---|---|
| Binary Drift in Production Namespace | High | T1059 | SecurityAlert |
| Container Malware Detected | High | T1204 | SecurityAlert |
| Suspicious kubectl exec into Container | Medium | T1609 | AzureDiagnostics |

The exec rule includes `kube-system`; a namespace name does not establish a
trusted caller. Tune specific authenticated automation identities only after
reviewing their actual activity, rather than excluding the entire namespace.

Gated-deployment events are intentionally absent from the Sentinel rules and
workbook. Microsoft documents Admission Monitoring as their review surface and
does not document a `SecurityAlert` `AlertType` named `GatedDeployment`.

## Estimated Cost

| Resource | Approx. Monthly Cost |
|---|---|
| AKS | One `Standard_D4s_v3` node plus any control-plane/network charges |
| Defender for Containers | Subscription pricing and protected vCores |
| Log Analytics | Ingestion and retention for the selected region/tier |

Pricing and included allowances change. Use Azure Pricing and Cost Management
for the target subscription rather than treating a sample estimate as a cap.
Destroy the lab when it is not in use.

## Cleanup

Preview the cleanup:

```powershell
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" -Destroy -WhatIf
```

Read the preview output, then run the cleanup:

```powershell
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" -Destroy
```

Deployment creates an owner-only `.aks-runtime-lab-state-<project>.json`
manifest before the first cloud write. A pre-existing resource group is never
adopted without that manifest and its per-deployment ownership token.

`-Destroy -WhatIf` previews exact cleanup. The real cleanup validates the
manifest and resource-group ownership tag, preflights shared pricing, deletes
the exact owned group, and verifies its absence before restoring captured
pre-lab Defender pricing/extensions. A failed or incomplete group deletion keeps
the current protection and retry manifest. Pricing restore is rechecked for
concurrent changes and verified before the manifest is removed. A retry accepts
the exact already-restored before-state, so a failed restore or interrupted
final manifest removal can be completed without another group deletion. Other
detected shared-setting drift fails closed. These are compare-before-write checks,
not an atomic lock against another subscription administrator.

Pricing comparisons exclude documented server-only fields such as
`enablementTime` and extension `operationStatus`. Deployment verifies the
requested writable values and extension results, then records the writable
state returned by the pricing PUT as `pricingApplied`. Later reads must match
that snapshot before automatic rollback or cleanup can replace shared settings.
Unknown fields, failed reads, and ambiguous writes retain the manifest for
operator review. Old manifests without `pricingApplied` are recoverable only
when current normalized pricing exactly matches their captured before-state or
requested state; extra writable settings are not silently adopted. In
particular, do not delete a manifest or edit it to match current pricing merely
to bypass a drift refusal.

The response-shape and failure-recovery tests are offline mocks; they do not
establish a fresh Azure deployment or billing outcome.

## Monitoring and policy boundaries

The three scheduled rules keep a one-hour event lookback but select rows
ingested in the latest five-minute interval before expansion. This avoids
re-alerting the same stored row solely because scheduled lookbacks overlap;
provider status updates or duplicate ingestion routes still require review.
The drift namespace list includes the default `runtime-security-tests` scope.
Hunts and the workbook retain ProductName so the legacy connector and XDR
routes can be distinguished; row counts are not unique underlying alerts.

The script creates the subscription-based Defender for Cloud **Legacy**
connector. For a workspace integrated with Defender XDR, review Microsoft's
current connector/incident guidance to avoid duplicate ingestion and incidents.
Sentinel in the Azure portal ends support on March 31, 2027; Defender-portal
workspaces without XDR have a different connector path.

The Container Insights add-on is enabled, but this bundle does not configure a
DCR/association or assert that ContainerLogV2/KubePodInventory is populated.
Verify that collection separately using Microsoft's supported onboarding
procedure. Lab queries use SecurityAlert and kube-audit AzureDiagnostics. The
redundant kube-audit-admin stream and unused AllMetrics export are omitted.

Policy preflight includes inherited assignments and direct members of policy
initiatives. Unreadable initiatives fail closed before replacing the managed
sensor. A matching definition is conservatively treated as a conflict; review
parameters/exemptions rather than assuming an initiative cannot apply. The
exclusion tag retained for compatibility is not proof that AKS provisioning is
disabled; effective policy and Defender profile checks remain necessary.

The Linux Azure Network Policy Manager choice remains supported into 2028; a
Cilium migration changes cluster networking and is not performed silently by
this maintenance update. Audit JSON-query optimization likewise requires
representative profiling before adding filters that might drop encoded input.

## Resources

- [Microsoft: Binary drift detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/binary-drift-detection)
- [Microsoft: Container runtime anti-malware](https://learn.microsoft.com/en-us/azure/defender-for-cloud/anti-malware)
- [Microsoft: Kubernetes Gated Deployment](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enablement-guide-runtime-gated)
- [Microsoft: Troubleshoot Gated Deployment](https://learn.microsoft.com/en-us/azure/defender-for-cloud/troubleshooting-runtime-gated)
- [Microsoft: Install the Defender sensor with Helm](https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-helm)
- [Microsoft: Defender sensor changelog](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-sensor-change-log)
- [Microsoft: Defender for Cloud Attack Simulation](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation)
- [MITRE ATT&CK: Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)

## License

MIT
