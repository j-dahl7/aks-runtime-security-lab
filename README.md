# AKS Runtime Security Lab

Prepare a dedicated AKS lab for three layers of Microsoft Defender for Cloud controls:

| Layer | Feature | Status | What It Does |
|---|---|---|---|
| **Deploy-time gate** | Gated Deployment | GA | Evaluates images at admission; configured rules can audit or deny matching images |
| **Runtime detection** | Binary Drift | GA | Detects or blocks executables that differ from the original container image |
| **Runtime protection** | Container Anti-Malware | GA | Real-time malware detection and blocking inside running containers |

Companion lab for the blog post: [AKS Runtime Security: Binary Drift, Anti-Malware & Gated Deployment with Defender for Cloud](https://nineliveszerotrust.com/blog/aks-runtime-security-defender/)

## Validation Boundary

The August 13, 2026 source-audited revision was validated with Bicep compilation,
PowerShell parsing, and mocked safety/rollback tests. It was not freshly
deployed to Azure, and no live AKS, Defender, Helm, Sentinel, or alert-ingestion
validation was performed for this revision. Feature availability, policy
behavior, chart availability, and alert latency can vary by
subscription, region, and cluster version.

Run the offline deployment-safety harness from a fresh checkout:

```powershell
pwsh -NoProfile -File tests/Test-DeployLabSafety.ps1
```

It mocks Azure CLI, Kubernetes, and Helm to exercise ownership refusal, exact
stale-resource cleanup, `-WhatIf`, pricing/profile rollback, readiness, and
default-disabled/explicitly-enabled rules. It refuses to run over an existing
ownership manifest. Passing this harness is not a live cluster or sensor test.
The separate `validate.yml` pull-request workflow compiles Bicep and runs these
mocks without cloud credentials, deployment steps, or schedules.

## Prerequisites

- Azure subscription with **Owner** or **Contributor + User Access Administrator** role
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) v2.60+
- [kubectl](https://kubernetes.io/docs/tasks/tools/) compatible with the
  bundled AKS Kubernetes 1.35 deployment
- [Helm](https://helm.sh/docs/intro/install/) v3.12+
- [PowerShell 7.4 or later](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) (enforced before either entry point runs; required for the supported .NET APIs)

This lab can enable or change the paid Defender for Containers plan and its
extensions at subscription scope. If the required state is not already active,
the real deployment requires the exact environment confirmation
`CONFIRM_SUBSCRIPTION_SCOPE=ENABLE-DEFENDER-FOR-CONTAINERS`.

The script pins Defender's OCI Helm chart to `0.11.4` because that is the
bundle-tested version. It is not a claim that `0.11.4` is the newest release or
compatible with every future AKS/Defender combination. Before a live run,
confirm that the publisher still serves the pin and review its supported
Kubernetes/Defender matrix:

```powershell
helm show chart oci://mcr.microsoft.com/azuredefender/microsoft-defender-for-containers --version 0.11.4
```

A Helm-managed sensor is not upgraded automatically; the operator owns chart
review and upgrades. Microsoft also notes that the portal can label a
Helm-installed subscription `not supported for Gated deployment`. If the gated
rule flow offers to auto-install components, choose **Skip** so it does not
conflict with the existing Helm deployment. This lab uses standard AKS and the
`mdc` namespace; AKS Automatic has separate `kube-system` requirements. Review
[Microsoft's current Helm guidance](https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-helm)
before a live run.

## Quick Start

```bash
git clone https://github.com/j-dahl7/aks-runtime-security-lab.git
cd aks-runtime-security-lab
```

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

# Required only when the script reports that the shared plan/extensions need
# to change:
$env:CONFIRM_SUBSCRIPTION_SCOPE = 'ENABLE-DEFENDER-FOR-CONTAINERS'

# Live deployment: AKS + Defender + Helm sensor + disabled Sentinel rules + workbook
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -ApiServerAuthorizedIpRanges $operatorEgress

# After reviewing the queries, explicitly enable the three rules.
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -EnableSentinelRules
```

The confirmation authorizes a live subscription-level change; it is not a
preview. A real deployment also updates kubeconfig, writes cluster resources,
and briefly materializes an owner-only Helm values file containing the
workspace key. The script removes that file after success or failure, uses
Helm `--atomic`, and attempts to restore the prior cluster Defender/profile-tag
state if the chart deployment fails.

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

Run the test scenarios after the ownership-verified deployment:

```powershell
./scripts/Test-RuntimeSecurity.ps1 -ProjectName "aks-runtime-lab" -Namespace "runtime-security-tests"
```

Deployment parameters are `-Location`, `-ProjectName`, `-ApiServerAuthorizedIpRanges`, `-SkipSentinel`,
`-EnableSentinelRules`, `-Destroy`, and PowerShell's common `-WhatIf` switch. The test helper accepts
`-ProjectName`, `-Namespace`, `-SkipDrift`, `-SkipMalware`, and `-SkipGated`.

The test helper verifies the active tenant/subscription, resource-group owner,
ARM resource ID and immutable resourceUID, API allowlist, kubeconfig server/CA,
and recorded kube-system namespace UID before creating anything. A matching
context alias alone is insufficient. A foreign namespace or foreign pod in the
test namespace is refused. Every run creates uniquely named, owner-labeled pods;
it never pre-deletes or replaces existing pods and verifies pod UID before exec.
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
vulnerability findings artifacts for evaluated images. The lab deploys AKS
1.35 with OIDC, but you must verify every service-side prerequisite and artifact
before attributing an allow/deny result to a policy.

## What Gets Deployed

| Resource | Type | Purpose |
|---|---|---|
| `aks-runtime-lab` | AKS Cluster | Single-node cluster (Standard_D4s_v3) |
| Defender Sensor | Helm Chart | Bundle-tested pin `0.11.4` with anti-malware collector (`mdc` namespace) |
| `aks-runtime-lab-law` | Log Analytics | Container Insights + Microsoft Sentinel |
| Defender for Containers | Security Plan | Subscription-level enablement |
| 3 Analytics Rules | Sentinel | Binary drift, malware, kubectl exec |
| 1 Workbook | Sentinel | Container Runtime Security Dashboard |

## Repository Structure

```
├── bicep/
│   ├── main.bicep                  # Subscription-scoped orchestrator
│   └── modules/
│       ├── aks.bicep               # AKS cluster + diagnostics (sensor via Helm)
│       └── monitoring.bicep        # Log Analytics + Sentinel + Container Insights
├── detection/
│   ├── analytics-rules.kql         # 3 Sentinel analytics rules
│   └── hunting-queries.kql         # 3 proactive hunting queries
├── scripts/
│   ├── Deploy-Lab.ps1              # One-command deployment
│   └── Test-RuntimeSecurity.ps1    # 3 test scenarios
├── tests/
│   └── Test-DeployLabSafety.ps1    # Offline Azure/Kubernetes/Helm safety mocks
└── workbook/
    └── container-runtime-workbook.json  # Container Runtime Security Dashboard
```

## Test Scenarios

### Test 1: Binary Drift

Drops and executes a script not present in the original container image.

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

Attempts Microsoft's test image shown in its gated-deployment troubleshooting
documentation. This avoids assuming that an arbitrary old image tag still maps
to current vulnerability findings.

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

```powershell
./scripts/Deploy-Lab.ps1 -ProjectName "aks-runtime-lab" -Destroy -WhatIf
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
shared-setting drift fails closed; it is never overwritten.

## Resources

- [Microsoft: Binary drift detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/binary-drift-detection)
- [Microsoft: Container runtime anti-malware](https://learn.microsoft.com/en-us/azure/defender-for-cloud/anti-malware)
- [Microsoft: Kubernetes Gated Deployment](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enablement-guide-runtime-gated)
- [Microsoft: Troubleshoot Gated Deployment](https://learn.microsoft.com/en-us/azure/defender-for-cloud/troubleshooting-runtime-gated)
- [Microsoft: Install the Defender sensor with Helm](https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-helm)
- [Microsoft: Defender for Cloud Attack Simulation](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation)
- [MITRE ATT&CK: Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)

## License

MIT
