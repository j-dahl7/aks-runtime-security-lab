# AKS Runtime Security Lab

Deploy three layers of AKS runtime defense with Microsoft Defender for Cloud:

| Layer | Feature | Status | What It Does |
|---|---|---|---|
| **Deploy-time gate** | Gated Deployment | GA | Evaluates images at admission; configured rules can audit or deny matching images |
| **Runtime detection** | Binary Drift | GA | Detects or blocks executables that differ from the original container image |
| **Runtime protection** | Container Anti-Malware | GA | Real-time malware detection and blocking inside running containers |

Companion lab for the blog post: [AKS Runtime Security: Binary Drift, Anti-Malware & Gated Deployment with Defender for Cloud](https://nineliveszerotrust.com/blog/aks-runtime-security-defender/)

## Validation Boundary

The hardened July 25, 2026 revision was validated with Bicep compilation,
PowerShell parsing, and mocked safety/rollback tests. It was not freshly
deployed to Azure, and no live AKS, Defender, Helm, Sentinel, or alert-ingestion
validation was performed for this revision. Feature availability, policy
behavior, chart availability, and alert latency can vary by
subscription, region, and cluster version.

## Prerequisites

- Azure subscription with **Owner** or **Contributor + User Access Administrator** role
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) v2.60+
- [kubectl](https://kubernetes.io/docs/tasks/tools/) compatible with the
  bundled AKS Kubernetes 1.35 deployment
- [Helm](https://helm.sh/docs/intro/install/) v3.12+
- [PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell)

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

## Quick Start

```bash
git clone https://github.com/j-dahl7/aks-runtime-security-lab.git
cd aks-runtime-security-lab
```

```powershell
# Read-only preview. This reports intended operations and performs no Azure,
# Kubernetes, Helm, kubeconfig, or local secret-file mutations.
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -WhatIf
```

Verify the active subscription and current shared plan before the real run:

```powershell
az account show --query '{subscription:name,id:id}' -o table
az security pricing show --name Containers -o json

# Required only when the script reports that the shared plan/extensions need
# to change:
$env:CONFIRM_SUBSCRIPTION_SCOPE = 'ENABLE-DEFENDER-FOR-CONTAINERS'

# Live deployment: AKS + Defender + Helm sensor + disabled Sentinel rules + workbook
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab"

# After reviewing the queries, explicitly enable the four rules.
./scripts/Deploy-Lab.ps1 -Location "eastus" -ProjectName "aks-runtime-lab" -EnableSentinelRules
```

The confirmation authorizes a live subscription-level change; it is not a
preview. A real deployment also updates kubeconfig, writes cluster resources,
and briefly materializes an owner-only Helm values file containing the
workspace key. The script removes that file after success or failure, uses
Helm `--atomic`, and attempts to restore the prior cluster Defender/profile-tag
state if the chart deployment fails.

After verifying that `kubectl config current-context` is the dedicated lab
cluster, run the harmless test scenarios:

```powershell
./scripts/Test-RuntimeSecurity.ps1 -ProjectName "aks-runtime-lab" -Namespace "runtime-security-tests"
```

Deployment parameters are `-Location`, `-ProjectName`, `-SkipSentinel`,
`-EnableSentinelRules`, `-Destroy`, and PowerShell's common `-WhatIf` switch. The test helper accepts
`-ProjectName`, `-Namespace`, `-SkipDrift`, `-SkipMalware`, and `-SkipGated`.

> **Portal steps required before testing:** Configure the **binary drift policy** in Defender for Cloud > Environment Settings > Containers drift policy. The default is "Ignore drift detection"; change it to "Drift detection alert" or "Drift detection blocking". Then create a gated-deployment vulnerability-assessment rule under Environment Settings > Security Rules. Start with **Audit**, validate its matches, and move to **Deny** only when the intended scope and thresholds are correct. The deployment script does not create either policy.

## What Gets Deployed

| Resource | Type | Purpose |
|---|---|---|
| `aks-runtime-lab` | AKS Cluster | Single-node cluster (Standard_D4s_v3) |
| Defender Sensor | Helm Chart | Bundle-tested pin `0.11.4` with anti-malware collector (`mdc` namespace) |
| `aks-runtime-lab-law` | Log Analytics | Container Insights + Microsoft Sentinel |
| Defender for Containers | Security Plan | Subscription-level enablement |
| 4 Analytics Rules | Sentinel | Binary drift, malware, gated deployment, kubectl exec |
| 1 Workbook | Sentinel | Container Runtime Security Dashboard |

## Repository Structure

```
├── bicep/
│   ├── main.bicep                  # Subscription-scoped orchestrator
│   └── modules/
│       ├── aks.bicep               # AKS cluster + diagnostics (sensor via Helm)
│       └── monitoring.bicep        # Log Analytics + Sentinel + Container Insights
├── detection/
│   ├── analytics-rules.kql         # 4 Sentinel analytics rules
│   └── hunting-queries.kql         # 3 proactive hunting queries
├── scripts/
│   ├── Deploy-Lab.ps1              # One-command deployment
│   └── Test-RuntimeSecurity.ps1    # 3 test scenarios
└── workbook/
    └── container-runtime-workbook.json  # Container Runtime Security Dashboard
```

## Test Scenarios

### Test 1: Binary Drift

Drops and executes a script not present in the original container image.

```bash
kubectl run drift-test --image=nginx:latest --restart=Never
kubectl exec drift-test -- /bin/sh -c \
  "echo '#!/bin/sh' > /tmp/notinimage.sh && chmod +x /tmp/notinimage.sh && /tmp/notinimage.sh"
```

**Expected signal:** a binary-drift alert if the feature and policy are enabled.
Alert generation and ingestion are asynchronous and are not guaranteed within a
fixed window.

### Test 2: Anti-Malware (EICAR)

Writes the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) into a running container.

```bash
kubectl run malware-test --image=nginx:latest --restart=Never
kubectl exec malware-test -- /bin/sh -c \
  "echo 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=' | base64 -d > /tmp/eicar.com"
```

**Expected signal:** a malware alert if the sensor and anti-malware extension
are healthy. EICAR is a harmless industry-standard test string, not malware.

### Test 3: Gated Deployment

Attempts to deploy an image with known critical CVEs.

```bash
kubectl run vuln-test --image=nginx:1.14.0 --restart=Never
```

**Expected signal:** denial in an effective Deny policy or an audit
recommendation in Audit mode. An old image tag does not guarantee that the
current vulnerability feed will still classify it as a critical finding.

## Sentinel Analytics Rules

| Rule | Severity | MITRE | Table |
|---|---|---|---|
| Binary Drift in Production Namespace | High | T1059 | SecurityAlert |
| Container Malware Detected | High | T1204 | SecurityAlert |
| Vulnerable Image Deployment Attempted | Medium | T1190 | SecurityAlert |
| Suspicious kubectl exec into Container | Medium | T1609 | AzureDiagnostics |

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
manifest and resource-group ownership tag, restores the captured pre-lab
Defender for Containers pricing/extensions only when the current shared state
still exactly matches what this lab wrote, deletes the exact owned resource
group, verifies deletion, and then removes the manifest. Any ownership or
shared-setting drift fails closed before deletion.

## Resources

- [Microsoft: Binary drift detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/binary-drift-detection)
- [Microsoft: Container runtime anti-malware](https://learn.microsoft.com/en-us/azure/defender-for-cloud/anti-malware-detection-blocking)
- [Microsoft: Kubernetes Gated Deployment](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enablement-guide-runtime-gated)
- [Microsoft: Defender for Cloud Attack Simulation](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation)
- [MITRE ATT&CK: Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)

## License

MIT
