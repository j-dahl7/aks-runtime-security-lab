# AKS Runtime Security Lab

Deploy three layers of AKS runtime defense with Microsoft Defender for Cloud:

| Layer | Feature | Status | What It Does |
|---|---|---|---|
| **Deploy-time gate** | Gated Deployment | GA | Admission control blocks images with unresolved critical CVEs |
| **Runtime detection** | Binary Drift | GA detect / Preview block | Catches executables not in the original container image |
| **Runtime protection** | Container Anti-Malware | Preview | Real-time malware detection and blocking inside running containers |

Companion lab for the blog post: [AKS Runtime Security: Binary Drift, Anti-Malware & Gated Deployment with Defender for Cloud](https://nineliveszerotrust.com/blog/aks-runtime-security-defender/)

## Verification status

**Source-verified — last verified 2026-07-10.** The Bicep compiled, PowerShell parsed, workbook JSON loaded, tracked links and repository paths were checked, and the deployment code was aligned with the current Defender for Containers Helm chart. The review did not create an AKS cluster or regenerate Defender incidents. Binary drift, anti-malware, and gated-deployment outcomes therefore remain tenant-, region-, policy-, and ingestion-dependent.

## Prerequisites

- Azure subscription with **Owner** or **Contributor + User Access Administrator** role. The script changes the subscription-level Defender for Containers plan.
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) v2.60+
- [kubectl](https://kubernetes.io/docs/tasks/tools/) compatible with AKS Kubernetes 1.35
- [Helm](https://helm.sh/docs/intro/install/) v3.12+
- [PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell)
- Permission to read the lab Log Analytics workspace ID and shared key. The Helm sensor needs both for telemetry publishing; the deployment passes them through an owner-only temporary values file rather than process arguments.

Confirm that AKS Kubernetes 1.35 and `Standard_D4s_v3` are available in the selected region before deploying. The template requests the supported Azure Linux 3 generation through the `AzureLinux` OS SKU.

## Quick Start

```bash
git clone https://github.com/j-dahl7/aks-runtime-security-lab.git
cd aks-runtime-security-lab
```

```powershell
# Preview the complete plan without changing Azure, kubeconfig, Kubernetes, or Helm state
./scripts/Deploy-Lab.ps1 -Location "eastus" -WhatIf

# Deploy everything (AKS + Defender + Helm sensor + Sentinel rules + workbook)
./scripts/Deploy-Lab.ps1 -Location "eastus"

# Run test scenarios (binary drift, EICAR malware, vulnerable image)
./scripts/Test-RuntimeSecurity.ps1
```

> **Portal step required:** After deployment, configure the **binary drift policy** in Defender for Cloud > Environment Settings > Containers drift policy. The default is "Ignore drift detection" — change it to "Drift detection alert" (or "Block" in Preview). There is no REST API for this setting.

## What Gets Deployed

| Resource | Type | Purpose |
|---|---|---|
| `aks-runtime-lab` | AKS Cluster | Kubernetes 1.35, single node (Standard_D4s_v3) |
| Defender Sensor | Helm Chart | Pinned chart 0.11.4 with anti-malware collector (`mdc` namespace) |
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
├── tests/
│   └── Test-DeployLabSafety.ps1     # WhatIf, rollback, and secret-file regression harness
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

**Expected alert:** "A drift binary detected executing in the container" (5-15 min)

### Test 2: Anti-Malware (EICAR)

Writes the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) into a running container.

```bash
kubectl run malware-test --image=nginx:latest --restart=Never
kubectl exec malware-test -- /bin/sh -c \
  "echo 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=' | base64 -d > /tmp/eicar.com"
```

**Expected alert:** "Malicious file detected" (5-15 min)

### Test 3: Gated Deployment

Attempts to deploy an image with known critical CVEs.

```bash
kubectl run vuln-test --image=nginx:1.14.0 --restart=Never
```

**Expected:** Deployment blocked (Deny mode) or audit recommendation (Audit mode)

The public image must have a Defender vulnerability assessment before the gate can make a decision. A first-time image or a tenant still in audit mode can be admitted even when the test command succeeds.

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
| AKS (1x Standard_D4s_v3) | ~$140 |
| Defender for Containers | ~$7/vCore/month |
| Log Analytics (30-day retention) | ~$2.76/GB |

**Total:** ~$160-180/month for a single-node lab cluster. Destroy when not in use.

These are planning estimates, not a quote. VM, Defender, and Log Analytics prices vary by region, agreement, retention, and ingestion volume; confirm them in the Azure pricing calculator before deployment.

## Cleanup

```powershell
./scripts/Deploy-Lab.ps1 -Destroy
```

Or manually:

```bash
az group delete --name aks-runtime-lab-rg --yes --no-wait
```

Resource-group deletion removes the cluster, Helm release, workspace, rules, and workbook created in that group. It does **not** disable the subscription-level Defender for Containers plan. Review that plan separately after cleanup; disabling it can reduce protection for unrelated clusters in the same subscription.

## Troubleshooting and validation

- Run `helm status defender-k8s --namespace mdc` and `kubectl get pods --namespace mdc` before testing. Helm-based sensors require you to manage chart upgrades.
- Before changing the cluster, the script stops on the known Defender auto-provision policy assignment or a Defender Helm release with a different name. Resolve that exact conflict rather than deleting broad subscription policy assignments that may protect other clusters.
- Known cluster-scoped resources left by the managed sensor are inventoried before mutation and removed by exact name only when no existing `defender-k8s` release owns them.
- Helm runs atomically. If installation fails after the managed Defender profile is disabled or the Helm exclusion tag is added, the script restores the prior Defender workspace/profile and exact prior tag state before returning the error.
- The Log Analytics shared key is written only to an owner-only temporary values file, never included in Helm process arguments, and deleted in a `finally` block on both success and failure.
- Defender alerts and Sentinel incidents can take several minutes to arrive. Validate raw `SecurityAlert` and `AzureDiagnostics` rows before assuming an analytics rule is broken.
- The binary-drift policy is still a required portal configuration. The script cannot make that setting for you.
- Test scripts create pods and the EICAR antivirus test file. EICAR is non-malicious but intentionally triggers security tooling; use only in the disposable lab cluster.

Run the bounded deployment-safety regression harness without an Azure deployment:

```powershell
pwsh ./tests/Test-DeployLabSafety.ps1
```

It mocks Azure CLI, kubectl, and Helm to prove that `-WhatIf` performs zero mutations and that a forced Helm failure restores cluster protection and deletes the temporary secret file.

## Resources

- [Microsoft: Binary drift detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/binary-drift-detection)
- [Microsoft: Container runtime anti-malware](https://learn.microsoft.com/en-us/azure/defender-for-cloud/anti-malware)
- [Microsoft: Kubernetes Gated Deployment](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enablement-guide-runtime-gated)
- [Microsoft: Defender for Cloud Attack Simulation](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation)
- [MITRE ATT&CK: Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)

## License

MIT
