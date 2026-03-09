# AKS Runtime Security Lab

Deploy three layers of AKS runtime defense with Microsoft Defender for Cloud:

| Layer | Feature | Status | What It Does |
|---|---|---|---|
| **Deploy-time gate** | Gated Deployment | GA | Admission control blocks images with unresolved critical CVEs |
| **Runtime detection** | Binary Drift | GA detect / Preview block | Catches executables not in the original container image |
| **Runtime protection** | Container Anti-Malware | Preview | Real-time malware detection and blocking inside running containers |

Companion lab for the blog post: [AKS Runtime Security: Binary Drift, Anti-Malware & Gated Deployment with Defender for Cloud](https://nineliveszerotrust.com/blog/aks-runtime-security-defender/)

## Prerequisites

- Azure subscription with **Owner** or **Contributor + User Access Administrator** role
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) v2.60+
- [kubectl](https://kubernetes.io/docs/tasks/tools/) v1.28+
- [Helm](https://helm.sh/docs/intro/install/) v3.12+
- [PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell)

## Quick Start

```bash
git clone https://github.com/j-dahl7/aks-runtime-security-lab.git
cd aks-runtime-security-lab
```

```powershell
# Deploy everything (AKS + Defender + Sentinel rules + workbook)
./scripts/Deploy-Lab.ps1 -Location "eastus"

# Run test scenarios (binary drift, EICAR malware, vulnerable image)
./scripts/Test-RuntimeSecurity.ps1
```

## What Gets Deployed

| Resource | Type | Purpose |
|---|---|---|
| `aks-runtime-lab` | AKS Cluster | Single-node cluster (Standard_D4s_v3) with Defender sensor |
| `aks-runtime-lab-law` | Log Analytics | Container Insights + Microsoft Sentinel |
| Defender for Containers | Security Plan | Subscription-level enablement |
| 4 Analytics Rules | Sentinel | Binary drift, malware, gated deployment, kubectl exec |
| 1 Workbook | Sentinel | Container Runtime Security Dashboard |

## Repository Structure

```
├── bicep/
│   ├── main.bicep                  # Subscription-scoped orchestrator
│   └── modules/
│       ├── aks.bicep               # AKS + Defender sensor + diagnostics
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

**Expected alert:** "A drift binary detected executing in the container" (5-15 min)

### Test 2: Anti-Malware (EICAR)

Writes the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) into a running container.

```bash
kubectl run malware-test --image=nginx:latest --restart=Never
kubectl exec malware-test -- /bin/sh -c \
  "echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > /tmp/eicar.com"
```

**Expected alert:** "Malicious file detected" (5-15 min)

### Test 3: Gated Deployment

Attempts to deploy an image with known critical CVEs.

```bash
kubectl run vuln-test --image=nginx:1.14.0 --restart=Never
```

**Expected:** Deployment blocked (Deny mode) or audit recommendation (Audit mode)

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

## Cleanup

```powershell
./scripts/Deploy-Lab.ps1 -Destroy
```

Or manually:

```bash
az group delete --name aks-runtime-lab-rg --yes --no-wait
```

## Resources

- [Microsoft: Binary drift detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/binary-drift-detection)
- [Microsoft: Container runtime anti-malware](https://learn.microsoft.com/en-us/azure/defender-for-cloud/anti-malware-detection-blocking)
- [Microsoft: Kubernetes Gated Deployment](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enablement-guide-runtime-gated)
- [Microsoft: Defender for Cloud Attack Simulation](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation)
- [MITRE ATT&CK: Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)

## License

MIT
