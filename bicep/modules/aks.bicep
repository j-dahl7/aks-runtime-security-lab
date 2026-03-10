// AKS Cluster for Defender for Containers lab
// Note: Defender sensor is deployed separately via Helm (Deploy-Lab.ps1 step 5)
// to get v0.10.2+ with anti-malware support.

param projectName string
param location string
param kubernetesVersion string
param nodeVmSize string
param nodeCount int
param logAnalyticsWorkspaceId string
param tags object = {}

resource aks 'Microsoft.ContainerService/managedClusters@2024-09-01' = {
  name: projectName
  location: location
  tags: union({
    project: projectName
    component: 'aks'
  }, tags)
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: projectName
    enableRBAC: true

    agentPoolProfiles: [
      {
        name: 'nodepool1'
        count: nodeCount
        vmSize: nodeVmSize
        osType: 'Linux'
        osSKU: 'AzureLinux'
        mode: 'System'
        enableAutoScaling: false
      }
    ]

    // Enable Container Insights (OMS agent addon)
    addonProfiles: {
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: logAnalyticsWorkspaceId
          useAADAuth: 'true'
        }
      }
      azurepolicy: {
        enabled: true
      }
    }

    // Network configuration
    networkProfile: {
      networkPlugin: 'azure'
      networkPolicy: 'azure'
      serviceCidr: '10.0.0.0/16'
      dnsServiceIP: '10.0.0.10'
    }

    // Enable workload identity
    oidcIssuerProfile: {
      enabled: true
    }

    // Security profile - workload identity only
    // Defender sensor is deployed via Helm chart (Deploy-Lab.ps1) for v0.10.2+
    // which includes anti-malware collector and drift blocking support.
    securityProfile: {
      workloadIdentity: {
        enabled: true
      }
    }
  }
}

// Diagnostic settings - send kube-audit logs to Log Analytics
resource aksDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${projectName}-diag'
  scope: aks
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'kube-audit-admin'
        enabled: true
      }
      {
        category: 'kube-audit'
        enabled: true
      }
      {
        category: 'guard'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

output clusterName string = aks.name
output clusterFqdn string = aks.properties.fqdn
