// AKS Runtime Security Lab - Main Orchestrator
// Deploys AKS cluster with Defender for Containers, Log Analytics, and Container Insights
//
// Usage:
//   az deployment sub create --location eastus --template-file main.bicep --parameters location=eastus
//
// Note: Defender for Containers plan enablement, drift policies, and Sentinel rules
// are configured separately via PowerShell due to REST API dependencies.

targetScope = 'subscription'

@description('Project name used for resource naming')
@minLength(3)
@maxLength(20)
param projectName string = 'aks-runtime-lab'

@description('Azure region for all resources')
param location string = 'eastus'

@description('AKS node VM size')
param nodeVmSize string = 'Standard_D4s_v3'

@description('Number of AKS nodes')
@minValue(1)
@maxValue(3)
param nodeCount int = 1

@description('Kubernetes version')
param kubernetesVersion string = '1.32'

@description('Additional tags for all resources')
param tags object = {}

// ---------- Resource Group ----------
resource resourceGroup 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: '${projectName}-rg'
  location: location
  tags: union({
    project: projectName
    environment: 'lab'
    purpose: 'aks-runtime-security-demo'
  }, tags)
}

// ---------- Log Analytics Workspace ----------
module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring-deployment'
  scope: resourceGroup
  params: {
    projectName: projectName
    location: location
    tags: tags
  }
}

// ---------- AKS Cluster ----------
module aks 'modules/aks.bicep' = {
  name: 'aks-deployment'
  scope: resourceGroup
  params: {
    projectName: projectName
    location: location
    kubernetesVersion: kubernetesVersion
    nodeVmSize: nodeVmSize
    nodeCount: nodeCount
    logAnalyticsWorkspaceId: monitoring.outputs.workspaceId
    tags: tags
  }
}

// ---------- Outputs ----------
output resourceGroupName string = resourceGroup.name
output clusterName string = aks.outputs.clusterName
output workspaceId string = monitoring.outputs.workspaceId
output workspaceName string = monitoring.outputs.workspaceName
