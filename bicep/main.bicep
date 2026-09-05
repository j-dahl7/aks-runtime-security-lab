// AKS Runtime Security Lab - Main Orchestrator
// Deploys AKS cluster with Defender for Containers, Log Analytics, and Container Insights
//
// Supported entry point from the repository root:
//   ./scripts/Deploy-Lab.ps1 -Location eastus -WhatIf
// Use that ownership-aware orchestrator for deployment; it supplies the secure
// ownerToken and records the rollback manifest. Direct Bicep deployment is unsupported.
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
param kubernetesVersion string = '1.35'

@description('Additional tags for all resources')
param tags object = {}

@secure()
@description('Per-deployment ownership token used to prevent resource-group adoption')
param ownerToken string

var labTags = union({
  project: projectName
  environment: 'lab'
  purpose: 'aks-runtime-security-demo'
  'nlzt-owner': ownerToken
}, tags)

// ---------- Resource Group ----------
resource resourceGroup 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: '${projectName}-rg'
  location: location
  tags: labTags
}

// ---------- Log Analytics Workspace ----------
module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring-deployment'
  scope: resourceGroup
  params: {
    projectName: projectName
    location: location
    tags: labTags
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
    tags: labTags
  }
}

// ---------- Outputs ----------
output resourceGroupName string = resourceGroup.name
output resourceGroupId string = resourceGroup.id
output clusterName string = aks.outputs.clusterName
output workspaceId string = monitoring.outputs.workspaceId
output workspaceName string = monitoring.outputs.workspaceName
