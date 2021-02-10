﻿using Azure.Analytics.Synapse.AccessControl.Models;
using Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters;
using Microsoft.Azure.Commands.Synapse.Common;
using Microsoft.Azure.Commands.Synapse.Models;
using Microsoft.Azure.Commands.Synapse.Properties;
using Microsoft.WindowsAzure.Commands.Utilities.Common;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Text;

namespace Microsoft.Azure.Commands.Synapse
{
    [Cmdlet(VerbsCommon.New, ResourceManager.Common.AzureRMConstants.AzureRMPrefix + SynapseConstants.SynapsePrefix + SynapseConstants.RoleAssignment, 
        DefaultParameterSetName = NewByWorkspaceNameAndNameParameterSet, SupportsShouldProcess = true)]
    [OutputType(typeof(PSRoleAssignmentDetails))]
    public class NewAzureSynapseRoleAssignment : SynapseRoleCmdletBase
    {
        private const string NewByWorkspaceNameAndNameParameterSet = "NewByWorkspaceNameAndNameParameterSet";
        private const string NewByWorkspaceNameAndIdParameterSet = "NewByWorkspaceNameAndIdParameterSet";
        private const string NewByWorkspaceObjectAndNameParameterSet = "NewByWorkspaceObjectAndNameParameterSet";
        private const string NewByWorkspaceObjectAndIdParameterSet = "NewByWorkspaceObjectAndIdParameterSet";
        private const string NewByWorkspaceNameAndRoleAssignmentIdAndObjectIdParameterSet = "NewByWorkspaceNameAndRoleAssignmentIdAndObjectIdParameterSet";
        private const string NewByWorkspaceObjectAndRoleAssignmentIdAndObjectIdParameterSet = "NewByWorkspaceObjectAndRoleAssignmentIdAndObjectIdParameterSet";
        private const string NewByWorkspaceNameAndServicePrincipalNameParameterSet = "NewByWorkspaceNameAndServicePrincipalNameParameterSet";
        private const string NewByWorkspaceObjectAndServicePrincipalNameParameterSet = "NewByWorkspaceObjectAndServicePrincipalNameParameterSet";

        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.WorkspaceName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.WorkspaceName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndRoleAssignmentIdAndObjectIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.WorkspaceName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndServicePrincipalNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.WorkspaceName)]
        [ResourceNameCompleter(ResourceTypes.Workspace, "ResourceGroupName")]
        [ValidateNotNullOrEmpty]
        public override string WorkspaceName { get; set; }

        [Parameter(ValueFromPipeline = true, ParameterSetName = NewByWorkspaceObjectAndNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.WorkspaceObject)]
        [Parameter(ValueFromPipeline = true, ParameterSetName = NewByWorkspaceObjectAndIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.WorkspaceObject)]
        [Parameter(ValueFromPipeline = true, ParameterSetName = NewByWorkspaceObjectAndRoleAssignmentIdAndObjectIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.WorkspaceObject)]
        [Parameter(ValueFromPipeline = true, ParameterSetName = NewByWorkspaceObjectAndServicePrincipalNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.WorkspaceObject)]
        [ValidateNotNull]
        public PSSynapseWorkspace WorkspaceObject { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleDefinitionName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleDefinitionName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleDefinitionName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleDefinitionName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndServicePrincipalNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleDefinitionName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndServicePrincipalNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleDefinitionName)]
        [ValidateNotNullOrEmpty]
        public string RoleDefinitionName { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndRoleAssignmentIdAndObjectIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleDefinitionId)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndRoleAssignmentIdAndObjectIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleDefinitionId)]
        [ValidateNotNullOrEmpty]
        public string RoleDefinitionId { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndRoleAssignmentIdAndObjectIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleAssignmentId)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndRoleAssignmentIdAndObjectIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.RoleAssignmentId)]
        [ValidateNotNullOrEmpty]
        public string RoleAssignmentId { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.SignInName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.SignInName)]
        [Alias("Email", "UserPrincipalName")]
        [ValidateNotNullOrEmpty]
        public string SignInName { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndServicePrincipalNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.ServicePrincipalName)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndServicePrincipalNameParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.ServicePrincipalName)]
        [ValidateNotNullOrEmpty]
        public string ServicePrincipalName { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.PrincipalId)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.PrincipalId)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndRoleAssignmentIdAndObjectIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.PrincipalId)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndRoleAssignmentIdAndObjectIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.PrincipalId)]
        [Alias("Id", "PrincipalId")]
        [ValidateNotNullOrEmpty]
        public string ObjectId { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceNameAndIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.Scope)]
        [Parameter(ValueFromPipelineByPropertyName = false, ParameterSetName = NewByWorkspaceObjectAndIdParameterSet,
            Mandatory = true, HelpMessage = HelpMessages.Scope)]
        [ValidateNotNullOrEmpty]
        public string Scope { get; set; }

        [Parameter(Mandatory = false, HelpMessage = HelpMessages.AsJob)]
        public SwitchParameter AsJob { get; set; }

        public override void ExecuteCmdlet()
        {
            if (this.IsParameterBound(c => c.WorkspaceObject))
            {
                this.WorkspaceName = this.WorkspaceObject.Name;
            }

            if (this.IsParameterBound(c => c.RoleDefinitionName))
            {
                this.RoleDefinitionId = SynapseAnalyticsClient.GetRoleDefinitionIdFromRoleDefinitionName(this.RoleDefinitionName);
            }

            if (this.IsParameterBound(c => c.SignInName))
            {
                this.ObjectId = SynapseAnalyticsClient.GetObjectIdFromSignInName(this.SignInName);
            }

            if (this.IsParameterBound(c => c.ServicePrincipalName))
            {
                this.ObjectId = SynapseAnalyticsClient.GetObjectIdFromServicePrincipalName(this.ServicePrincipalName);
            }

            if (this.ShouldProcess(this.WorkspaceName, String.Format(Resources.CreatingSynapseRoleAssignment, this.WorkspaceName, this.RoleAssignmentId, this.ObjectId)))
            {
                PSRoleAssignmentDetails roleAssignmentDetails = new PSRoleAssignmentDetails(SynapseAnalyticsClient.CreateRoleAssignment(this.RoleAssignmentId, this.RoleDefinitionId, this.ObjectId,  this.Scope));
                WriteObject(roleAssignmentDetails);
            }
        }
    }
}
