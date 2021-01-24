// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Models
{
    using static Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Runtime.Extensions;

    public partial class WindowsIotServicesIdentity :
        Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Models.IWindowsIotServicesIdentity,
        Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Models.IWindowsIotServicesIdentityInternal
    {

        /// <summary>Backing field for <see cref="DeviceName" /> property.</summary>
        private string _deviceName;

        /// <summary>The name of the Windows IoT Device Service.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Origin(Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.PropertyOrigin.Owned)]
        public string DeviceName { get => this._deviceName; set => this._deviceName = value; }

        /// <summary>Backing field for <see cref="Id" /> property.</summary>
        private string _id;

        /// <summary>Resource identity path</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Origin(Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.PropertyOrigin.Owned)]
        public string Id { get => this._id; set => this._id = value; }

        /// <summary>Backing field for <see cref="ResourceGroupName" /> property.</summary>
        private string _resourceGroupName;

        /// <summary>The name of the resource group that contains the Windows IoT Device Service.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Origin(Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.PropertyOrigin.Owned)]
        public string ResourceGroupName { get => this._resourceGroupName; set => this._resourceGroupName = value; }

        /// <summary>Backing field for <see cref="SubscriptionId" /> property.</summary>
        private string _subscriptionId;

        /// <summary>The subscription identifier.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Origin(Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.PropertyOrigin.Owned)]
        public string SubscriptionId { get => this._subscriptionId; set => this._subscriptionId = value; }

        /// <summary>Creates an new <see cref="WindowsIotServicesIdentity" /> instance.</summary>
        public WindowsIotServicesIdentity()
        {

        }
    }
    public partial interface IWindowsIotServicesIdentity :
        Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Runtime.IJsonSerializable
    {
        /// <summary>The name of the Windows IoT Device Service.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The name of the Windows IoT Device Service.",
        SerializedName = @"deviceName",
        PossibleTypes = new [] { typeof(string) })]
        string DeviceName { get; set; }
        /// <summary>Resource identity path</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"Resource identity path",
        SerializedName = @"id",
        PossibleTypes = new [] { typeof(string) })]
        string Id { get; set; }
        /// <summary>The name of the resource group that contains the Windows IoT Device Service.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The name of the resource group that contains the Windows IoT Device Service.",
        SerializedName = @"resourceGroupName",
        PossibleTypes = new [] { typeof(string) })]
        string ResourceGroupName { get; set; }
        /// <summary>The subscription identifier.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.WindowsIotServices.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The subscription identifier.",
        SerializedName = @"subscriptionId",
        PossibleTypes = new [] { typeof(string) })]
        string SubscriptionId { get; set; }

    }
    internal partial interface IWindowsIotServicesIdentityInternal

    {
        /// <summary>The name of the Windows IoT Device Service.</summary>
        string DeviceName { get; set; }
        /// <summary>Resource identity path</summary>
        string Id { get; set; }
        /// <summary>The name of the resource group that contains the Windows IoT Device Service.</summary>
        string ResourceGroupName { get; set; }
        /// <summary>The subscription identifier.</summary>
        string SubscriptionId { get; set; }

    }
}