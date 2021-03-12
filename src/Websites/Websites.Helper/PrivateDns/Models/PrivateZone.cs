// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.PowerShell.Cmdlets.Websites.Helper.PrivateDns.Models
{
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Describes a Private DNS zone.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class PrivateZone : TrackedResource
    {
        /// <summary>
        /// Initializes a new instance of the PrivateZone class.
        /// </summary>
        public PrivateZone()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the PrivateZone class.
        /// </summary>
        /// <param name="id">Fully qualified resource Id for the resource.
        /// Example -
        /// '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/privateDnsZones/{privateDnsZoneName}'.</param>
        /// <param name="name">The name of the resource</param>
        /// <param name="type">The type of the resource. Example -
        /// 'Microsoft.Network/privateDnsZones'.</param>
        /// <param name="tags">Resource tags.</param>
        /// <param name="location">The Azure Region where the resource
        /// lives</param>
        /// <param name="etag">The ETag of the zone.</param>
        /// <param name="maxNumberOfRecordSets">The maximum number of record
        /// sets that can be created in this Private DNS zone. This is a
        /// read-only property and any attempt to set this value will be
        /// ignored.</param>
        /// <param name="numberOfRecordSets">The current number of record sets
        /// in this Private DNS zone. This is a read-only property and any
        /// attempt to set this value will be ignored.</param>
        /// <param name="maxNumberOfVirtualNetworkLinks">The maximum number of
        /// virtual networks that can be linked to this Private DNS zone. This
        /// is a read-only property and any attempt to set this value will be
        /// ignored.</param>
        /// <param name="numberOfVirtualNetworkLinks">The current number of
        /// virtual networks that are linked to this Private DNS zone. This is
        /// a read-only property and any attempt to set this value will be
        /// ignored.</param>
        /// <param name="maxNumberOfVirtualNetworkLinksWithRegistration">The
        /// maximum number of virtual networks that can be linked to this
        /// Private DNS zone with registration enabled. This is a read-only
        /// property and any attempt to set this value will be ignored.</param>
        /// <param name="numberOfVirtualNetworkLinksWithRegistration">The
        /// current number of virtual networks that are linked to this Private
        /// DNS zone with registration enabled. This is a read-only property
        /// and any attempt to set this value will be ignored.</param>
        /// <param name="provisioningState">The provisioning state of the
        /// resource. This is a read-only property and any attempt to set this
        /// value will be ignored. Possible values include: 'Creating',
        /// 'Updating', 'Deleting', 'Succeeded', 'Failed', 'Canceled'</param>
        public PrivateZone(string id = default(string), string name = default(string), string type = default(string), IDictionary<string, string> tags = default(IDictionary<string, string>), string location = default(string), string etag = default(string), long? maxNumberOfRecordSets = default(long?), long? numberOfRecordSets = default(long?), long? maxNumberOfVirtualNetworkLinks = default(long?), long? numberOfVirtualNetworkLinks = default(long?), long? maxNumberOfVirtualNetworkLinksWithRegistration = default(long?), long? numberOfVirtualNetworkLinksWithRegistration = default(long?), string provisioningState = default(string))
            : base(id, name, type, tags, location)
        {
            Etag = etag;
            MaxNumberOfRecordSets = maxNumberOfRecordSets;
            NumberOfRecordSets = numberOfRecordSets;
            MaxNumberOfVirtualNetworkLinks = maxNumberOfVirtualNetworkLinks;
            NumberOfVirtualNetworkLinks = numberOfVirtualNetworkLinks;
            MaxNumberOfVirtualNetworkLinksWithRegistration = maxNumberOfVirtualNetworkLinksWithRegistration;
            NumberOfVirtualNetworkLinksWithRegistration = numberOfVirtualNetworkLinksWithRegistration;
            ProvisioningState = provisioningState;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the ETag of the zone.
        /// </summary>
        [JsonProperty(PropertyName = "etag")]
        public string Etag { get; set; }

        /// <summary>
        /// Gets the maximum number of record sets that can be created in this
        /// Private DNS zone. This is a read-only property and any attempt to
        /// set this value will be ignored.
        /// </summary>
        [JsonProperty(PropertyName = "properties.maxNumberOfRecordSets")]
        public long? MaxNumberOfRecordSets { get; private set; }

        /// <summary>
        /// Gets the current number of record sets in this Private DNS zone.
        /// This is a read-only property and any attempt to set this value will
        /// be ignored.
        /// </summary>
        [JsonProperty(PropertyName = "properties.numberOfRecordSets")]
        public long? NumberOfRecordSets { get; private set; }

        /// <summary>
        /// Gets the maximum number of virtual networks that can be linked to
        /// this Private DNS zone. This is a read-only property and any attempt
        /// to set this value will be ignored.
        /// </summary>
        [JsonProperty(PropertyName = "properties.maxNumberOfVirtualNetworkLinks")]
        public long? MaxNumberOfVirtualNetworkLinks { get; private set; }

        /// <summary>
        /// Gets the current number of virtual networks that are linked to this
        /// Private DNS zone. This is a read-only property and any attempt to
        /// set this value will be ignored.
        /// </summary>
        [JsonProperty(PropertyName = "properties.numberOfVirtualNetworkLinks")]
        public long? NumberOfVirtualNetworkLinks { get; private set; }

        /// <summary>
        /// Gets the maximum number of virtual networks that can be linked to
        /// this Private DNS zone with registration enabled. This is a
        /// read-only property and any attempt to set this value will be
        /// ignored.
        /// </summary>
        [JsonProperty(PropertyName = "properties.maxNumberOfVirtualNetworkLinksWithRegistration")]
        public long? MaxNumberOfVirtualNetworkLinksWithRegistration { get; private set; }

        /// <summary>
        /// Gets the current number of virtual networks that are linked to this
        /// Private DNS zone with registration enabled. This is a read-only
        /// property and any attempt to set this value will be ignored.
        /// </summary>
        [JsonProperty(PropertyName = "properties.numberOfVirtualNetworkLinksWithRegistration")]
        public long? NumberOfVirtualNetworkLinksWithRegistration { get; private set; }

        /// <summary>
        /// Gets the provisioning state of the resource. This is a read-only
        /// property and any attempt to set this value will be ignored.
        /// Possible values include: 'Creating', 'Updating', 'Deleting',
        /// 'Succeeded', 'Failed', 'Canceled'
        /// </summary>
        [JsonProperty(PropertyName = "properties.provisioningState")]
        public string ProvisioningState { get; private set; }

    }
}
