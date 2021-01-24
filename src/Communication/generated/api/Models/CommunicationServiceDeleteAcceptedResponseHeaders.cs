// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Communication.Models
{
    using static Microsoft.Azure.PowerShell.Cmdlets.Communication.Runtime.Extensions;

    public partial class CommunicationServiceDeleteAcceptedResponseHeaders :
        Microsoft.Azure.PowerShell.Cmdlets.Communication.Models.ICommunicationServiceDeleteAcceptedResponseHeaders,
        Microsoft.Azure.PowerShell.Cmdlets.Communication.Models.ICommunicationServiceDeleteAcceptedResponseHeadersInternal,
        Microsoft.Azure.PowerShell.Cmdlets.Communication.Runtime.IHeaderSerializable
    {

        /// <summary>Backing field for <see cref="Location" /> property.</summary>
        private string _location;

        [Microsoft.Azure.PowerShell.Cmdlets.Communication.Origin(Microsoft.Azure.PowerShell.Cmdlets.Communication.PropertyOrigin.Owned)]
        public string Location { get => this._location; set => this._location = value; }

        /// <summary>
        /// Creates an new <see cref="CommunicationServiceDeleteAcceptedResponseHeaders" /> instance.
        /// </summary>
        public CommunicationServiceDeleteAcceptedResponseHeaders()
        {

        }

        /// <param name="headers"></param>
        void Microsoft.Azure.PowerShell.Cmdlets.Communication.Runtime.IHeaderSerializable.ReadHeaders(global::System.Net.Http.Headers.HttpResponseHeaders headers)
        {
            if (headers.TryGetValues("location", out var __locationHeader))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Communication.Models.ICommunicationServiceDeleteAcceptedResponseHeadersInternal)this).Location = System.Linq.Enumerable.FirstOrDefault(__locationHeader) is string __headerLocationHeader ? __headerLocationHeader : (string)null;
            }
        }
    }
    public partial interface ICommunicationServiceDeleteAcceptedResponseHeaders

    {
        [Microsoft.Azure.PowerShell.Cmdlets.Communication.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"",
        SerializedName = @"location",
        PossibleTypes = new [] { typeof(string) })]
        string Location { get; set; }

    }
    internal partial interface ICommunicationServiceDeleteAcceptedResponseHeadersInternal

    {
        string Location { get; set; }

    }
}