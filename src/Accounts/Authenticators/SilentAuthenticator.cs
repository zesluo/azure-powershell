﻿// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;

using Azure.Core;
using Azure.Identity;

using Microsoft.Azure.Commands.Common.Authentication;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;

namespace Microsoft.Azure.PowerShell.Authenticators
{
    public class SilentAuthenticator : DelegatingAuthenticator
    {
        public override Task<IAccessToken> Authenticate(AuthenticationParameters parameters, CancellationToken cancellationToken)
        {
            var silentParameters = parameters as SilentParameters;
            var onPremise = silentParameters.Environment.OnPremise;
            var tenantId = onPremise ? AdfsTenant : silentParameters.TenantId;
            var resource = silentParameters.Environment.GetEndpoint(silentParameters.ResourceId) ?? silentParameters.ResourceId;
            var scopes = AuthenticationHelpers.GetScope(onPremise, resource);
            var authority = onPremise ?
                                silentParameters.Environment.ActiveDirectoryAuthority :
                                AuthenticationHelpers.GetAuthority(silentParameters.Environment, silentParameters.TenantId);

            //TODO: Modify SharedTokenCacheCredentialOptions to accept clientId?
            var options = new SharedTokenCacheCredentialOptions()
            {
                Username = silentParameters.UserId,
                AuthorityHost = new Uri(authority),
                //ClientId = AuthenticationHelpers.PowerShellClientId,
                TenantId = tenantId,
                //AllowUnencryptedCache = true
            };

            var cacheCredential = new SharedTokenCacheCredential(options);
            var requestContext = new TokenRequestContext(scopes);
            var tokenTask = cacheCredential.GetTokenAsync(requestContext);
            return MsalAccessToken.GetAccessTokenAsync(tokenTask, silentParameters.TenantId, silentParameters.UserId, silentParameters.HomeAccountId);
        }

        public override bool CanAuthenticate(AuthenticationParameters parameters)
        {
            return (parameters as SilentParameters) != null;
        }
    }
}
