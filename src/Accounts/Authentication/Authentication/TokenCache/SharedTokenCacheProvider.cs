﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;

namespace Microsoft.Azure.Commands.Common.Authentication
{
    public class SharedTokenCacheProvider : PowerShellTokenCacheProvider
    {
        private static MsalCacheHelper _helper;
        private static readonly object _lock = new object();

        public override Task<byte[]> ReadAsync()
        {
            throw new NotImplementedException();
        }

        public override Task WriteAsync(byte[] bytes)
        {
            throw new NotImplementedException();
        }

        public override byte[] ReadTokenData()
        {
            return GetCacheHelper(PowerShellClientId).LoadUnencryptedTokenCache();
        }

        public override void FlushTokenData()
        {
            GetCacheHelper(PowerShellClientId).SaveUnencryptedTokenCache(_tokenCacheDataToFlush);
            base.FlushTokenData();
        }

        /// <summary>
        /// Check if current environment support token cache persistence
        /// </summary>
        /// <returns></returns>
        public static bool SupportCachePersistence(out string message)
        {
            try
            {
                var cacheHelper = GetCacheHelper(PowerShellClientId);
                cacheHelper.VerifyPersistence();
            }
            catch (MsalCachePersistenceException e)
            {
                message = e.Message;
                return false;
            }
            message = null;
            return true;
        }

        protected override void RegisterCache(IPublicClientApplication client)
        {
            var cacheHelper = GetCacheHelper(client.AppConfig.ClientId);
            cacheHelper.RegisterCache(client.UserTokenCache);
        }

        private static MsalCacheHelper GetCacheHelper(String clientId)
        {
            if (_helper != null)
            {
                return _helper;
            }
            lock (_lock)
            {
                // Double check helper existence
                if (_helper == null)
                {
                    _helper = CreateCacheHelper(clientId);
                }
                return _helper;
            }
        }

        private static MsalCacheHelper CreateCacheHelper(string clientId)
        {
            var cacheDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), ".IdentityService");
            StorageCreationProperties storageProperties = new StorageCreationPropertiesBuilder("msal.cache", cacheDirectory, clientId)
                .WithMacKeyChain("Microsoft.Developer.IdentityService", "MSALCache")
                .WithLinuxKeyring("msal.cache", "default", "MSALCache",
                new KeyValuePair<string, string>("MsalClientID", null),
                new KeyValuePair<string, string>("Microsoft.Developer.IdentityService", null))
                .Build();

            return MsalCacheHelper.CreateAsync(storageProperties).ConfigureAwait(false).GetAwaiter().GetResult(); ;
        }
    }
}
