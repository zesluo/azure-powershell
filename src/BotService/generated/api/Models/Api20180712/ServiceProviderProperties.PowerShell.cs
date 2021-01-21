namespace Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712
{
    using Microsoft.Azure.PowerShell.Cmdlets.BotService.Runtime.PowerShell;

    /// <summary>The Object used to describe a Service Provider supported by Bot Service</summary>
    [System.ComponentModel.TypeConverter(typeof(ServiceProviderPropertiesTypeConverter))]
    public partial class ServiceProviderProperties
    {

        /// <summary>
        /// <c>AfterDeserializeDictionary</c> will be called after the deserialization has finished, allowing customization of the
        /// object before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>

        partial void AfterDeserializeDictionary(global::System.Collections.IDictionary content);

        /// <summary>
        /// <c>AfterDeserializePSObject</c> will be called after the deserialization has finished, allowing customization of the object
        /// before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>

        partial void AfterDeserializePSObject(global::System.Management.Automation.PSObject content);

        /// <summary>
        /// <c>BeforeDeserializeDictionary</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <see "returnNow" /> output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializeDictionary(global::System.Collections.IDictionary content, ref bool returnNow);

        /// <summary>
        /// <c>BeforeDeserializePSObject</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <see "returnNow" /> output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializePSObject(global::System.Management.Automation.PSObject content, ref bool returnNow);

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.ServiceProviderProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderProperties"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderProperties DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new ServiceProviderProperties(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.ServiceProviderProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderProperties"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderProperties DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new ServiceProviderProperties(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="ServiceProviderProperties" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="className" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderProperties FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.BotService.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.ServiceProviderProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal ServiceProviderProperties(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).Id = (string) content.GetValueForProperty("Id",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).Id, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).DisplayName = (string) content.GetValueForProperty("DisplayName",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).DisplayName, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).ServiceProviderName = (string) content.GetValueForProperty("ServiceProviderName",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).ServiceProviderName, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).DevPortalUrl = (string) content.GetValueForProperty("DevPortalUrl",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).DevPortalUrl, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).IconUrl = (string) content.GetValueForProperty("IconUrl",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).IconUrl, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).Parameter = (Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderParameter[]) content.GetValueForProperty("Parameter",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).Parameter, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderParameter>(__y, Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.ServiceProviderParameterTypeConverter.ConvertFrom));
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.ServiceProviderProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal ServiceProviderProperties(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).Id = (string) content.GetValueForProperty("Id",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).Id, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).DisplayName = (string) content.GetValueForProperty("DisplayName",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).DisplayName, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).ServiceProviderName = (string) content.GetValueForProperty("ServiceProviderName",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).ServiceProviderName, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).DevPortalUrl = (string) content.GetValueForProperty("DevPortalUrl",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).DevPortalUrl, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).IconUrl = (string) content.GetValueForProperty("IconUrl",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).IconUrl, global::System.Convert.ToString);
            ((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).Parameter = (Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderParameter[]) content.GetValueForProperty("Parameter",((Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderPropertiesInternal)this).Parameter, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.IServiceProviderParameter>(__y, Microsoft.Azure.PowerShell.Cmdlets.BotService.Models.Api20180712.ServiceProviderParameterTypeConverter.ConvertFrom));
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.BotService.Runtime.SerializationMode.IncludeAll)?.ToString();
    }
    /// The Object used to describe a Service Provider supported by Bot Service
    [System.ComponentModel.TypeConverter(typeof(ServiceProviderPropertiesTypeConverter))]
    public partial interface IServiceProviderProperties

    {

    }
}