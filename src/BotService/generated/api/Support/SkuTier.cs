// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.BotService.Support
{

    /// <summary>Gets the sku tier. This is based on the SKU name.</summary>
    public partial struct SkuTier :
        System.IEquatable<SkuTier>
    {
        public static Microsoft.Azure.PowerShell.Cmdlets.BotService.Support.SkuTier Free = @"Free";

        public static Microsoft.Azure.PowerShell.Cmdlets.BotService.Support.SkuTier Standard = @"Standard";

        /// <summary>the value for an instance of the <see cref="SkuTier" /> Enum.</summary>
        private string _value { get; set; }

        /// <summary>Conversion from arbitrary object to SkuTier</summary>
        /// <param name="value">the value to convert to an instance of <see cref="SkuTier" />.</param>
        internal static object CreateFrom(object value)
        {
            return new SkuTier(System.Convert.ToString(value));
        }

        /// <summary>Compares values of enum type SkuTier</summary>
        /// <param name="e">the value to compare against this instance.</param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public bool Equals(Microsoft.Azure.PowerShell.Cmdlets.BotService.Support.SkuTier e)
        {
            return _value.Equals(e._value);
        }

        /// <summary>Compares values of enum type SkuTier (override for Object)</summary>
        /// <param name="obj">the value to compare against this instance.</param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public override bool Equals(object obj)
        {
            return obj is SkuTier && Equals((SkuTier)obj);
        }

        /// <summary>Returns hashCode for enum SkuTier</summary>
        /// <returns>The hashCode of the value</returns>
        public override int GetHashCode()
        {
            return this._value.GetHashCode();
        }

        /// <summary>Creates an instance of the <see cref="SkuTier" Enum class./></summary>
        /// <param name="underlyingValue">the value to create an instance for.</param>
        private SkuTier(string underlyingValue)
        {
            this._value = underlyingValue;
        }

        /// <summary>Returns string representation for SkuTier</summary>
        /// <returns>A string for this value.</returns>
        public override string ToString()
        {
            return this._value;
        }

        /// <summary>Implicit operator to convert string to SkuTier</summary>
        /// <param name="value">the value to convert to an instance of <see cref="SkuTier" />.</param>

        public static implicit operator SkuTier(string value)
        {
            return new SkuTier(value);
        }

        /// <summary>Implicit operator to convert SkuTier to string</summary>
        /// <param name="e">the value to convert to an instance of <see cref="SkuTier" />.</param>

        public static implicit operator string(Microsoft.Azure.PowerShell.Cmdlets.BotService.Support.SkuTier e)
        {
            return e._value;
        }

        /// <summary>Overriding != operator for enum SkuTier</summary>
        /// <param name="e1">the value to compare against <see cref="e2" /></param>
        /// <param name="e2">the value to compare against <see cref="e1" /></param>
        /// <returns><c>true</c> if the two instances are not equal to the same value</returns>
        public static bool operator !=(Microsoft.Azure.PowerShell.Cmdlets.BotService.Support.SkuTier e1, Microsoft.Azure.PowerShell.Cmdlets.BotService.Support.SkuTier e2)
        {
            return !e2.Equals(e1);
        }

        /// <summary>Overriding == operator for enum SkuTier</summary>
        /// <param name="e1">the value to compare against <see cref="e2" /></param>
        /// <param name="e2">the value to compare against <see cref="e1" /></param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public static bool operator ==(Microsoft.Azure.PowerShell.Cmdlets.BotService.Support.SkuTier e1, Microsoft.Azure.PowerShell.Cmdlets.BotService.Support.SkuTier e2)
        {
            return e2.Equals(e1);
        }
    }
}