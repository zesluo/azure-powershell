// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support
{

    /// <summary>Disk mode property used for identifying independent disks.</summary>
    [System.ComponentModel.TypeConverter(typeof(Microsoft.Azure.PowerShell.Cmdlets.Migrate.Support.VirtualDiskModeTypeConverter))]
    public partial struct VirtualDiskMode :
        System.Management.Automation.IArgumentCompleter
    {

        /// <summary>
        /// Implementations of this function are called by PowerShell to complete arguments.
        /// </summary>
        /// <param name="commandName">The name of the command that needs argument completion.</param>
        /// <param name="parameterName">The name of the parameter that needs argument completion.</param>
        /// <param name="wordToComplete">The (possibly empty) word being completed.</param>
        /// <param name="commandAst">The command ast in case it is needed for completion.</param>
        /// <param name="fakeBoundParameters">This parameter is similar to $PSBoundParameters, except that sometimes PowerShell cannot
        /// or will not attempt to evaluate an argument, in which case you may need to use commandAst.</param>
        /// <returns>
        /// A collection of completion results, most like with ResultType set to ParameterValue.
        /// </returns>
        public global::System.Collections.Generic.IEnumerable<global::System.Management.Automation.CompletionResult> CompleteArgument(global::System.String commandName, global::System.String parameterName, global::System.String wordToComplete, global::System.Management.Automation.Language.CommandAst commandAst, global::System.Collections.IDictionary fakeBoundParameters)
        {
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "persistent".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("persistent", "persistent", global::System.Management.Automation.CompletionResultType.ParameterValue, "persistent");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "independent_persistent".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("independent_persistent", "independent_persistent", global::System.Management.Automation.CompletionResultType.ParameterValue, "independent_persistent");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "independent_nonpersistent".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("independent_nonpersistent", "independent_nonpersistent", global::System.Management.Automation.CompletionResultType.ParameterValue, "independent_nonpersistent");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "nonpersistent".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("nonpersistent", "nonpersistent", global::System.Management.Automation.CompletionResultType.ParameterValue, "nonpersistent");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "undoable".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("undoable", "undoable", global::System.Management.Automation.CompletionResultType.ParameterValue, "undoable");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "append".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("append", "append", global::System.Management.Automation.CompletionResultType.ParameterValue, "append");
            }
        }
    }
}