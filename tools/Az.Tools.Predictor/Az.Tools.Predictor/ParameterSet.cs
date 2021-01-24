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

using Microsoft.Azure.PowerShell.Tools.AzPredictor.Utilities;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Language;

namespace Microsoft.Azure.PowerShell.Tools.AzPredictor
{
    /// <summary>
    /// Treating parameter lists as sets of parameters to show that parameter order
    /// does not matter to resulting prediction - the prediction should adapt to the
    /// order of the parameters typed by the user.
    /// </summary>
    sealed class ParameterSet
    {
        /// <summary>
        /// Gets the list of the parameters with their names and values.
        /// </summary>
        public IReadOnlyList<Parameter> Parameters { get; }

        public ParameterSet(CommandAst commandAst)
        {
            Validation.CheckArgument(commandAst, $"{nameof(commandAst)} cannot be null.");

            var parameters = new List<Parameter>();
            var elements = commandAst.CommandElements.Skip(1);
            CommandParameterAst param = null;
            Ast arg = null;
            foreach (Ast elem in elements)
            {
                if (elem is CommandParameterAst p)
                {
                    AddParameter(param, arg);
                    param = p;
                    arg = null;
                }
                else if (AzPredictorConstants.ParameterIndicator == elem?.ToString().Trim().FirstOrDefault())
                {
                    // We have an incomplete command line such as
                    // `New-AzResourceGroup -Name ResourceGroup01 -Location WestUS -`
                    // We'll ignore the incomplete parameter.
                    AddParameter(param, arg);
                    param = null;
                    arg = null;
                }
                else
                {
                    arg = elem;
                }
            }

            Validation.CheckInvariant((param != null) || (arg == null));

            AddParameter(param, arg);

            Parameters = parameters;

            void AddParameter(CommandParameterAst parameterName, Ast parameterValue)
            {
                if (parameterName != null)
                {
                    parameters.Add(new Parameter(parameterName.ParameterName, (parameterValue == null) ? null : CommandLineUtilities.UnescapePredictionText(parameterValue.ToString())));
                }
            }
        }
    }
}
