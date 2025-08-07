using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing;

public class VaultParser
{
    private readonly IEnumerable<IVaultFormatParser> _parsers;

    public VaultParser(IEnumerable<IVaultFormatParser> parsers)
    {
        _parsers = parsers;
    }

    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        foreach (var parser in _parsers)
        {
            var result = parser.Parse(rootNode, accountSelector, inputFile);
            if (result is not null)
            {
                return result;
            }
        }

        Console.Error.WriteLine("\nERROR: Could not determine the format of the provided JSON file or find any account data within it.");
        Console.Error.WriteLine("Please ensure this is a valid Bitwarden `data.json` export file.");
        Console.Error.WriteLine("The file may be in an unsupported format, corrupted, or not a Bitwarden export at all.");
        
        return null;
    }
}
