using BitwardenDecryptor.Exceptions;
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
        foreach (IVaultFormatParser parser in _parsers)
        {
            VaultMetadata? result = parser.Parse(rootNode, accountSelector, inputFile);
            if (result is not null)
            {
                return result;
            }
        }

        throw new VaultFormatException(
            "Could not determine the format of the provided JSON file or find any account data within it.\n" +
            "Please ensure this is a valid Bitwarden `data.json` export file.\n" +
            "The file may be in an unsupported format, corrupted, or not a Bitwarden export at all."
        );
    }
}