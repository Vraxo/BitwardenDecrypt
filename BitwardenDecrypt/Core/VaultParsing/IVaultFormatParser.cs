using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing;

public interface IVaultFormatParser
{
    VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile);
}
