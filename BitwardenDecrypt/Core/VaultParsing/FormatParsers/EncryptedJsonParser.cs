using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class EncryptedJsonParser : IVaultFormatParser
{
    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        if (rootNode["encrypted"]?.GetValue<bool>() != true || rootNode["passwordProtected"]?.GetValue<bool>() != true)
        {
            return null;
        }

        string fileFormat = "EncryptedJSON";
        string emailOrSalt = rootNode["salt"]!.GetValue<string>();
        int kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
        int kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
        string protectedSymmKeyOrValidation = rootNode["encKeyValidation_DO_NOT_EDIT"]!.GetValue<string>();

        return new(
            fileFormat,
            emailOrSalt,
            kdfIterations,
            null,
            null,
            kdfType,
            protectedSymmKeyOrValidation,
            null);
    }
}
