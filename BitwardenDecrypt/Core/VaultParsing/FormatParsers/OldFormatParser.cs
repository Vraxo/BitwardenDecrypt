using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class OldFormatParser : IVaultFormatParser
{
    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        if (rootNode["userEmail"] is null)
        {
            return null;
        }

        string fileFormat = "OLD";
        string accountUuid = rootNode["userId"]?.GetValue<string>() ?? string.Empty;
        string accountEmail = rootNode["userEmail"]!.GetValue<string>();

        KdfParameters kdfParams = GetKdfParameters(rootNode, accountEmail);

        return new(
            fileFormat,
            kdfParams.EmailOrSalt,
            kdfParams.KdfIterations,
            kdfParams.KdfMemory,
            kdfParams.KdfParallelism,
            kdfParams.KdfType,
            kdfParams.ProtectedSymmetricKey,
            kdfParams.ProtectedRsaPrivateKey,
            accountEmail,
            accountUuid);
    }

    private static KdfParameters GetKdfParameters(JsonNode rootNode, string accountEmail)
    {
        string emailOrSalt = accountEmail;
        int kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
        int kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
        string protectedSymmKey = rootNode["encKey"]!.GetValue<string>();
        string? encPrivateKey = rootNode["encPrivateKey"]?.GetValue<string>();
        return new KdfParameters(emailOrSalt, kdfIterations, null, null, kdfType, protectedSymmKey, encPrivateKey);
    }
}