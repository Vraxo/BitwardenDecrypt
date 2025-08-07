using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class OldFormatParser : IVaultFormatParser
{
    private record KdfAndKeyParameters(string EmailOrSalt, int KdfIterations, int? KdfMemory, int? KdfParallelism, int KdfType, string ProtectedSymmKey, string? EncPrivateKey);

    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        if (rootNode["userEmail"] is null)
        {
            return null;
        }

        string fileFormat = "OLD";
        string accountUuid = rootNode["userId"]?.GetValue<string>() ?? string.Empty;
        string accountEmail = rootNode["userEmail"]!.GetValue<string>();

        KdfAndKeyParameters kdfParams = GetKdfAndKeyParameters(rootNode, accountEmail);

        return new(
            fileFormat,
            kdfParams.EmailOrSalt,
            kdfParams.KdfIterations,
            kdfParams.KdfMemory,
            kdfParams.KdfParallelism,
            kdfParams.KdfType,
            kdfParams.ProtectedSymmKey,
            kdfParams.EncPrivateKey,
            accountEmail,
            accountUuid);
    }
    
    private static KdfAndKeyParameters GetKdfAndKeyParameters(JsonNode rootNode, string accountEmail)
    {
        string emailOrSalt = accountEmail;
        int kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
        int kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
        string protectedSymmKey = rootNode["encKey"]!.GetValue<string>();
        string? encPrivateKey = rootNode["encPrivateKey"]?.GetValue<string>();
        return new KdfAndKeyParameters(emailOrSalt, kdfIterations, null, null, kdfType, protectedSymmKey, encPrivateKey);
    }
}
