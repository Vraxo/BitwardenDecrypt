using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class Format2024Parser : IVaultFormatParser
{
    private record KdfAndKeyParameters(string EmailOrSalt, int KdfIterations, int? KdfMemory, int? KdfParallelism, int KdfType, string ProtectedSymmKey, string? EncPrivateKey);

    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        if (rootNode["global_account_accounts"] is not JsonObject accountsNode)
        {
            return null;
        }

        string fileFormat = "2024";
        List<AccountInfo> validAccounts = ExtractAccounts(accountsNode);

        AccountInfo? selectedAccount = accountSelector.SelectAccount(validAccounts, inputFile);

        if (selectedAccount is null)
        {
            return null;
        }

        string selectedAccountUuid = selectedAccount.Uuid;
        string selectedAccountEmail = selectedAccount.Email;

        KdfAndKeyParameters kdfParams = GetKdfAndKeyParameters(rootNode, selectedAccountUuid, selectedAccountEmail);

        return new(
            fileFormat,
            kdfParams.EmailOrSalt,
            kdfParams.KdfIterations,
            kdfParams.KdfMemory,
            kdfParams.KdfParallelism,
            kdfParams.KdfType,
            kdfParams.ProtectedSymmKey,
            kdfParams.EncPrivateKey,
            selectedAccountEmail,
            selectedAccountUuid);
    }

    private static List<AccountInfo> ExtractAccounts(JsonObject accountsNode)
    {
        return accountsNode
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value != null && kvp.Value.AsObject().Count != 0)
            .Select(kvp => new AccountInfo(kvp.Key, kvp.Value!["email"]!.GetValue<string>()))
            .ToList();
    }

    private static KdfAndKeyParameters GetKdfAndKeyParameters(JsonNode rootNode, string accountUuid, string accountEmail)
    {
        string emailOrSalt = accountEmail;
        JsonNode kdfConfigNode = rootNode[$"user_{accountUuid}_kdfConfig_kdfConfig"]!;
        int kdfIterations = kdfConfigNode["iterations"]!.GetValue<int>();
        int? kdfMemory = kdfConfigNode["memory"]?.GetValue<int>();
        int? kdfParallelism = kdfConfigNode["parallelism"]?.GetValue<int>();
        int kdfType = kdfConfigNode["kdfType"]!.GetValue<int>();
        string protectedSymmKey = rootNode[$"user_{accountUuid}_masterPassword_masterKeyEncryptedUserKey"]!.GetValue<string>();
        string? encPrivateKey = rootNode[$"user_{accountUuid}_crypto_privateKey"]?.GetValue<string>();

        return new(
            emailOrSalt,
            kdfIterations,
            kdfMemory,
            kdfParallelism,
            kdfType,
            protectedSymmKey,
            encPrivateKey);
    }
}
