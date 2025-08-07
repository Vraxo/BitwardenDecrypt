using System.Text.Json.Nodes;
using BitwardenDecryptor.Models;
using BitwardenDecryptor.Utils;

namespace BitwardenDecryptor.Core;

public static class VaultFileParser
{
    private record KdfAndKeyParameters(string EmailOrSalt, int KdfIterations, int? KdfMemory, int? KdfParallelism, int KdfType, string ProtectedSymmKey, string? EncPrivateKey);

    public static VaultMetadata? Parse(JsonNode rootNode, string inputFile)
    {
        VaultMetadata? result = TryParseEncryptedJsonFormat(rootNode)
            ?? TryParse2024Format(rootNode, inputFile)
            ?? TryParseNewFormat(rootNode, inputFile)
            ?? TryParseOldFormat(rootNode);

        if (result is not null)
        {
            return result;
        }

        Console.Error.WriteLine("\nERROR: Could not determine the format of the provided JSON file or find any account data within it.");
        Console.Error.WriteLine("Please ensure this is a valid Bitwarden `data.json` export file.");
        Console.Error.WriteLine("The file may be in an unsupported format, corrupted, or not a Bitwarden export at all.");
        
        return null;
    }

    private static VaultMetadata? TryParseEncryptedJsonFormat(JsonNode rootNode)
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

    private static List<AccountInfo> Extract2024FormatAccounts(JsonObject accountsNode)
    {
        return accountsNode
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value != null && kvp.Value.AsObject().Count != 0)
            .Select(kvp => new AccountInfo(kvp.Key, kvp.Value!["email"]!.GetValue<string>()))
            .ToList();
    }

    private static KdfAndKeyParameters GetKdfAndKeyParametersFor2024Format(JsonNode rootNode, string accountUuid, string accountEmail)
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

    private static VaultMetadata? TryParse2024Format(JsonNode rootNode, string inputFile)
    {
        if (rootNode["global_account_accounts"] is not JsonObject accountsNode)
        {
            return null;
        }

        string fileFormat = "2024";
        List<AccountInfo> validAccounts = Extract2024FormatAccounts(accountsNode);

        AccountInfo? selectedAccount = AccountSelector.SelectAccount(validAccounts, inputFile);
        
        if (selectedAccount is null)
        {
            return null;
        }

        string selectedAccountUuid = selectedAccount.Uuid;
        string selectedAccountEmail = selectedAccount.Email;

        KdfAndKeyParameters kdfParams =
            GetKdfAndKeyParametersFor2024Format(rootNode, selectedAccountUuid, selectedAccountEmail);

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

    private static List<AccountInfo> ExtractNewFormatAccounts(JsonNode rootNode)
    {
        return rootNode.AsObject()
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value?["profile"]?["email"] != null)
            .Select(kvp => new AccountInfo(kvp.Key, kvp.Value!["profile"]!["email"]!.GetValue<string>()))
            .ToList();
    }

    private static KdfAndKeyParameters GetKdfAndKeyParametersForNewFormat(JsonNode rootNode, string accountUuid, string accountEmail)
    {
        JsonNode accountNode = rootNode[accountUuid]!;
        string emailOrSalt = accountEmail;
        JsonNode profileNode = accountNode["profile"]!;
        int kdfIterations = profileNode["kdfIterations"]!.GetValue<int>();
        int? kdfMemory = profileNode["kdfMemory"]?.GetValue<int>();
        int? kdfParallelism = profileNode["kdfParallelism"]?.GetValue<int>();
        int kdfType = profileNode["kdfType"]!.GetValue<int>();
        JsonNode keysNode = accountNode["keys"]!;
        string protectedSymmKey = keysNode["masterKeyEncryptedUserKey"]?.GetValue<string>() ?? keysNode["cryptoSymmetricKey"]!["encrypted"]!.GetValue<string>();
        string? encPrivateKey = keysNode["privateKey"]!["encrypted"]!.GetValue<string>();
        
        return new(
            emailOrSalt,
            kdfIterations,
            kdfMemory,
            kdfParallelism,
            kdfType,
            protectedSymmKey,
            encPrivateKey);
    }

    private static VaultMetadata? TryParseNewFormat(JsonNode rootNode, string inputFile)
    {
        List<AccountInfo> potentialNewFormatAccounts = ExtractNewFormatAccounts(rootNode);

        if (potentialNewFormatAccounts.Count == 0)
        {
            return null;
        }

        string fileFormat = "NEW";

        var selectedAccount = AccountSelector.SelectAccount(potentialNewFormatAccounts, inputFile);
        if (selectedAccount is null)
        {
            return null;
        }
        string selectedAccountUuid = selectedAccount.Uuid;
        string selectedAccountEmail = selectedAccount.Email;

        KdfAndKeyParameters kdfParams =
            GetKdfAndKeyParametersForNewFormat(rootNode, selectedAccountUuid, selectedAccountEmail);

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

    private static KdfAndKeyParameters GetKdfAndKeyParametersForOldFormat(JsonNode rootNode, string accountEmail)
    {
        string emailOrSalt = accountEmail;
        int kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
        int kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
        string protectedSymmKey = rootNode["encKey"]!.GetValue<string>();
        string? encPrivateKey = rootNode["encPrivateKey"]?.GetValue<string>();
        return new KdfAndKeyParameters(emailOrSalt, kdfIterations, null, null, kdfType, protectedSymmKey, encPrivateKey);
    }

    private static VaultMetadata? TryParseOldFormat(JsonNode rootNode)
    {
        if (rootNode["userEmail"] is null)
        {
            return null;
        }

        string fileFormat = "OLD";
        string accountUuid = rootNode["userId"]?.GetValue<string>() ?? string.Empty;
        string accountEmail = rootNode["userEmail"]!.GetValue<string>();

        KdfAndKeyParameters kdfParams =
            GetKdfAndKeyParametersForOldFormat(rootNode, accountEmail);

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
}