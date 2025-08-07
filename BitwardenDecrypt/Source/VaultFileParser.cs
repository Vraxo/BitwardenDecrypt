using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class VaultFileParser
{
    public static VaultFileParseResult ParseAndExtractParameters(JsonNode rootNode, CommandLineOptions options)
    {
        VaultFileParseResult? result;

        result = TryParseEncryptedJsonFormat(rootNode, options);

        if (result is not null)
        {
            return result;
        }

        result = TryParse2024Format(rootNode, options);

        if (result is not null)
        {
            return result;
        }

        result = TryParseNewFormat(rootNode, options);

        if (result is not null)
        {
            return result;
        }

        result = TryParseOldFormat(rootNode, options);

        if (result is not null)
        {
            return result;
        }

        Console.Error.WriteLine("\nERROR: Could not determine the format of the provided JSON file or find any account data within it.");
        Console.Error.WriteLine("Please ensure this is a valid Bitwarden `data.json` export file.");
        Console.Error.WriteLine("The file may be in an unsupported format, corrupted, or not a Bitwarden export at all.");

        return new(false);
    }

    private static VaultFileParseResult? TryParseEncryptedJsonFormat(JsonNode rootNode, CommandLineOptions options)
    {
        if (rootNode["encrypted"]?.GetValue<bool>() != true || rootNode["passwordProtected"]?.GetValue<bool>() != true)
        {
            return null;
        }

        options.FileFormat = "EncryptedJSON";
        string emailOrSalt = rootNode["salt"]!.GetValue<string>();
        int kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
        int kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
        string protectedSymmKeyOrValidation = rootNode["encKeyValidation_DO_NOT_EDIT"]!.GetValue<string>();

        return new(true, emailOrSalt, kdfIterations, null, null, kdfType, protectedSymmKeyOrValidation, null);
    }

    private static List<(string uuid, string email)> Extract2024FormatAccounts(JsonObject accountsNode)
    {
        return accountsNode
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value != null && kvp.Value.AsObject().Count != 0)
            .Select(kvp => (uuid: kvp.Key, email: kvp.Value!["email"]!.GetValue<string>()))
            .ToList();
    }

    private static (string emailOrSalt, int kdfIterations, int? kdfMemory, int? kdfParallelism, int kdfType, string protectedSymmKey, string? encPrivateKey) GetKdfAndKeyParametersFor2024Format(JsonNode rootNode, string accountUuid, string accountEmail)
    {
        string emailOrSalt = accountEmail;
        JsonNode kdfConfigNode = rootNode[$"user_{accountUuid}_kdfConfig_kdfConfig"]!;
        int kdfIterations = kdfConfigNode["iterations"]!.GetValue<int>();
        int? kdfMemory = kdfConfigNode["memory"]?.GetValue<int>();
        int? kdfParallelism = kdfConfigNode["parallelism"]?.GetValue<int>();
        int kdfType = kdfConfigNode["kdfType"]!.GetValue<int>();
        string protectedSymmKey = rootNode[$"user_{accountUuid}_masterPassword_masterKeyEncryptedUserKey"]!.GetValue<string>();
        string? encPrivateKey = rootNode[$"user_{accountUuid}_crypto_privateKey"]?.GetValue<string>();
        return (emailOrSalt, kdfIterations, kdfMemory, kdfParallelism, kdfType, protectedSymmKey, encPrivateKey);
    }

    private static VaultFileParseResult? TryParse2024Format(JsonNode rootNode, CommandLineOptions options)
    {
        if (rootNode["global_account_accounts"] is not JsonObject accountsNode)
        {
            return null;
        }

        options.FileFormat = "2024";
        List<(string uuid, string email)> validAccounts = Extract2024FormatAccounts(accountsNode);

        if (!SelectAccount(validAccounts, options.InputFile, out var selectedAccountUuid, out var selectedAccountEmail))
        {
            return new(false);
        }

        options.AccountUuid = selectedAccountUuid;
        options.AccountEmail = selectedAccountEmail;

        var (emailOrSalt, kdfIterations, kdfMemory, kdfParallelism, kdfType, protectedSymmKey, encPrivateKey) =
            GetKdfAndKeyParametersFor2024Format(rootNode, options.AccountUuid, options.AccountEmail);

        return new(true, emailOrSalt, kdfIterations, kdfMemory, kdfParallelism, kdfType, protectedSymmKey, encPrivateKey);
    }

    private static List<(string uuid, string email)> ExtractNewFormatAccounts(JsonNode rootNode)
    {
        return rootNode.AsObject()
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value?["profile"]?["email"] != null)
            .Select(kvp => (uuid: kvp.Key, email: kvp.Value!["profile"]!["email"]!.GetValue<string>()))
            .ToList();
    }

    private static (string emailOrSalt, int kdfIterations, int? kdfMemory, int? kdfParallelism, int kdfType, string protectedSymmKey, string? encPrivateKey) GetKdfAndKeyParametersForNewFormat(JsonNode rootNode, string accountUuid, string accountEmail)
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
        return (emailOrSalt, kdfIterations, kdfMemory, kdfParallelism, kdfType, protectedSymmKey, encPrivateKey);
    }

    private static VaultFileParseResult? TryParseNewFormat(JsonNode rootNode, CommandLineOptions options)
    {
        List<(string uuid, string email)> potentialNewFormatAccounts = ExtractNewFormatAccounts(rootNode);

        if (potentialNewFormatAccounts.Count == 0)
        {
            return null;
        }

        options.FileFormat = "NEW";

        if (!SelectAccount(potentialNewFormatAccounts, options.InputFile, out var selectedAccountUuid, out var selectedAccountEmail))
        {
            return new(false);
        }

        options.AccountUuid = selectedAccountUuid;
        options.AccountEmail = selectedAccountEmail;

        var (emailOrSalt, kdfIterations, kdfMemory, kdfParallelism, kdfType, protectedSymmKey, encPrivateKey) =
            GetKdfAndKeyParametersForNewFormat(rootNode, options.AccountUuid, options.AccountEmail);

        return new(true, emailOrSalt, kdfIterations, kdfMemory, kdfParallelism, kdfType, protectedSymmKey, encPrivateKey);
    }

    private static (string emailOrSalt, int kdfIterations, int? kdfMemory, int? kdfParallelism, int kdfType, string protectedSymmKey, string? encPrivateKey) GetKdfAndKeyParametersForOldFormat(JsonNode rootNode, string accountEmail)
    {
        string emailOrSalt = accountEmail;
        int kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
        int kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
        string protectedSymmKey = rootNode["encKey"]!.GetValue<string>();
        string? encPrivateKey = rootNode["encPrivateKey"]?.GetValue<string>();
        return (emailOrSalt, kdfIterations, null, null, kdfType, protectedSymmKey, encPrivateKey);
    }

    private static VaultFileParseResult? TryParseOldFormat(JsonNode rootNode, CommandLineOptions options)
    {
        if (rootNode["userEmail"] is null)
        {
            return null;
        }

        options.FileFormat = "OLD";
        options.AccountUuid = rootNode["userId"]?.GetValue<string>() ?? string.Empty;
        options.AccountEmail = rootNode["userEmail"]!.GetValue<string>();

        (string emailOrSalt, int kdfIterations, int? kdfMemory, int? kdfParallelism, int kdfType, string protectedSymmKey, string encPrivateKey) =
            GetKdfAndKeyParametersForOldFormat(rootNode, options.AccountEmail);

        return new(true, emailOrSalt, kdfIterations, kdfMemory, kdfParallelism, kdfType, protectedSymmKey, encPrivateKey);
    }

    private static bool SelectAccount(List<(string uuid, string email)> accounts, string inputFile, out string selectedUuid, out string selectedEmail)
    {
        selectedUuid = string.Empty;
        selectedEmail = string.Empty;

        if (accounts.Count == 0)
        {
            Console.Error.WriteLine($"ERROR: No Accounts Found In {inputFile}");
            return false;
        }

        if (accounts.Count == 1)
        {
            selectedUuid = accounts[0].uuid;
            selectedEmail = accounts[0].email;
            return true;
        }

        Console.WriteLine("Which Account Would You Like To Decrypt?");

        for (int i = 0; i < accounts.Count; i++)
        {
            Console.WriteLine($" {i + 1}:\t{accounts[i].email}");
        }

        int choice = 0;

        Console.WriteLine();

        while (choice < 1 || choice > accounts.Count)
        {
            Console.Write("Enter Number: ");

            if (int.TryParse(Console.ReadLine(), out choice))
            {
                continue;
            }

            choice = 0;
        }

        Console.WriteLine();

        selectedUuid = accounts[choice - 1].uuid;
        selectedEmail = accounts[choice - 1].email;
        return true;
    }
}
