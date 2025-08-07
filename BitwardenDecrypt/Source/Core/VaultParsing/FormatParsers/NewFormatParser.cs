using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class NewFormatParser : IVaultFormatParser
{
    private record KdfAndKeyParameters(string EmailOrSalt, int KdfIterations, int? KdfMemory, int? KdfParallelism, int KdfType, string ProtectedSymmKey, string? EncPrivateKey);
    
    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        List<AccountInfo> potentialNewFormatAccounts = ExtractAccounts(rootNode);

        if (potentialNewFormatAccounts.Count == 0)
        {
            return null;
        }

        string fileFormat = "NEW";

        var selectedAccount = accountSelector.SelectAccount(potentialNewFormatAccounts, inputFile);
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
    
    private static List<AccountInfo> ExtractAccounts(JsonNode rootNode)
    {
        return rootNode.AsObject()
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value?["profile"]?["email"] != null)
            .Select(kvp => new AccountInfo(kvp.Key, kvp.Value!["profile"]!["email"]!.GetValue<string>()))
            .ToList();
    }

    private static KdfAndKeyParameters GetKdfAndKeyParameters(JsonNode rootNode, string accountUuid, string accountEmail)
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
}
