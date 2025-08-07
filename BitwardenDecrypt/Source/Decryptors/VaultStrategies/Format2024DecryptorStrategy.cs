using System.Text.Json.Nodes;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core.VaultStrategies;

public class Format2024DecryptorStrategy(
    JsonNode rootNode,
    BitwardenSecrets secrets,
    CommandLineOptions options,
    VaultItemDecryptor vaultItemDecryptor) : IVaultDecryptorStrategy
{
    public JsonObject Decrypt()
    {
        JsonObject decryptedEntries = [];

        DecryptAndStoreOrganizationKeys();

        string[] groupsToProcess = ["folder_folders", "ciphers_ciphers", "collection_collections", "organizations_organizations"];

        foreach (string groupKey in groupsToProcess)
        {
            JsonObject? groupDataNode = rootNode[$"user_{options.AccountUuid}_{groupKey}"]?.AsObject();
            if (groupDataNode == null) continue;

            JsonArray itemsArray = [];
            foreach (var itemKvp in groupDataNode)
            {
                if (itemKvp.Value is JsonObject itemObj)
                {
                    itemsArray.Add(vaultItemDecryptor.ProcessGroupItem(itemObj.DeepClone()));
                }
                else if (itemKvp.Value is JsonArray itemArr)
                {
                    foreach (JsonNode? node in itemArr)
                    {
                        if (node is JsonObject obj)
                        {
                            itemsArray.Add(vaultItemDecryptor.ProcessGroupItem(obj.DeepClone()));
                        }
                    }
                }
            }
            string outputKey = groupKey.Replace("_folders", "s").Replace("ciphers_ciphers", "items").Replace("_collections", "s").Replace("_organizations", "s");
            decryptedEntries[outputKey] = itemsArray;
        }

        if (options.IncludeSends)
        {
            ProcessSends(decryptedEntries);
        }

        return decryptedEntries;
    }

    private void DecryptAndStoreOrganizationKeys()
    {
        if (rootNode[$"user_{options.AccountUuid}_crypto_organizationKeys"] is not JsonObject orgKeysNode || secrets.RsaPrivateKeyDer is null)
        {
            return;
        }

        foreach (KeyValuePair<string, JsonNode?> kvp in orgKeysNode)
        {
            string? orgKeyCipher = kvp.Value?["key"]?.GetValue<string>() ?? kvp.Value?.GetValue<string>();
            if (orgKeyCipher == null) continue;

            byte[]? decryptedOrgKey = vaultItemDecryptor.DecryptRsaInternal(orgKeyCipher);
            if (decryptedOrgKey != null) secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
        }
    }

    private void ProcessSends(JsonObject decryptedEntries)
    {
        if (rootNode[$"user_{options.AccountUuid}_encryptedSend_sendUserEncrypted"] is not JsonObject sendsDataNode)
        {
            return;
        }

        JsonArray sendsArray = [];
        foreach (KeyValuePair<string, JsonNode?> itemKvp in sendsDataNode)
        {
            if (itemKvp.Value is JsonObject itemObj)
            {
                sendsArray.Add(vaultItemDecryptor.DecryptSend(itemObj.DeepClone()));
            }
        }
        decryptedEntries["sends"] = sendsArray;
    }
}
