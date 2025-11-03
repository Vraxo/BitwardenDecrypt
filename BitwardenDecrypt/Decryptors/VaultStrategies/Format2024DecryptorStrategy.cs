using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultStrategies;

public class Format2024DecryptorStrategy(
    JsonNode rootNode,
    BitwardenSecrets secrets,
    DecryptionContext context,
    VaultItemDecryptor vaultItemDecryptor) : IVaultDecryptorStrategy
{
    public JsonObject Decrypt()
    {
        JsonObject decryptedEntries = [];

        var orgKeysNode = rootNode[$"user_{context.AccountUuid}_crypto_organizationKeys"]?.AsObject();
        vaultItemDecryptor.DecryptAndStoreOrganizationKeys(orgKeysNode);

        string[] groupsToProcess = ["folder_folders", "ciphers_ciphers", "collection_collections", "organizations_organizations"];

        foreach (string groupKey in groupsToProcess)
        {
            JsonObject? groupDataNode = rootNode[$"user_{context.AccountUuid}_{groupKey}"]?.AsObject();
            if (groupDataNode is null)
            {
                continue;
            }

            JsonArray itemsArray = [];
            foreach (KeyValuePair<string, JsonNode?> itemKvp in groupDataNode)
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

        if (context.IncludeSends)
        {
            ProcessSends(decryptedEntries);
        }

        return decryptedEntries;
    }

    private void ProcessSends(JsonObject decryptedEntries)
    {
        if (rootNode[$"user_{context.AccountUuid}_encryptedSend_sendUserEncrypted"] is not JsonObject sendsDataNode)
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