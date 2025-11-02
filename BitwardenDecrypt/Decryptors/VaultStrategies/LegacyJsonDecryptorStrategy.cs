using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultStrategies;

public class LegacyJsonDecryptorStrategy(
    JsonNode rootNode,
    BitwardenSecrets secrets,
    DecryptionContext context,
    VaultItemDecryptor vaultItemDecryptor) : IVaultDecryptorStrategy
{
    public JsonObject Decrypt()
    {
        JsonNode accountNode;
        if (context.FileFormat == "NEW")
        {
            accountNode = rootNode[context.AccountUuid!]!;
            DecryptAndStoreOrganizationKeys(accountNode["keys"]?["organizationKeys"]?["encrypted"]?.AsObject());
        }
        else // OLD format
        {
            accountNode = rootNode;
            DecryptAndStoreOrganizationKeys(accountNode["encOrgKeys"]?.AsObject());
        }

        if ((context.FileFormat == "NEW" ? accountNode["data"] : accountNode) is not JsonObject dataContainerNode)
        {
            Console.Error.WriteLine("ERROR: Data container not found in JSON.");
            Environment.Exit(1);
            return [];
        }

        JsonObject decryptedEntries = [];
        foreach (KeyValuePair<string, JsonNode?> groupKvp in dataContainerNode)
        {
            string groupKeyOriginal = groupKvp.Key;
            string outputKey = groupKeyOriginal.Contains('_') ? groupKeyOriginal[..groupKeyOriginal.IndexOf('_')] : groupKeyOriginal;
            outputKey = outputKey.Replace("ciphers", "items");

            if ((groupKeyOriginal == "sends" || (outputKey == "sends" && groupKeyOriginal.StartsWith("sends_"))) && !context.IncludeSends)
            {
                continue;
            }

            string[] supportedOutputKeys = ["folders", "items", "collections", "organizations", "sends"];
            if (!supportedOutputKeys.Contains(outputKey))
            {
                continue;
            }

            JsonNode? actualDataNode = groupKvp.Value;
            if (context.FileFormat == "NEW" && outputKey != "organizations" && outputKey != "sends" && groupKvp.Value?["encrypted"] is not null)
            {
                actualDataNode = groupKvp.Value["encrypted"];
            }

            if (actualDataNode is not JsonObject groupDataObj)
            {
                continue;
            }

            JsonArray itemsArray = [];
            foreach (KeyValuePair<string, JsonNode?> itemKvp in groupDataObj)
            {
                if (itemKvp.Value is JsonObject itemObj)
                {
                    itemsArray.Add(outputKey == "sends"
                        ? vaultItemDecryptor.DecryptSend(itemObj.DeepClone())
                        : vaultItemDecryptor.ProcessGroupItem(itemObj.DeepClone()));
                }
            }
            decryptedEntries[outputKey] = itemsArray;
        }

        return decryptedEntries;
    }

    private void DecryptAndStoreOrganizationKeys(JsonObject? orgKeysNode)
    {
        if (orgKeysNode == null || secrets.RsaPrivateKeyDer == null)
        {
            return;
        }

        foreach (KeyValuePair<string, JsonNode?> kvp in orgKeysNode)
        {
            string? orgKeyCipher = kvp.Value?["key"]?.GetValue<string>() ?? kvp.Value?.GetValue<string>();
            if (orgKeyCipher == null)
            {
                continue;
            }

            byte[]? decryptedOrgKey = vaultItemDecryptor.DecryptRsaInternal(orgKeyCipher);
            if (decryptedOrgKey != null)
            {
                secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
            }
        }
    }
}