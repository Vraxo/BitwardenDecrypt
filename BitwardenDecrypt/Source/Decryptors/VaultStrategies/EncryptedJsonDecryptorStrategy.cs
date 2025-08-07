using System.Text.Json.Nodes;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core.VaultStrategies;

public class EncryptedJsonDecryptorStrategy(
    JsonNode rootNode,
    BitwardenSecrets secrets,
    VaultItemDecryptor vaultItemDecryptor) : IVaultDecryptorStrategy
{
    public JsonObject Decrypt()
    {
        string? encryptedVaultData = rootNode["data"]?.GetValue<string>();

        if (string.IsNullOrEmpty(encryptedVaultData))
        {
            Console.Error.WriteLine("ERROR: No vault data found in EncryptedJSON export.");
            Environment.Exit(1);
        }

        string decryptedJsonPayload = vaultItemDecryptor.DecryptCipherString(encryptedVaultData, secrets.StretchedEncryptionKey, secrets.StretchedMacKey);

        if (decryptedJsonPayload.StartsWith("ERROR"))
        {
            Console.Error.WriteLine($"ERROR: Failed to decrypt EncryptedJSON payload. {decryptedJsonPayload}");
            Environment.Exit(1);
        }

        JsonObject payloadNode = JsonNode.Parse(decryptedJsonPayload)!.AsObject();
        JsonObject decryptedEntries = [];
        foreach (KeyValuePair<string, JsonNode?> prop in payloadNode)
        {
            decryptedEntries[prop.Key] = prop.Value?.DeepClone();
        }
        
        return decryptedEntries;
    }
}
