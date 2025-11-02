using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultStrategies;

public class EncryptedJsonDecryptorStrategy : IVaultDecryptorStrategy
{
    private readonly JsonNode rootNode;
    private readonly BitwardenSecrets secrets;
    private readonly VaultItemDecryptor vaultItemDecryptor;

    public EncryptedJsonDecryptorStrategy(JsonNode rootNode, BitwardenSecrets secrets, VaultItemDecryptor vaultItemDecryptor)
    {
        this.rootNode = rootNode;
        this.secrets = secrets;
        this.vaultItemDecryptor = vaultItemDecryptor;
    }

    public JsonObject Decrypt()
    {
        string? encryptedVaultData = rootNode["data"]?.GetValue<string>();

        if (string.IsNullOrEmpty(encryptedVaultData))
        {
            throw new VaultFormatException("No vault data found in EncryptedJSON export.");
        }

        string decryptedJsonPayload = vaultItemDecryptor.DecryptCipherString(encryptedVaultData, secrets.StretchedEncryptionKey, secrets.StretchedMacKey);

        if (decryptedJsonPayload.StartsWith("ERROR"))
        {
            throw new DecryptionException($"Failed to decrypt EncryptedJSON payload. {decryptedJsonPayload}");
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