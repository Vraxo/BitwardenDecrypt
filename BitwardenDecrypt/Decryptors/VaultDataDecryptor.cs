using BitwardenDecryptor.Core.VaultStrategies;
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class VaultDataDecryptor(BitwardenSecrets secrets, DecryptionContext context)
{
    public JsonObject DecryptVault(JsonNode rootNode)
    {
        IVaultDecryptorStrategy strategy = CreateStrategy(rootNode);
        return strategy.Decrypt();
    }

    private IVaultDecryptorStrategy CreateStrategy(JsonNode rootNode)
    {
        VaultItemDecryptor vaultItemDecryptor = new(secrets);

        return context.FileFormat switch
        {
            "EncryptedJSON" => new EncryptedJsonDecryptorStrategy(rootNode, secrets, vaultItemDecryptor),
            "2024" => new Format2024DecryptorStrategy(rootNode, secrets, context, vaultItemDecryptor),
            "NEW" or "OLD" => new LegacyJsonDecryptorStrategy(rootNode, secrets, context, vaultItemDecryptor),
            _ => throw new NotSupportedException($"The file format '{context.FileFormat}' is not supported.")
        };
    }
}