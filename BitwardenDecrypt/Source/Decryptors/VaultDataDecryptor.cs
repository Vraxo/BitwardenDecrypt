using System.Text.Json.Nodes;
using BitwardenDecryptor.Core.VaultStrategies;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class VaultDataDecryptor(BitwardenSecrets secrets, CommandLineOptions options)
{
    public JsonObject DecryptVault(JsonNode rootNode)
    {
        IVaultDecryptorStrategy strategy = CreateStrategy(rootNode);
        return strategy.Decrypt();
    }

    private IVaultDecryptorStrategy CreateStrategy(JsonNode rootNode)
    {
        var vaultItemDecryptor = new VaultItemDecryptor(secrets);

        return options.FileFormat switch
        {
            "EncryptedJSON" => new EncryptedJsonDecryptorStrategy(rootNode, secrets, vaultItemDecryptor),
            "2024" => new Format2024DecryptorStrategy(rootNode, secrets, options, vaultItemDecryptor),
            "NEW" or "OLD" => new LegacyJsonDecryptorStrategy(rootNode, secrets, options, vaultItemDecryptor),
            _ => throw new NotSupportedException($"The file format '{options.FileFormat}' is not supported.")
        };
    }
}
