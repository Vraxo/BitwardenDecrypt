using BitwardenDecryptor.Core.VaultStrategies;
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class VaultDataDecryptor
{
    private readonly BitwardenSecrets _secrets;
    private readonly DecryptionContext _context;
    private readonly IProtectedKeyDecryptor _protectedKeyDecryptor;

    public VaultDataDecryptor(BitwardenSecrets secrets, DecryptionContext context, IProtectedKeyDecryptor protectedKeyDecryptor)
    {
        _secrets = secrets;
        _context = context;
        _protectedKeyDecryptor = protectedKeyDecryptor;
    }

    public JsonObject DecryptVault(JsonNode rootNode)
    {
        IVaultDecryptorStrategy strategy = CreateStrategy(rootNode);
        return strategy.Decrypt();
    }

    private IVaultDecryptorStrategy CreateStrategy(JsonNode rootNode)
    {
        VaultItemDecryptor vaultItemDecryptor = new(_secrets, _protectedKeyDecryptor);

        return _context.FileFormat switch
        {
            "EncryptedJSON" => new EncryptedJsonDecryptorStrategy(rootNode, _secrets, vaultItemDecryptor),
            "2024" => new Format2024DecryptorStrategy(rootNode, _context, vaultItemDecryptor),
            "NEW" or "OLD" => new LegacyJsonDecryptorStrategy(rootNode, _context, vaultItemDecryptor),
            _ => throw new NotSupportedException($"The file format '{_context.FileFormat}' is not supported.")
        };
    }
}