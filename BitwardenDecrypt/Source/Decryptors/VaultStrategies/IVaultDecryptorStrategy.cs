using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultStrategies;

public interface IVaultDecryptorStrategy
{
    JsonObject Decrypt();
}
