namespace BitwardenDecryptor.Core;

public class VaultFileParseResult
{
    public bool Success { get; }
    public string EmailOrSalt { get; }
    public int KdfIterations { get; }
    public int? KdfMemory { get; }
    public int? KdfParallelism { get; }
    public int KdfType { get; }
    public string ProtectedSymmetricKeyOrValidation { get; }
    public string? EncPrivateKeyCipher { get; }

    public VaultFileParseResult(
        bool success,
        string emailOrSalt = "",
        int kdfIterations = 0,
        int? kdfMemory = null,
        int? kdfParallelism = null,
        int kdfType = 0,
        string protectedSymmetricKeyOrValidation = "",
        string? encPrivateKeyCipher = null)
    {
        Success = success;
        EmailOrSalt = emailOrSalt;
        KdfIterations = kdfIterations;
        KdfMemory = kdfMemory;
        KdfParallelism = kdfParallelism;
        KdfType = kdfType;
        ProtectedSymmetricKeyOrValidation = protectedSymmetricKeyOrValidation;
        EncPrivateKeyCipher = encPrivateKeyCipher;
    }
}