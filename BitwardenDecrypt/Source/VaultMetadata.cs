namespace BitwardenDecryptor.Core;

public class VaultMetadata
{
    public string FileFormat { get; }
    public string? AccountEmail { get; }
    public string? AccountUuid { get; }
    public string KdfSalt { get; }
    public int KdfIterations { get; }
    public int? KdfMemory { get; }
    public int? KdfParallelism { get; }
    public int KdfType { get; }
    public string ProtectedSymmetricKey { get; }
    public string? ProtectedRsaPrivateKey { get; }

    public VaultMetadata(
        string fileFormat,
        string kdfSalt,
        int kdfIterations,
        int? kdfMemory,
        int? kdfParallelism,
        int kdfType,
        string protectedSymmetricKey,
        string? protectedRsaPrivateKey,
        string? accountEmail = null,
        string? accountUuid = null)
    {
        FileFormat = fileFormat;
        KdfSalt = kdfSalt;
        KdfIterations = kdfIterations;
        KdfMemory = kdfMemory;
        KdfParallelism = kdfParallelism;
        KdfType = kdfType;
        ProtectedSymmetricKey = protectedSymmetricKey;
        ProtectedRsaPrivateKey = protectedRsaPrivateKey;
        AccountEmail = accountEmail;
        AccountUuid = accountUuid;
    }
}
