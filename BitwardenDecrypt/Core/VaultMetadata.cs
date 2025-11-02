namespace BitwardenDecryptor.Core;

public record VaultMetadata(
    string FileFormat,
    string KdfSalt,
    int KdfIterations,
    int? KdfMemory,
    int? KdfParallelism,
    int KdfType,
    string ProtectedSymmetricKey,
    string? ProtectedRsaPrivateKey,
    string? AccountEmail = null,
    string? AccountUuid = null);