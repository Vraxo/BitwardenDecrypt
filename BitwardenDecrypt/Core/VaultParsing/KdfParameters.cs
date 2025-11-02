namespace BitwardenDecryptor.Core.VaultParsing;

internal record KdfParameters(
    string EmailOrSalt,
    int KdfIterations,
    int? KdfMemory,
    int? KdfParallelism,
    int KdfType,
    string ProtectedSymmetricKey,
    string? ProtectedRsaPrivateKey);