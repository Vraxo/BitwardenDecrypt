namespace BitwardenDecryptor.Models;

public class BitwardenSecrets
{
    public string Email { get; set; } = string.Empty;
    public byte[] MasterPasswordBytes { get; set; } = [];
    public int KdfIterations { get; set; }
    public int? KdfMemory { get; set; }
    public int? KdfParallelism { get; set; }
    public int KdfType { get; set; }
    public string ProtectedSymmetricKeyCipherString { get; set; } = string.Empty;
    public string? ProtectedRsaPrivateKeyCipherString { get; set; }

    public byte[] MasterKey { get; set; } = [];
    public string MasterPasswordHash { get; set; } = string.Empty;

    public byte[] StretchedEncryptionKey { get; set; } = [];
    public byte[] StretchedMacKey { get; set; } = [];

    public byte[] GeneratedSymmetricKey { get; set; } = [];
    public byte[] GeneratedEncryptionKey { get; set; } = [];
    public byte[] GeneratedMacKey { get; set; } = [];

    public byte[]? RsaPrivateKeyDer { get; set; }

    public Dictionary<string, byte[]> OrganizationKeys { get; } = [];
}