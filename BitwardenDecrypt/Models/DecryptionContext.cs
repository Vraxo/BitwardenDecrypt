namespace BitwardenDecryptor.Models;

public record DecryptionContext(
    string FileFormat,
    string AccountUuid,
    string AccountEmail,
    bool IncludeSends
);