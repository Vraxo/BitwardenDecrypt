namespace BitwardenDecryptor.Models;

public record SymmetricKeyDecryptionResult(byte[]? FullKey, byte[]? EncKey, byte[]? MacKey, string? Error);
