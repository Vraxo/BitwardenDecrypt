namespace BitwardenDecryptor.Models;

public record DecryptionResult(byte[]? Plaintext, string? Error);
