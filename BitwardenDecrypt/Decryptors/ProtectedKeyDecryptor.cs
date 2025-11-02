using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class ProtectedKeyDecryptor : IProtectedKeyDecryptor
{
    public SymmetricKeyDecryptionResult DecryptSymmetricKey(string cipherString, byte[] masterKey, byte[] masterMacKey, bool isExportValidationKey = false)
    {
        if (string.IsNullOrEmpty(cipherString))
        {
            return new(null, null, null, "CipherString is empty.");
        }

        (int encryptionType, string? error) = ParseCipherStringHeader(cipherString);

        if (error is not null)
        {
            return new(null, null, null, error);
        }

        DecryptionResult decryptionResult = CryptoService.VerifyAndDecryptAesCbc(masterKey, masterMacKey, cipherString);

        return decryptionResult.Error != null || decryptionResult.Plaintext == null
            ? new(null, null, null, decryptionResult.Error)
            : ProcessDecryptedKey(decryptionResult.Plaintext, encryptionType, isExportValidationKey);
    }

    private static (int EncryptionType, string? Error) ParseCipherStringHeader(string cipherString)
    {
        string[] parts = cipherString.Split('.');

        if (parts.Length < 2)
        {
            return (0, "Invalid CipherString format.");
        }

        if (!int.TryParse(parts[0], out int encType))
        {
            return (0, "Invalid encryption type in CipherString.");
        }

        return (encType, null);
    }

    private static SymmetricKeyDecryptionResult ProcessDecryptedKey(byte[] cleartextBytes, int encType, bool isExportValidationKey)
    {
        if (!isExportValidationKey && encType == 2 && cleartextBytes.Length < 64)
        {
            return new(
                null,
                null,
                null,
                "Decrypted key is too short. Likely wrong password (for data.json user key).");
        }

        bool isCompositeKeyType = encType is 2 or 0;

        if (!isCompositeKeyType || cleartextBytes.Length < 64)
        {
            return new(cleartextBytes, null, null, null);
        }

        byte[] enc = [.. cleartextBytes.Take(32)];
        byte[] mac = [.. cleartextBytes.Skip(32).Take(32)];

        return new(cleartextBytes, enc, mac, null);
    }

    public byte[]? DecryptRsaPrivateKeyBytes(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        DecryptionResult result = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);

        return result.Error != null ? null : result.Plaintext;
    }
}