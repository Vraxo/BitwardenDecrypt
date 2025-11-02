using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class ProtectedKeyDecryptor
{
    public static SymmetricKeyDecryptionResult DecryptSymmetricKey(string cipherString, byte[] masterKey, byte[] masterMacKey, bool isExportValidationKey = false)
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
        
        if (decryptionResult.Error != null || decryptionResult.Plaintext == null)
        {
            return new(null, null, null, decryptionResult.Error);
        }

        return ProcessDecryptedKey(decryptionResult.Plaintext, encryptionType, isExportValidationKey);
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

        bool isCompositeKeyType = (encType == 2 || encType == 0);

        if (!isCompositeKeyType || cleartextBytes.Length < 64)
        {
            return new(cleartextBytes, null, null, null);
        }

        byte[] enc = [.. cleartextBytes.Take(32)];
        byte[] mac = [.. cleartextBytes.Skip(32).Take(32)];

        return new(cleartextBytes, enc, mac, null);
    }

    public static byte[]? DecryptRsaPrivateKeyBytes(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        DecryptionResult result = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);

        if (result.Error != null)
        {
            return null;
        }

        return result.Plaintext;
    }
}