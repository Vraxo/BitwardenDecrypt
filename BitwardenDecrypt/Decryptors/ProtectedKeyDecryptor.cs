using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public static class ProtectedKeyDecryptor
{
    public static SymmetricKeyDecryptionResult DecryptSymmetricKey(string cipherString, byte[] masterKey, byte[] masterMacKey, bool isExportValidationKey = false)
    {
        if (string.IsNullOrEmpty(cipherString))
        {
            return new(null, null, null, "CipherString is empty.");
        }

        string[] parts = cipherString.Split('.');

        if (parts.Length < 2)
        {
            return new(null, null, null, "Invalid CipherString format.");
        }

        if (!int.TryParse(parts[0], out int encType))
        {
            return new(null, null, null, "Invalid encryption type in CipherString.");
        }

        DecryptionResult decryptionResult = CryptoService.VerifyAndDecryptAesCbc(masterKey, masterMacKey, cipherString);

        if (decryptionResult.Error != null || decryptionResult.Plaintext == null)
        {
            return new(null, null, null, decryptionResult.Error);
        }

        byte[] cleartextBytes = decryptionResult.Plaintext;

        if (!isExportValidationKey && encType == 2 && cleartextBytes.Length < 64)
        {
            return new(null, null, null, "Decrypted key is too short. Likely wrong password (for data.json user key).");
        }

        if ((encType == 2 || encType == 0) && cleartextBytes.Length >= 64)
        {
            byte[] enc = cleartextBytes.Take(32).ToArray();
            byte[] mac = cleartextBytes.Skip(32).Take(32).ToArray();
            return new SymmetricKeyDecryptionResult(cleartextBytes, enc, mac, null);
        }

        return new(cleartextBytes, null, null, null);
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