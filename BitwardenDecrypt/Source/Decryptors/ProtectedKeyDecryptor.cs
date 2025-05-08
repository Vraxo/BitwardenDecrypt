using BitwardenDecryptor.Crypto;

namespace BitwardenDecryptor.Core;

public static class ProtectedKeyDecryptor
{
    public static (byte[]? FullKey, byte[]? EncKey, byte[]? MacKey, string? Error) DecryptSymmetricKey(string cipherString, byte[] masterKey, byte[] masterMacKey, bool isExportValidationKey = false)
    {
        if (string.IsNullOrEmpty(cipherString))
        {
            return (null, null, null, "CipherString is empty.");
        }

        string[] parts = cipherString.Split('.');

        if (parts.Length < 2)
        {
            return (null, null, null, "Invalid CipherString format.");
        }

        if (!int.TryParse(parts[0], out int encType))
        {
            return (null, null, null, "Invalid encryption type in CipherString.");
        }

        (byte[]? cleartextBytes, string? error) = CryptoService.VerifyAndDecryptAesCbc(masterKey, masterMacKey, cipherString);

        if (error != null || cleartextBytes == null)
        {
            return (null, null, null, error);
        }

        if (!isExportValidationKey && encType == 2 && cleartextBytes.Length < 64)
        {
            return (null, null, null, "Decrypted key is too short. Likely wrong password (for data.json user key).");
        }

        if ((encType == 2 || encType == 0) && cleartextBytes.Length >= 64)
        {
            byte[] enc = cleartextBytes.Take(32).ToArray();
            byte[] mac = cleartextBytes.Skip(32).Take(32).ToArray();
            return (cleartextBytes, enc, mac, null);
        }

        return (cleartextBytes, null, null, null);
    }

    public static byte[]? DecryptRsaPrivateKeyBytes(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        (byte[]? cleartext, string? error) = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);

        if (error != null)
        {
            Console.Error.WriteLine($"ERROR decrypting RSA private key wrapper: {error}");
            return null;
        }

        return cleartext;
    }
}