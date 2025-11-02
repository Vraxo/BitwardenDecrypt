using BitwardenDecryptor.Models;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using System.Security.Cryptography;

namespace BitwardenDecryptor.Crypto;

public static class CryptoService
{
    public static byte[] DerivePbkdf2Sha256(byte[] password, byte[] salt, int iterations, int outputLength)
    {
        using Rfc2898DeriveBytes pbkdf2 = new(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(outputLength);
    }

    public static byte[] DeriveArgon2id(byte[] password, byte[] salt, int iterations, int memoryKiB, int parallelism, int outputLength)
    {
        Argon2Config config = new()
        {
            Type = Argon2Type.HybridAddressing,
            Version = Argon2Version.Nineteen,
            TimeCost = iterations,
            MemoryCost = memoryKiB,
            Lanes = parallelism,
            Threads = parallelism,
            Password = password,
            Salt = salt,
            HashLength = outputLength
        };

        using Argon2 argon2 = new(config);
        using SecureArray<byte> hashResult = argon2.Hash();
        return hashResult.Buffer;
    }

    public static byte[] HkdfExpandSha256(byte[] ikm, byte[] info, int outputLength)
    {
        return HKDF.Expand(HashAlgorithmName.SHA256, ikm, outputLength, info);
    }

    public static byte[] ComputeHmacSha256(byte[] key, byte[] data)
    {
        using HMACSHA256 hmac = new(key);
        return hmac.ComputeHash(data);
    }

    public static byte[]? DecryptAesCbc(byte[] key, byte[] iv, byte[] ciphertext, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        using Aes aes = Aes.Create();

        if (aes is null)
        {
            return null;
        }

        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = paddingMode;
        aes.Key = key;
        aes.IV = iv;

        using ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using MemoryStream msDecrypt = new(ciphertext);
        using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
        using MemoryStream msPlain = new();
        csDecrypt.CopyTo(msPlain);

        return msPlain.ToArray();
    }

    public static DecryptionResult VerifyAndDecryptAesCbc(byte[] encryptionKey, byte[] macKey, string cipherString)
    {
        string[] parts = cipherString.Split('.');

        if (parts.Length < 2)
        {
            return new DecryptionResult(null, "Invalid CipherString format (missing type or data).");
        }

        string[] dataParts = parts[1].Split('|');

        if (dataParts.Length < 3)
        {
            return new DecryptionResult(null, "Invalid CipherString format (missing IV, ciphertext, or MAC).");
        }

        byte[] iv;
        byte[] ciphertext;
        byte[] mac;

        try
        {
            iv = Convert.FromBase64String(dataParts[0]);
            ciphertext = Convert.FromBase64String(dataParts[1]);
            mac = Convert.FromBase64String(dataParts[2]);
        }
        catch (FormatException ex)
        {
            return new DecryptionResult(null, $"Base64 decoding failed: {ex.Message}");
        }

        byte[] dataToMac = [.. iv, .. ciphertext];
        byte[] calculatedMac = ComputeHmacSha256(macKey, dataToMac);

        if (!mac.SequenceEqual(calculatedMac))
        {
            return new DecryptionResult(null, "MAC mismatch.");
        }

        try
        {
            byte[]? decrypted = DecryptAesCbc(encryptionKey, iv, ciphertext);
            return new DecryptionResult(decrypted, null);
        }
        catch (CryptographicException ex)
        {
            return new DecryptionResult(null, $"Decryption failed (possibly wrong password/key or padding): {ex.Message}");
        }
    }

    public static byte[]? DecryptRsaOaepSha1(byte[] privateKeyDer, byte[] ciphertext)
    {
        try
        {
            using RSA rsa = RSA.Create();

            if (rsa == null)
            {
                return null;
            }

            try
            {
                rsa.ImportPkcs8PrivateKey(privateKeyDer, out _);
            }
            catch (CryptographicException)
            {
                try
                {
                    rsa.ImportRSAPrivateKey(privateKeyDer, out _);
                }
                catch (CryptographicException ex)
                {
                    Console.Error.WriteLine($"Failed to import RSA private key (DER): {ex.Message}");
                    return null;
                }
            }

            return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA1);
        }
        catch (CryptographicException ex)
        {
            Console.Error.WriteLine($"RSA decryption failed: {ex.Message}");
            return null;
        }
    }

    public static byte[] Sha256Hash(byte[] data)
    {
        return SHA256.HashData(data);
    }
}
