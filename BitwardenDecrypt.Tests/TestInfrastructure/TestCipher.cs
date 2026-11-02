using System.Security.Cryptography;
using System.Text;

namespace BitwardenDecryptor.Tests;

internal static class TestCipher
{
    public static string Create(
        string plaintext,
        byte[] encryptionKey,
        byte[] macKey,
        int encryptionType = 2)
    {
        return Create(Encoding.UTF8.GetBytes(plaintext), encryptionKey, macKey, encryptionType);
    }

    public static string Create(
        byte[] plaintext,
        byte[] encryptionKey,
        byte[] macKey,
        int encryptionType = 2)
    {
        byte[] iv = [.. Enumerable.Range(0, 16).Select(index => (byte)index)];

        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = encryptionKey;
        aes.IV = iv;

        using ICryptoTransform encryptor = aes.CreateEncryptor();
        byte[] ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        byte[] authenticatedData = [.. iv, .. ciphertext];

        using HMACSHA256 hmac = new(macKey);
        byte[] mac = hmac.ComputeHash(authenticatedData);

        return $"{encryptionType}.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(ciphertext)}|{Convert.ToBase64String(mac)}";
    }

    public static byte[] DerivePbkdf2MasterKey(string password, string salt, int iterations)
    {
        using Rfc2898DeriveBytes pbkdf2 = new(
            Encoding.UTF8.GetBytes(password),
            Encoding.UTF8.GetBytes(salt),
            iterations,
            HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

    public static (byte[] EncryptionKey, byte[] MacKey) GetStretchedKeys(byte[] masterKey)
    {
        byte[] encryptionKey = HKDF.Expand(
            HashAlgorithmName.SHA256,
            masterKey,
            32,
            Encoding.UTF8.GetBytes("enc"));
        byte[] macKey = HKDF.Expand(
            HashAlgorithmName.SHA256,
            masterKey,
            32,
            Encoding.UTF8.GetBytes("mac"));
        return (encryptionKey, macKey);
    }
}
