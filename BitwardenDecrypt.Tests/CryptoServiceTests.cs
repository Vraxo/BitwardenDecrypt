using AwesomeAssertions;
using BitwardenDecryptor.Crypto;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace BitwardenDecryptor.Tests;

public class CryptoServiceTests
{
    [Fact]
    public void DerivePbkdf2Sha256_MatchesKnownVector()
    {
        byte[] result = CryptoService.DerivePbkdf2Sha256(
            Encoding.UTF8.GetBytes(TestData.Password),
            Encoding.UTF8.GetBytes(TestData.Email),
            TestData.Pbkdf2Iterations,
            32);

        Convert.ToHexString(result).Should().Be("396B3EFAF33A2D658CD83A9EFEB387386F5915D51E8EEA61D5CD70F63923360F");
    }

    [Fact]
    public void DeriveArgon2id_MatchesKnownVector()
    {
        byte[] salt = CryptoService.Sha256Hash(Encoding.UTF8.GetBytes(TestData.Email));

        byte[] result = CryptoService.DeriveArgon2id(
            Encoding.UTF8.GetBytes(TestData.Password),
            salt,
            iterations: 2,
            memoryKiB: 1024,
            parallelism: 1,
            outputLength: 32);

        Convert.ToHexString(result).Should().Be("E3909E3AB5F23F1F629ED82D87D539662C1FEE3B0E7B456E79721E7A0AFFD2A8");
    }

    [Fact]
    public void HkdfExpandSha256_MatchesKnownVector()
    {
        byte[] masterKey = Convert.FromHexString("396B3EFAF33A2D658CD83A9EFEB387386F5915D51E8EEA61D5CD70F63923360F");

        byte[] result = CryptoService.HkdfExpandSha256(masterKey, Encoding.UTF8.GetBytes("enc"), 32);

        Convert.ToHexString(result).Should().Be("8259476CBF11787EC717C254A62E6FE942887E1C5516162B07F9F2A170394226");
    }

    [Fact]
    public void DecryptAesCbc_MatchesNistVector()
    {
        byte[] key = Convert.FromHexString("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
        byte[] iv = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        byte[] ciphertext = Convert.FromHexString("F58C4C04D6E5F1BA779EABFB5F7BFBD6");

        byte[]? plaintext = CryptoService.DecryptAesCbc(key, iv, ciphertext, PaddingMode.None);

        plaintext.Should().NotBeNull();
        Convert.ToHexString(plaintext!).Should().Be("6BC1BEE22E409F96E93D7E117393172A");
    }

    [Fact]
    public void VerifyAndDecryptAesCbc_ValidCipherString_ReturnsPlaintext()
    {
        byte[] encryptionKey = TestData.Key(1);
        byte[] macKey = TestData.Key(101);
        byte[] plaintext = Encoding.UTF8.GetBytes("vault secret ✓");
        string cipherString = TestCipher.Create(plaintext, encryptionKey, macKey);

        var result = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);

        result.Error.Should().BeNull();
        result.Plaintext.Should().NotBeNull();
        result.Plaintext!.Should().Equal(plaintext);
    }

    [Fact]
    public void VerifyAndDecryptAesCbc_TamperedMac_ReturnsError()
    {
        byte[] encryptionKey = TestData.Key(1);
        byte[] macKey = TestData.Key(101);
        string cipherString = TestCipher.Create("secret", encryptionKey, macKey);
        string[] parts = cipherString.Split('|');
        parts[^1] = Convert.ToBase64String(new byte[32]);
        string tamperedCipherString = string.Join("|", parts);

        var result = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, tamperedCipherString);

        result.Plaintext.Should().BeNull();
        result.Error.Should().Be("MAC mismatch.");
    }

    [Theory]
    [InlineData("missing-data", "Invalid CipherString format")]
    [InlineData("2.only-iv", "Invalid CipherString format")]
    [InlineData("2.%%%|%%%|%%%", "Base64 decoding failed:")]
    public void VerifyAndDecryptAesCbc_MalformedCipherString_ReturnsError(
        string cipherString,
        string expectedError)
    {
        var result = CryptoService.VerifyAndDecryptAesCbc(TestData.Key(1), TestData.Key(101), cipherString);

        result.Plaintext.Should().BeNull();
        result.Error.Should().StartWith(expectedError);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DecryptRsaOaepSha1_SupportsStandardPrivateKeyFormats(bool usePkcs1)
    {
        using RSA rsa = RSA.Create();
        rsa.KeySize = 2048;
        byte[] privateKey = usePkcs1 ? rsa.ExportRSAPrivateKey() : rsa.ExportPkcs8PrivateKey();
        byte[] plaintext = Encoding.UTF8.GetBytes("organization key");
        byte[] ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA1);

        byte[]? result = CryptoService.DecryptRsaOaepSha1(privateKey, ciphertext);

        result.Should().NotBeNull();
        result!.Should().Equal(plaintext);
    }
}
