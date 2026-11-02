using AwesomeAssertions;
using BitwardenDecryptor.Core;
using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using Xunit;

namespace BitwardenDecryptor.Tests;

public class KeyDerivationServiceTests
{
    private const string Pbkdf2MasterKeyHex = "396B3EFAF33A2D658CD83A9EFEB387386F5915D51E8EEA61D5CD70F63923360F";
    private const string Argon2MasterKeyHex = "E3909E3AB5F23F1F629ED82D87D539662C1FEE3B0E7B456E79721E7A0AFFD2A8";

    [Fact]
    public void DeriveKeys_Pbkdf2Account_DerivesAndDecryptsKeys()
    {
        VaultMetadata metadata = CreateMetadata(kdfType: 0, iterations: 1000, memory: null, parallelism: null);
        KeyDerivationService service = new(metadata, new ProtectedKeyDecryptor());

        BitwardenSecrets secrets = service.DeriveKeys(TestData.Password);

        secrets.MasterKey.Should().Equal(Convert.FromHexString(Pbkdf2MasterKeyHex));
        secrets.MasterPasswordHash.Should().Be("Yu+pGSqBSLaBqYz4/Gg5d7FwD2sfJdXCLPMnP+RP1Ys=");
        secrets.GeneratedSymmetricKey.Should().Equal(TestData.Key(20, 64));
        secrets.GeneratedEncryptionKey.Should().Equal(TestData.Key(20, 64).Take(32).ToArray());
        secrets.GeneratedMacKey.Should().Equal(TestData.Key(20, 64).Skip(32).Take(32).ToArray());
        secrets.RsaPrivateKeyDer.Should().BeNull();
    }

    [Fact]
    public void DeriveKeys_Argon2Account_DerivesAndDecryptsKeys()
    {
        VaultMetadata metadata = CreateMetadata(kdfType: 1, iterations: 2, memory: 1, parallelism: 1);
        KeyDerivationService service = new(metadata, new ProtectedKeyDecryptor());

        BitwardenSecrets secrets = service.DeriveKeys(TestData.Password);

        secrets.MasterKey.Should().Equal(Convert.FromHexString(Argon2MasterKeyHex));
        secrets.GeneratedSymmetricKey.Should().Equal(TestData.Key(20, 64));
        secrets.GeneratedEncryptionKey.Should().Equal(TestData.Key(20, 64).Take(32).ToArray());
        secrets.GeneratedMacKey.Should().Equal(TestData.Key(20, 64).Skip(32).Take(32).ToArray());
    }

    [Fact]
    public void DeriveKeys_WrongPassword_ThrowsHelpfulError()
    {
        VaultMetadata metadata = CreateMetadata(kdfType: 0, iterations: 1000, memory: null, parallelism: null);
        KeyDerivationService service = new(metadata, new ProtectedKeyDecryptor());

        Action act = () => service.DeriveKeys("wrong password");

        act.Should().Throw<KeyDerivationException>().WithMessage("*wrong password*");
    }

    [Theory]
    [InlineData(null, 1)]
    [InlineData(1, null)]
    public void DeriveKeys_IncompleteArgon2Configuration_Throws(int? memory, int? parallelism)
    {
        VaultMetadata metadata = CreateMetadata(kdfType: 1, iterations: 2, memory: memory, parallelism: parallelism);
        KeyDerivationService service = new(metadata, new ProtectedKeyDecryptor());

        Action act = () => service.DeriveKeys(TestData.Password);

        act.Should().Throw<KeyDerivationException>().WithMessage("*KDF memory or parallelism not set*");
    }

    private static VaultMetadata CreateMetadata(int kdfType, int iterations, int? memory, int? parallelism)
    {
        byte[] masterKey = Convert.FromHexString(kdfType == 1 ? Argon2MasterKeyHex : Pbkdf2MasterKeyHex);
        (byte[] encryptionKey, byte[] macKey) = TestCipher.GetStretchedKeys(masterKey);
        string protectedKey = TestCipher.Create(TestData.Key(20, 64), encryptionKey, macKey);

        return new(
            FileFormat: "2024",
            KdfSalt: TestData.Email,
            KdfIterations: iterations,
            KdfMemory: memory,
            KdfParallelism: parallelism,
            KdfType: kdfType,
            ProtectedSymmetricKey: protectedKey,
            ProtectedRsaPrivateKey: null,
            AccountEmail: TestData.Email,
            AccountUuid: "11111111-1111-1111-1111-111111111111");
    }
}
