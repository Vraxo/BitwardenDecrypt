using AwesomeAssertions;
using BitwardenDecryptor.Core;
using Xunit;

namespace BitwardenDecryptor.Tests;

public class ProtectedKeyDecryptorTests
{
    private readonly ProtectedKeyDecryptor _decryptor = new();

    [Fact]
    public void DecryptSymmetricKey_CompositeKey_SplitsEncryptionAndMacKeys()
    {
        byte[] fullKey = TestData.Key(1, 64);
        string cipherString = TestCipher.Create(fullKey, TestData.Key(101), TestData.Key(151));

        var result = _decryptor.DecryptSymmetricKey(cipherString, TestData.Key(101), TestData.Key(151));

        result.Error.Should().BeNull();
        result.FullKey.Should().NotBeNull();
        result.FullKey!.Should().Equal(fullKey);
        result.EncKey.Should().NotBeNull();
        result.EncKey!.Should().Equal(fullKey.Take(32).ToArray());
        result.MacKey.Should().NotBeNull();
        result.MacKey!.Should().Equal(fullKey.Skip(32).Take(32).ToArray());
    }

    [Fact]
    public void DecryptSymmetricKey_ShortUserKey_ReturnsError()
    {
        string cipherString = TestCipher.Create(TestData.Key(1, 16), TestData.Key(101), TestData.Key(151));

        var result = _decryptor.DecryptSymmetricKey(cipherString, TestData.Key(101), TestData.Key(151));

        result.FullKey.Should().BeNull();
        result.Error.Should().Contain("Decrypted key is too short");
    }

    [Fact]
    public void DecryptSymmetricKey_ShortExportValidationKey_IsAccepted()
    {
        byte[] validationKey = TestData.Key(1, 16);
        string cipherString = TestCipher.Create(validationKey, TestData.Key(101), TestData.Key(151));

        var result = _decryptor.DecryptSymmetricKey(
            cipherString,
            TestData.Key(101),
            TestData.Key(151),
            isExportValidationKey: true);

        result.Error.Should().BeNull();
        result.FullKey.Should().NotBeNull();
        result.FullKey!.Should().Equal(validationKey);
        result.EncKey.Should().BeNull();
        result.MacKey.Should().BeNull();
    }

    [Theory]
    [InlineData("", "CipherString is empty.")]
    [InlineData("invalid", "Invalid CipherString format.")]
    [InlineData("x.anything", "Invalid encryption type in CipherString.")]
    public void DecryptSymmetricKey_InvalidInput_ReturnsError(string cipherString, string expectedError)
    {
        var result = _decryptor.DecryptSymmetricKey(cipherString, TestData.Key(101), TestData.Key(151));

        result.FullKey.Should().BeNull();
        result.Error.Should().Be(expectedError);
    }
}
