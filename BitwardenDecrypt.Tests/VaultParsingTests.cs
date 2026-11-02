using AwesomeAssertions;
using BitwardenDecryptor.Core;
using BitwardenDecryptor.Core.VaultParsing;
using BitwardenDecryptor.Core.VaultParsing.FormatParsers;
using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;
using Xunit;

namespace BitwardenDecryptor.Tests;

public class VaultParsingTests
{
    private const string FirstAccountId = "11111111-1111-1111-1111-111111111111";
    private const string SecondAccountId = "22222222-2222-2222-2222-222222222222";

    [Fact]
    public void EncryptedJsonParser_ValidExport_ReadsMetadata()
    {
        JsonNode root = JsonNode.Parse("""
            {
              "encrypted": true,
              "passwordProtected": true,
              "salt": "export-salt",
              "kdfIterations": 1000,
              "kdf": 0,
              "encKeyValidation_DO_NOT_EDIT": "validation-key"
            }
            """)!;
        EncryptedJsonParser parser = new();

        VaultMetadata? metadata = parser.Parse(root, new StubAccountSelector(), "export.json");

        metadata.Should().Be(new VaultMetadata(
            FileFormat: "EncryptedJSON",
            KdfSalt: "export-salt",
            KdfIterations: 1000,
            KdfMemory: null,
            KdfParallelism: null,
            KdfType: 0,
            ProtectedSymmetricKey: "validation-key",
            ProtectedRsaPrivateKey: null));
    }

    [Fact]
    public void EncryptedJsonParser_UnencryptedExport_ReturnsNullWithoutSelectingAccount()
    {
        JsonNode root = JsonNode.Parse("""{ "encrypted": false, "passwordProtected": false }""")!;
        StubAccountSelector selector = new();
        EncryptedJsonParser parser = new();

        VaultMetadata? metadata = parser.Parse(root, selector, "export.json");

        metadata.Should().BeNull();
        selector.CallCount.Should().Be(0);
    }

    [Fact]
    public void Format2024Parser_MultipleAccounts_UsesSelectedAccount()
    {
        JsonNode root = JsonNode.Parse("""
            {
              "global_account_accounts": {
                "11111111-1111-1111-1111-111111111111": { "email": "first@example.com" },
                "22222222-2222-2222-2222-222222222222": { "email": "second@example.com" },
                "33333333-3333-3333-3333-333333333333": {},
                "not-a-guid": { "email": "ignored@example.com" }
              },
              "user_22222222-2222-2222-2222-222222222222_kdfConfig_kdfConfig": {
                "iterations": 2,
                "memory": 64,
                "parallelism": 4,
                "kdfType": 1
              },
              "user_22222222-2222-2222-2222-222222222222_masterPassword_masterKeyEncryptedUserKey": "second-key",
              "user_22222222-2222-2222-2222-222222222222_crypto_privateKey": "second-private-key"
            }
            """)!;
        StubAccountSelector selector = new(selectedIndex: 1);
        Format2024Parser parser = new();

        VaultMetadata? metadata = parser.Parse(root, selector, "data.json");

        metadata.Should().NotBeNull();
        metadata!.FileFormat.Should().Be("2024");
        metadata.AccountUuid.Should().Be(SecondAccountId);
        metadata.AccountEmail.Should().Be("second@example.com");
        metadata.KdfSalt.Should().Be("second@example.com");
        metadata.KdfIterations.Should().Be(2);
        metadata.KdfMemory.Should().Be(64);
        metadata.KdfParallelism.Should().Be(4);
        metadata.KdfType.Should().Be(1);
        metadata.ProtectedSymmetricKey.Should().Be("second-key");
        metadata.ProtectedRsaPrivateKey.Should().Be("second-private-key");
        selector.Accounts.Should().NotBeNull();
        selector.Accounts!.Select(account => account.Email).Should().Equal("first@example.com", "second@example.com");
        selector.Context.Should().Be("data.json");
    }

    [Fact]
    public void NewFormatParser_MasterKeyEncryptedUserKey_IsPreferred()
    {
        JsonNode root = CreateNewFormatRoot();
        NewFormatParser parser = new();

        VaultMetadata? metadata = parser.Parse(root, new StubAccountSelector(), "data.json");

        metadata.Should().Be(new VaultMetadata(
            FileFormat: "NEW",
            KdfSalt: "new@example.com",
            KdfIterations: 500000,
            KdfMemory: null,
            KdfParallelism: null,
            KdfType: 0,
            ProtectedSymmetricKey: "master-key",
            ProtectedRsaPrivateKey: "private-key",
            AccountEmail: "new@example.com",
            AccountUuid: FirstAccountId));
    }

    [Fact]
    public void NewFormatParser_WithoutMasterKeyEncryptedUserKey_UsesLegacyKey()
    {
        JsonNode root = CreateNewFormatRoot();
        root[FirstAccountId]!["keys"]!.AsObject().Remove("masterKeyEncryptedUserKey");
        NewFormatParser parser = new();

        VaultMetadata? metadata = parser.Parse(root, new StubAccountSelector(), "data.json");

        metadata.Should().NotBeNull();
        metadata!.ProtectedSymmetricKey.Should().Be("fallback-key");
    }

    [Fact]
    public void OldFormatParser_ValidVault_ReadsMetadataAndDefaults()
    {
        JsonNode root = JsonNode.Parse("""
            {
              "userId": "old-user-id",
              "userEmail": "old@example.com",
              "kdfIterations": 250000,
              "encKey": "old-key",
              "encPrivateKey": "old-private-key"
            }
            """)!;
        OldFormatParser parser = new();

        VaultMetadata? metadata = parser.Parse(root, new StubAccountSelector(), "data.json");

        metadata.Should().Be(new VaultMetadata(
            FileFormat: "OLD",
            KdfSalt: "old@example.com",
            KdfIterations: 250000,
            KdfMemory: null,
            KdfParallelism: null,
            KdfType: 0,
            ProtectedSymmetricKey: "old-key",
            ProtectedRsaPrivateKey: "old-private-key",
            AccountEmail: "old@example.com",
            AccountUuid: "old-user-id"));
    }

    [Fact]
    public void VaultParser_UnsupportedJson_ThrowsVaultFormatException()
    {
        VaultParser parser = new(
        [
            new EncryptedJsonParser(),
            new Format2024Parser(),
            new NewFormatParser(),
            new OldFormatParser(),
        ]);
        JsonNode root = JsonNode.Parse("{}")!;

        Action act = () => parser.Parse(root, new StubAccountSelector(), "unknown.json");

        act.Should().Throw<VaultFormatException>().WithMessage("*unsupported format*");
    }

    private static JsonNode CreateNewFormatRoot()
    {
        return JsonNode.Parse("""
            {
              "11111111-1111-1111-1111-111111111111": {
                "profile": {
                  "email": "new@example.com",
                  "kdfIterations": 500000,
                  "kdfType": 0
                },
                "keys": {
                  "masterKeyEncryptedUserKey": "master-key",
                  "cryptoSymmetricKey": { "encrypted": "fallback-key" },
                  "privateKey": { "encrypted": "private-key" }
                }
              }
            }
            """)!;
    }
}
