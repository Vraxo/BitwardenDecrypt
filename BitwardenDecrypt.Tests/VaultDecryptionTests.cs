using AwesomeAssertions;
using BitwardenDecryptor.Core;
using BitwardenDecryptor.Core.VaultParsing.FormatParsers;
using BitwardenDecryptor.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace BitwardenDecryptor.Tests;

public class VaultDecryptionTests
{
    private const string AccountId = "11111111-1111-1111-1111-111111111111";

    [Fact]
    public void EncryptedJsonExport_DecryptsThroughTheCompletePipeline()
    {
        byte[] masterKey = TestCipher.DerivePbkdf2MasterKey(
            TestData.Password,
            TestData.Email,
            TestData.Pbkdf2Iterations);
        (byte[] stretchedEncryptionKey, byte[] stretchedMacKey) = TestCipher.GetStretchedKeys(masterKey);
        JsonObject payload = new()
        {
            ["folders"] = new JsonArray
            {
                new JsonObject { ["id"] = "folder-1", ["name"] = "Work" },
            },
            ["items"] = new JsonArray
            {
                new JsonObject
                {
                    ["name"] = "Example",
                    ["login"] = new JsonObject { ["username"] = "person@example.com" },
                },
            },
        };
        JsonObject root = new()
        {
            ["encrypted"] = true,
            ["passwordProtected"] = true,
            ["salt"] = TestData.Email,
            ["kdfIterations"] = TestData.Pbkdf2Iterations,
            ["kdf"] = 0,
            ["encKeyValidation_DO_NOT_EDIT"] = TestCipher.Create(
                TestData.Key(20, 64),
                stretchedEncryptionKey,
                stretchedMacKey),
            ["data"] = TestCipher.Create(payload.ToJsonString(), stretchedEncryptionKey, stretchedMacKey),
        };

        VaultMetadata? metadata = new EncryptedJsonParser().Parse(root, new StubAccountSelector(), "export.json");
        metadata.Should().NotBeNull();
        BitwardenSecrets secrets = new KeyDerivationService(metadata!, new ProtectedKeyDecryptor())
            .DeriveKeys(TestData.Password);
        DecryptionContext context = new(metadata!.FileFormat, string.Empty, string.Empty, IncludeSends: false);

        JsonObject result = new VaultDataDecryptor(secrets, context, new ProtectedKeyDecryptor()).DecryptVault(root);

        result["folders"]!.AsArray()[0]!["name"]!.GetValue<string>().Should().Be("Work");
        result["items"]!.AsArray()[0]!["login"]!["username"]!.GetValue<string>().Should().Be("person@example.com");
    }

    [Fact]
    public void Format2024Vault_DecryptsNestedItemsAndFolders()
    {
        BitwardenSecrets secrets = CreateLocalSecrets();
        JsonObject root = new()
        {
            [$"user_{AccountId}_ciphers_ciphers"] = new JsonObject
            {
                ["cipher-1"] = new JsonObject
                {
                    ["name"] = TestCipher.Create(
                        "Example login",
                        secrets.GeneratedEncryptionKey,
                        secrets.GeneratedMacKey),
                    ["login"] = new JsonObject
                    {
                        ["username"] = TestCipher.Create(
                            "person@example.com",
                            secrets.GeneratedEncryptionKey,
                            secrets.GeneratedMacKey),
                    },
                    ["favorite"] = true,
                    ["userId"] = "remove-me",
                    ["organizationUserId"] = "remove-me-too",
                },
            },
            [$"user_{AccountId}_folder_folders"] = new JsonObject
            {
                ["folder-group"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["name"] = TestCipher.Create("Work", secrets.GeneratedEncryptionKey, secrets.GeneratedMacKey),
                    },
                },
            },
            [$"user_{AccountId}_encryptedSend_sendUserEncrypted"] = new JsonObject
            {
                ["send-1"] = new JsonObject { ["name"] = "not processed" },
            },
        };
        DecryptionContext context = new("2024", AccountId, TestData.Email, IncludeSends: false);

        JsonObject result = new VaultDataDecryptor(secrets, context, new ProtectedKeyDecryptor()).DecryptVault(root);

        JsonObject item = result["items"]!.AsArray()[0]!.AsObject();
        item["name"]!.GetValue<string>().Should().Be("Example login");
        item["login"]!["username"]!.GetValue<string>().Should().Be("person@example.com");
        item["favorite"]!.GetValue<bool>().Should().BeTrue();
        item.ContainsKey("userId").Should().BeFalse();
        item.ContainsKey("organizationUserId").Should().BeFalse();
        result["folders"]!.AsArray()[0]!["name"]!.GetValue<string>().Should().Be("Work");
        result.ContainsKey("sends").Should().BeFalse();
    }

    [Fact]
    public void NewFormatVault_DecryptsLegacyDataGroups()
    {
        BitwardenSecrets secrets = CreateLocalSecrets();
        JsonObject root = new()
        {
            [AccountId] = new JsonObject
            {
                ["data"] = new JsonObject
                {
                    ["ciphers_login"] = new JsonObject
                    {
                        ["encrypted"] = new JsonObject
                        {
                            ["cipher-1"] = new JsonObject
                            {
                                ["name"] = TestCipher.Create(
                                    "Legacy login",
                                    secrets.GeneratedEncryptionKey,
                                    secrets.GeneratedMacKey),
                                ["userId"] = "remove-me",
                            },
                        },
                    },
                    ["unsupported_data"] = new JsonObject(),
                },
            },
        };
        DecryptionContext context = new("NEW", AccountId, TestData.Email, IncludeSends: false);

        JsonObject result = new VaultDataDecryptor(secrets, context, new ProtectedKeyDecryptor()).DecryptVault(root);

        JsonObject item = result["items"]!.AsArray()[0]!.AsObject();
        item["name"]!.GetValue<string>().Should().Be("Legacy login");
        item.ContainsKey("userId").Should().BeFalse();
        result.ContainsKey("unsupported").Should().BeFalse();
    }

    [Fact]
    public void DecryptSend_DerivesSendKeysAndDecryptsContent()
    {
        BitwardenSecrets secrets = CreateLocalSecrets();
        byte[] sendKey = TestData.Key(30, 64);
        byte[] derivedSendKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            sendKey,
            64,
            Encoding.UTF8.GetBytes("bitwarden-send"),
            Encoding.UTF8.GetBytes("send"));
        byte[] sendEncryptionKey = [.. derivedSendKey.Take(32)];
        byte[] sendMacKey = [.. derivedSendKey.Skip(32).Take(32)];
        JsonObject send = new()
        {
            ["key"] = TestCipher.Create(sendKey, secrets.GeneratedEncryptionKey, secrets.GeneratedMacKey),
            ["name"] = TestCipher.Create("Shared secret", sendEncryptionKey, sendMacKey),
            ["text"] = new JsonObject
            {
                ["text"] = TestCipher.Create("Send body", sendEncryptionKey, sendMacKey),
            },
        };
        VaultItemDecryptor decryptor = new(secrets, new ProtectedKeyDecryptor());

        JsonNode? result = decryptor.DecryptSend(send);

        result.Should().NotBeNull();
        JsonObject decryptedSend = result!.AsObject();
        decryptedSend["name"]!.GetValue<string>().Should().Be("Shared secret");
        decryptedSend["text"]!["text"]!.GetValue<string>().Should().Be("Send body");
        decryptedSend["key"]!.GetValue<string>().Should().Be(Convert.ToHexString(derivedSendKey).ToLowerInvariant());
    }

    private static BitwardenSecrets CreateLocalSecrets()
    {
        byte[] fullKey = TestData.Key(20, 64);
        return new()
        {
            GeneratedSymmetricKey = fullKey,
            GeneratedEncryptionKey = [.. fullKey.Take(32)],
            GeneratedMacKey = [.. fullKey.Skip(32).Take(32)],
        };
    }
}
