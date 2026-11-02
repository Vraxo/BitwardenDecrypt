using AwesomeAssertions;
using BitwardenDecryptor.Core;
using System.Text.Json.Nodes;
using Xunit;

namespace BitwardenDecryptor.Tests;

public class VaultFileHandlerTests
{
    [Theory]
    [InlineData("custom.json", false, "custom.json")]
    [InlineData("custom.json", true, "custom.json")]
    [InlineData(null, false, null)]
    public void DetermineOutputFile_OutputOptionAndDefaultBehavior_AreRespected(
        string? outputFile,
        bool save,
        string? expected)
    {
        string? result = VaultFileHandler.DetermineOutputFile("vault.json", outputFile, save);

        result.Should().Be(expected);
    }

    [Fact]
    public void DetermineOutputFile_SaveWithoutOutput_UsesDecryptedSuffixNextToInput()
    {
        string inputFile = Path.Combine("some", "vault.json");

        string? result = VaultFileHandler.DetermineOutputFile(inputFile, outputFile: null, save: true);

        result.Should().Be(Path.Combine("some", "vault.decrypted.json"));
    }

    [Fact]
    public void FileHandler_ReadsUtf8JsonAndOverwritesOutput()
    {
        using TemporaryDirectory directory = new();
        string filePath = directory.FilePath("vault.json");
        VaultFileHandler.WriteOutputToFile("""{ "message": "Hello ☃", "value": 42 }""", filePath);

        JsonNode root = VaultFileHandler.ReadAndParseVaultFile(filePath);

        root["message"]!.GetValue<string>().Should().Be("Hello ☃");
        root["value"]!.GetValue<int>().Should().Be(42);

        VaultFileHandler.WriteOutputToFile("updated", filePath);
        File.ReadAllText(filePath).Should().Be("updated");
    }
}
