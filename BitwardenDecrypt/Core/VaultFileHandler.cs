using System.Text;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public static class VaultFileHandler
{
    public static JsonNode ReadAndParseVaultFile(string inputFile)
    {
        string jsonData = File.ReadAllText(inputFile);
        return JsonNode.Parse(jsonData)!;
    }

    public static void WriteOutputToFile(string decryptedJson, string outputFile)
    {
        File.WriteAllText(outputFile, decryptedJson, Encoding.UTF8);
    }

    public static string? DetermineOutputFile(string inputFile, string? outputFile, bool save)
    {
        if (outputFile is not null)
        {
            return outputFile;
        }

        if (!save)
        {
            return null;
        }

        string? directory = Path.GetDirectoryName(inputFile);
        string filenameWithoutExt = Path.GetFileNameWithoutExtension(inputFile);
        string newFilename = $"{filenameWithoutExt}.decrypted.json";

        return Path.Combine(directory ?? "", newFilename);
    }
}