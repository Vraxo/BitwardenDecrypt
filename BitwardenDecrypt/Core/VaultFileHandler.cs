using System.Text;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class VaultFileHandler
{
    public JsonNode ReadAndParseVaultFile(string inputFile)
    {
        string jsonData = File.ReadAllText(inputFile);
        return JsonNode.Parse(jsonData)!;
    }

    public void WriteOutputToFile(string decryptedJson, string outputFile)
    {
        File.WriteAllText(outputFile, decryptedJson, Encoding.UTF8);
    }

    public string? DetermineOutputFile(string inputFile, string? outputFile, bool save)
    {
        if (outputFile != null)
        {
            return outputFile;
        }

        if (save)
        {
            string? directory = Path.GetDirectoryName(inputFile);
            string filenameWithoutExt = Path.GetFileNameWithoutExtension(inputFile);
            string newFilename = $"{filenameWithoutExt}.decrypted.json";
            return string.IsNullOrEmpty(directory)
                ? newFilename
                : Path.Combine(directory, newFilename);
        }

        return null;
    }
}