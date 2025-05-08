using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using BitwardenDecryptor.Models;
using BitwardenDecryptor.Utils;

namespace BitwardenDecryptor.Core;

public class BitwardenDecryptor(CommandLineOptions options)
{
    private readonly CommandLineOptions options = options;

    public string? DecryptBitwardenJson()
    {
        JsonNode? rootNode = LoadAndParseInputFile();
        
        if (rootNode is null)
        {
            return null;
        }

        VaultFileParseResult parseResult = VaultFileParser.ParseAndExtractParameters(rootNode, options);
        
        if (!parseResult.Success)
        {
            Environment.Exit(1);
            return null;
        }

        string password = GetPasswordFromUser(parseResult);

        BitwardenSecrets secrets = KeyDerivationService.DeriveKeys(parseResult, password, options.FileFormat!);

        VaultDataDecryptor vaultDataDecryptor = new(secrets, options);
        JsonObject decryptedData = vaultDataDecryptor.DecryptVault(rootNode);

        JsonObject finalOutputObject = StructureOutputJson(decryptedData);

        JsonSerializerOptions jsonSerializerOptions = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        return finalOutputObject.ToJsonString(jsonSerializerOptions);
    }

    private JsonNode? LoadAndParseInputFile()
    {
        string jsonData;

        try
        {
            jsonData = File.ReadAllText(options.InputFile);
        }
        catch (FileNotFoundException)
        {
            Console.Error.WriteLine($"ERROR: {options.InputFile} not found.");
            Environment.Exit(1);
            return null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ERROR: An error occurred reading: {options.InputFile} - {ex.Message}");
            Environment.Exit(1);
            return null;
        }

        try
        {
            return JsonNode.Parse(jsonData)!;
        }
        catch (JsonException ex)
        {
            Console.Error.WriteLine($"ERROR: Failed to parse JSON data from input file - {ex.Message}");
            Environment.Exit(1);
            return null;
        }
    }

    private string GetPasswordFromUser(VaultFileParseResult parseResult)
    {
        string passwordPromptDetail = options.FileFormat == "EncryptedJSON"
            ? $"Export Password (for salt: {parseResult.EmailOrSalt})"
            : $"Master Password (for account: {options.AccountEmail})";

        return ConsolePasswordReader.ReadPassword($"Enter {passwordPromptDetail}: ");
    }

    private static JsonObject StructureOutputJson(JsonObject decryptedData)
    {
        JsonObject finalOutputObject = [];

        if (decryptedData.ContainsKey("folders"))
        {
            finalOutputObject["folders"] = decryptedData["folders"]!.DeepClone();
        }

        foreach (KeyValuePair<string, JsonNode?> prop in decryptedData)
        {
            if (prop.Key == "folders" || prop.Key == "sends")
            {
                continue;
            }

            finalOutputObject[prop.Key] = prop.Value!.DeepClone();
        }

        if (decryptedData.ContainsKey("sends"))
        {
            finalOutputObject["sends"] = decryptedData["sends"]!.DeepClone();
        }

        return finalOutputObject;
    }
}