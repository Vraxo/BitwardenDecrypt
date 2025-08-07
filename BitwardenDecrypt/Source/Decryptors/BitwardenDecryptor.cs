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

        VaultMetadata? metadata = VaultFileParser.Parse(rootNode, options.InputFile);
        
        if (metadata is null)
        {
            Environment.Exit(1);
            return null;
        }

        options.FileFormat = metadata.FileFormat;
        options.AccountEmail = metadata.AccountEmail ?? string.Empty;
        options.AccountUuid = metadata.AccountUuid ?? string.Empty;

        string password = GetPasswordFromUser(metadata);

        BitwardenSecrets secrets = KeyDerivationService.DeriveKeys(metadata, password);

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
            Console.Error.WriteLine($"\nERROR: The input file '{options.InputFile}' was not found.");
            Console.Error.WriteLine("\nPlease check the following:");
            Console.Error.WriteLine($"  1. The file '{options.InputFile}' actually exists in the current directory.");
            Console.Error.WriteLine("  2. You have spelled the filename correctly.");
            Console.Error.WriteLine("  3. If the file is in a different directory, provide the full path to it.");
            Console.Error.WriteLine("     Example: bitwardendecrypt \"C:\\Users\\YourUser\\Downloads\\data.json\"");
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
            Console.Error.WriteLine($"\nERROR: The file '{options.InputFile}' could not be read because it is not valid JSON.");
            Console.Error.WriteLine("Please ensure it is a proper, unmodified export from Bitwarden.");
            Console.Error.WriteLine($"Details: {ex.Message}");
            Environment.Exit(1);
            return null;
        }
    }

    private string GetPasswordFromUser(VaultMetadata metadata)
    {
        string passwordPromptDetail = metadata.FileFormat == "EncryptedJSON"
            ? $"Export Password (for salt: {metadata.KdfSalt})"
            : $"Master Password (for account: {metadata.AccountEmail})";

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
