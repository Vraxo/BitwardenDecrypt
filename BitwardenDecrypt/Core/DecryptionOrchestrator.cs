using BitwardenDecryptor.Core.VaultParsing;
using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class DecryptionOrchestrator
{
    private readonly IProtectedKeyDecryptor _protectedKeyDecryptor;
    private readonly ConsoleUserInteractor _userInteractor;
    private readonly IAccountSelector _accountSelector;
    private readonly VaultParser _vaultParser;

    public DecryptionOrchestrator(
        IProtectedKeyDecryptor protectedKeyDecryptor,
        ConsoleUserInteractor userInteractor,
        VaultParser vaultParser)
    {
        _protectedKeyDecryptor = protectedKeyDecryptor;
        _userInteractor = userInteractor;
        _accountSelector = userInteractor;
        _vaultParser = vaultParser;
    }

    public void HandleDecryptionCommand(string inputFile, bool includeSends, string? outputFile, bool save, string? password)
    {
        try
        {
            string? finalOutputFile = VaultFileHandler.DetermineOutputFile(inputFile, outputFile, save);
            RunDecryption(inputFile, includeSends, finalOutputFile, password);
        }
        catch (Exception ex)
        {
            ConsoleExceptionHandler.Handle(ex, inputFile);
            Environment.ExitCode = 1;
        }
    }

    private void RunDecryption(string inputFile, bool includeSends, string? outputFile, string? password)
    {
        _userInteractor.PrintOutputHeader(outputFile);

        JsonNode rootNode = VaultFileHandler.ReadAndParseVaultFile(inputFile);
        VaultMetadata metadata = ParseVaultMetadata(rootNode, inputFile);

        string effectivePassword = string.IsNullOrEmpty(password)
            ? _userInteractor.GetPasswordFromUser(metadata)
            : password;

        KeyDerivationService keyDerivationService = new(metadata, _protectedKeyDecryptor);
        BitwardenSecrets secrets = keyDerivationService.DeriveKeys(effectivePassword);

        JsonObject decryptedData = DecryptVaultData(rootNode, secrets, metadata, includeSends);
        string decryptedJson = SerializeDecryptedData(decryptedData);

        if (outputFile is not null)
        {
            VaultFileHandler.WriteOutputToFile(decryptedJson, outputFile);
            _userInteractor.NotifySuccess(outputFile);
        }
        else
        {
            _userInteractor.WriteDecryptedJsonToConsole(decryptedJson);
        }
    }

    private VaultMetadata ParseVaultMetadata(JsonNode rootNode, string inputFile)
    {
        return _vaultParser.Parse(rootNode, _accountSelector, inputFile)
            ?? throw new VaultFormatException("Could not determine the format of the provided JSON file or find any account data within it.");
    }

    private JsonObject DecryptVaultData(JsonNode rootNode, BitwardenSecrets secrets, VaultMetadata metadata, bool includeSends)
    {
        DecryptionContext decryptionContext = new(
            FileFormat: metadata.FileFormat,
            AccountUuid: metadata.AccountUuid ?? string.Empty,
            AccountEmail: metadata.AccountEmail ?? string.Empty,
            IncludeSends: includeSends
        );

        VaultDataDecryptor vaultDataDecryptor = new(secrets, decryptionContext, _protectedKeyDecryptor);
        return vaultDataDecryptor.DecryptVault(rootNode);
    }

    private static string SerializeDecryptedData(JsonObject decryptedData)
    {
        JsonObject finalOutputObject = StructureOutputJson(decryptedData);
        JsonSerializerOptions jsonSerializerOptions = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        return finalOutputObject.ToJsonString(jsonSerializerOptions);
    }

    private static JsonObject StructureOutputJson(JsonObject decryptedData)
    {
        var finalOutputObject = new JsonObject();
        var keys = decryptedData.Select(p => p.Key).ToList();

        var orderedKeys = new List<string>();

        // 1. Add "folders" if it exists
        if (keys.Contains("folders"))
        {
            orderedKeys.Add("folders");
        }

        // 2. Add all other keys that aren't "folders" or "sends"
        orderedKeys.AddRange(keys.Where(k => k != "folders" && k != "sends"));

        // 3. Add "sends" if it exists
        if (keys.Contains("sends"))
        {
            orderedKeys.Add("sends");
        }

        // 4. Build the new object from the ordered keys
        foreach (var key in orderedKeys)
        {
            finalOutputObject[key] = decryptedData[key]!.DeepClone();
        }

        return finalOutputObject;
    }
}