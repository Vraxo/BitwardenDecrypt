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
    private readonly VaultFileHandler _fileHandler;
    private readonly ConsoleUserInteractor _userInteractor;
    private readonly IAccountSelector _accountSelector;
    private readonly VaultParser _vaultParser;

    public DecryptionOrchestrator(
        IProtectedKeyDecryptor protectedKeyDecryptor,
        VaultFileHandler fileHandler,
        ConsoleUserInteractor userInteractor,
        VaultParser vaultParser)
    {
        _protectedKeyDecryptor = protectedKeyDecryptor;
        _fileHandler = fileHandler;
        _userInteractor = userInteractor;
        _accountSelector = userInteractor;
        _vaultParser = vaultParser;
    }

    public void RunDecryption(string inputFile, bool includeSends, string? outputFile)
    {
        _userInteractor.PrintOutputHeader(outputFile);

        JsonNode rootNode = _fileHandler.ReadAndParseVaultFile(inputFile);
        VaultMetadata metadata = ParseVaultMetadata(rootNode, inputFile);
        string password = _userInteractor.GetPasswordFromUser(metadata);

        KeyDerivationService keyDerivationService = new(metadata, _protectedKeyDecryptor);
        BitwardenSecrets secrets = keyDerivationService.DeriveKeys(password);

        JsonObject decryptedData = DecryptVaultData(rootNode, secrets, metadata, includeSends);
        string decryptedJson = SerializeDecryptedData(decryptedData);

        if (outputFile != null)
        {
            _fileHandler.WriteOutputToFile(decryptedJson, outputFile);
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
        JsonObject finalOutputObject = [];

        if (decryptedData.ContainsKey("folders"))
        {
            finalOutputObject["folders"] = decryptedData["folders"]!.DeepClone();
        }

        foreach (KeyValuePair<string, JsonNode?> prop in decryptedData)
        {
            if (prop.Key is "folders" or "sends")
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