using BitwardenDecryptor.Core.VaultParsing;
using BitwardenDecryptor.Core.VaultParsing.FormatParsers;
using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using System.CommandLine;
using System.Runtime.Intrinsics.X86;
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

    public void HandleDecryptionCommand(string inputFile, bool includeSends, string? outputFile, bool save, string? password)
    {
        try
        {
            string? finalOutputFile = _fileHandler.DetermineOutputFile(inputFile, outputFile, save);
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

        JsonNode rootNode = _fileHandler.ReadAndParseVaultFile(inputFile);
        VaultMetadata metadata = ParseVaultMetadata(rootNode, inputFile);

        string effectivePassword = string.IsNullOrEmpty(password)
            ? _userInteractor.GetPasswordFromUser(metadata)
            : password;

        KeyDerivationService keyDerivationService = new(metadata, _protectedKeyDecryptor);
        BitwardenSecrets secrets = keyDerivationService.DeriveKeys(effectivePassword);

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
        var finalOutputObject = new JsonObject();
        var keys = decryptedData.Select(p => p.Key).ToList();

        // Ensure "folders" is first, if it exists.
        if (keys.Remove("folders"))
        {
            finalOutputObject["folders"] = decryptedData["folders"]!.DeepClone();
        }

        // Keep a placeholder for "sends" to be added last.
        bool hasSends = keys.Remove("sends");

        // Add all other items.
        foreach (var key in keys)
        {
            finalOutputObject[key] = decryptedData[key]!.DeepClone();
        }

        // Add "sends" at the end, if it exists.
        if (hasSends)
        {
            finalOutputObject["sends"] = decryptedData["sends"]!.DeepClone();
        }

        return finalOutputObject;
    }
}