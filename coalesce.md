### `BitwardenDecrypt\BitwardenDecrypt.csproj`

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Isopoh.Cryptography.Argon2" Version="2.0.0" />
    <PackageReference Include="System.CommandLine" Version="2.0.0-beta4.22272.1" />
  </ItemGroup>

</Project>
```

---

### `BitwardenDecrypt\Core\ConsoleExceptionHandler.cs`

```csharp
using BitwardenDecryptor.Exceptions;
using System.Text.Json;

namespace BitwardenDecryptor.Core;

public static class ConsoleExceptionHandler
{
    public static void Handle(Exception ex, string? inputFile = null)
    {
        Console.Error.WriteLine();
        switch (ex)
        {
            case FileNotFoundException:
                Console.Error.WriteLine($"ERROR: The input file '{inputFile}' was not found.");
                Console.Error.WriteLine("\nPlease check the following:");
                Console.Error.WriteLine($"  1. The file '{inputFile}' actually exists in the current directory.");
                Console.Error.WriteLine("  2. You have spelled the filename correctly.");
                Console.Error.WriteLine("  3. If the file is in a different directory, provide the full path to it.");
                Console.Error.WriteLine("     Example: bitwardendecrypt \"C:\\Users\\YourUser\\Downloads\\data.json\"");
                break;
            case JsonException:
                Console.Error.WriteLine($"ERROR: The file '{inputFile}' could not be read because it is not valid JSON.");
                Console.Error.WriteLine("Please ensure it is a proper, unmodified export from Bitwarden.");
                Console.Error.WriteLine($"Details: {ex.Message}");
                break;
            case VaultFormatException or KeyDerivationException or DecryptionException or InvalidOperationException:
                Console.Error.WriteLine($"ERROR: {ex.Message}");
                break;
            default:
                Console.Error.WriteLine("An unexpected error occurred:");
                Console.Error.WriteLine($"ERROR: {ex.Message}");
                Console.Error.WriteLine("\nPlease report this issue if you believe it's a bug.");
                break;
        }
    }
}
```

---

### `BitwardenDecrypt\Core\ConsoleUserInteractor.cs`

```csharp
using BitwardenDecryptor.Core.VaultParsing;
using BitwardenDecryptor.Models;
using BitwardenDecryptor.Utils;

namespace BitwardenDecryptor.Core;

public class ConsoleUserInteractor : IAccountSelector
{
    public void PrintOutputHeader(string? outputFile)
    {
        Console.WriteLine();
        if (!string.IsNullOrEmpty(outputFile))
        {
            Console.WriteLine(File.Exists(outputFile)
                ? $"Saving Output To: {outputFile} (File Exists, Will Be Overwritten)\n"
                : $"Saving Output To: {outputFile}\n");
        }
    }

    public string GetPasswordFromUser(VaultMetadata metadata)
    {
        string passwordPromptDetail = metadata.FileFormat == "EncryptedJSON"
            ? $"Export Password (for salt: {metadata.KdfSalt})"
            : $"Master Password (for account: {metadata.AccountEmail})";
        return ConsolePasswordReader.ReadPassword($"Enter {passwordPromptDetail}: ");
    }

    public void WriteDecryptedJsonToConsole(string decryptedJson)
    {
        Console.WriteLine(decryptedJson);
    }

    public void NotifySuccess(string outputFile)
    {
        Console.WriteLine($"Successfully wrote decrypted data to {outputFile}");
    }

    public AccountInfo? SelectAccount(IReadOnlyList<AccountInfo> accounts, string context)
    {
        if (accounts.Count == 0)
        {
            Console.Error.WriteLine($"ERROR: No Accounts Found In {context}");
            return null;
        }

        if (accounts.Count == 1)
        {
            return accounts[0];
        }

        Console.WriteLine("Which Account Would You Like To Decrypt?");

        for (int i = 0; i < accounts.Count; i++)
        {
            Console.WriteLine($" {i + 1}:\t{accounts[i].Email}");
        }

        int choice = 0;

        Console.WriteLine();

        while (choice < 1 || choice > accounts.Count)
        {
            Console.Write("Enter Number: ");

            if (!int.TryParse(Console.ReadLine(), out choice))
            {
                choice = 0;
            }
        }

        Console.WriteLine();

        return accounts[choice - 1];
    }
}
```

---

### `BitwardenDecrypt\Core\DecryptionOrchestrator.cs`

```csharp
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
```

---

### `BitwardenDecrypt\Core\PathHandler.cs`

```csharp
namespace BitwardenDecryptor.Core;

public static class PathHandler
{
    public static void HandleInstallPath()
    {
        try
        {
            string exeDir = GetExecutableDirectory();
            Console.WriteLine($"Attempting to add '{exeDir}' to the user PATH variable.");

            string pathVar = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "";
            List<string> paths = pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).ToList();

            if (paths.Any(p => p.Equals(exeDir, StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("Application directory is already in the user PATH. No changes made.");
                return;
            }

            paths.Add(exeDir);
            string newPath = string.Join(Path.PathSeparator, paths);
            Environment.SetEnvironmentVariable("PATH", newPath, EnvironmentVariableTarget.User);

            Console.WriteLine("\nSuccessfully added application directory to the user PATH.");
            Console.WriteLine("You may need to restart your terminal/shell or log out and back in for the changes to take effect.");
        }
        catch (Exception ex)
        {
            ConsoleExceptionHandler.Handle(ex);
            Environment.ExitCode = 1;
        }
    }

    public static void HandleUninstallPath()
    {
        try
        {
            string exeDir = GetExecutableDirectory();
            Console.WriteLine($"Attempting to remove '{exeDir}' from the user PATH variable.");

            string? pathVar = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User);
            if (string.IsNullOrEmpty(pathVar))
            {
                Console.WriteLine("User PATH is empty or not set. No changes needed.");
                return;
            }

            List<string> paths = pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).ToList();
            int removedCount = paths.RemoveAll(p => p.Equals(exeDir, StringComparison.OrdinalIgnoreCase));

            if (removedCount > 0)
            {
                string newPath = string.Join(Path.PathSeparator, paths);
                Environment.SetEnvironmentVariable("PATH", newPath, EnvironmentVariableTarget.User);
                Console.WriteLine("\nSuccessfully removed application directory from the user PATH.");
                Console.WriteLine("You may need to restart your terminal/shell or log out and back in for the changes to take effect.");
            }
            else
            {
                Console.WriteLine("Application directory was not found in the user PATH. No changes made.");
            }
        }
        catch (Exception ex)
        {
            ConsoleExceptionHandler.Handle(ex);
            Environment.ExitCode = 1;
        }
    }

    private static string GetExecutableDirectory()
    {
        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            throw new InvalidOperationException("Could not determine the application's path.");
        }

        string? exeDir = Path.GetDirectoryName(exePath);
        if (string.IsNullOrEmpty(exeDir))
        {
            throw new InvalidOperationException("Could not determine the application's directory.");
        }

        return exeDir;
    }
}
```

---

### `BitwardenDecrypt\Core\Program.cs`

```csharp
using BitwardenDecryptor.Core.VaultParsing;
using BitwardenDecryptor.Core.VaultParsing.FormatParsers;
using System.CommandLine;
using System.Text;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public static class Program
{
    public static int Main(string[] args)
    {
        IProtectedKeyDecryptor protectedKeyDecryptor = new ProtectedKeyDecryptor();
        ConsoleUserInteractor userInteractor = new();

        VaultParser vaultParser = new(
        [
            new EncryptedJsonParser(),
            new Format2024Parser(),
            new NewFormatParser(),
            new OldFormatParser(),
        ]);

        DecryptionOrchestrator orchestrator = new(protectedKeyDecryptor, userInteractor, vaultParser);

        RootCommand rootCommand = BuildCommandLine(orchestrator);

        return rootCommand.Invoke(args);
    }

    private static RootCommand BuildCommandLine(DecryptionOrchestrator orchestrator)
    {
        RootCommand rootCommand = new("Decrypts an encrypted Bitwarden data.json file.");

        Argument<string> inputFileArgument = new(
            name: "inputfile",
            description: "Path to the Bitwarden data.json file.",
            getDefaultValue: () => "data.json");

        Option<bool> includeSendsOption = new(
            name: "--includesends",
            description: "Include Sends in the output.");

        Option<string?> outputFileOption = new(
            name: "--output",
            description: "Write decrypted output to file. Will overwrite if file exists.");

        Option<bool> saveOption = new(
            name: "--save",
            description: "Save the decrypted output to a file with a default name (e.g., 'data.json' becomes 'data.decrypted.json'). This is ignored if --output is used.");
        saveOption.AddAlias("-s");

        Option<string?> passwordOption = new(
            name: "--password",
            description: "The Master Password or Export Password. If not provided, you will be prompted.");
        passwordOption.AddAlias("-p");

        rootCommand.AddArgument(inputFileArgument);
        rootCommand.AddOption(includeSendsOption);
        rootCommand.AddOption(outputFileOption);
        rootCommand.AddOption(saveOption);
        rootCommand.AddOption(passwordOption);

        rootCommand.SetHandler(orchestrator.HandleDecryptionCommand,
            inputFileArgument, includeSendsOption, outputFileOption, saveOption, passwordOption);

        Command installPathCommand = new("install-path", "Adds the application's directory to the PATH environment variable for the current user.");
        installPathCommand.SetHandler(PathHandler.HandleInstallPath);
        rootCommand.AddCommand(installPathCommand);

        Command uninstallPathCommand = new("uninstall-path", "Removes the application's directory from the PATH environment variable for the current user.");
        uninstallPathCommand.SetHandler(PathHandler.HandleUninstallPath);
        rootCommand.AddCommand(uninstallPathCommand);

        return rootCommand;
    }
}
```

---

### `BitwardenDecrypt\Core\VaultFileHandler.cs`

```csharp
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
```

---

### `BitwardenDecrypt\Core\VaultMetadata.cs`

```csharp
namespace BitwardenDecryptor.Core;

public record VaultMetadata(
    string FileFormat,
    string KdfSalt,
    int KdfIterations,
    int? KdfMemory,
    int? KdfParallelism,
    int KdfType,
    string ProtectedSymmetricKey,
    string? ProtectedRsaPrivateKey,
    string? AccountEmail = null,
    string? AccountUuid = null);
```

---

### `BitwardenDecrypt\Decryptors\GenericJsonDecryptor.cs`

```csharp
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;
using System.Text;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class GenericJsonDecryptor
{
    private readonly BitwardenSecrets _secrets;
    private readonly IProtectedKeyDecryptor _protectedKeyDecryptor;

    public GenericJsonDecryptor(BitwardenSecrets secrets, IProtectedKeyDecryptor protectedKeyDecryptor)
    {
        _secrets = secrets;
        _protectedKeyDecryptor = protectedKeyDecryptor;
    }

    public string DecryptCipherString(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        if (string.IsNullOrEmpty(cipherString))
        {
            return string.Empty;
        }

        if (!IsValidCipherStringFormat(cipherString))
        {
            return $"ERROR Decrypting: Invalid CipherString format {cipherString}";
        }

        DecryptionResult decryptionResult = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);
        return decryptionResult.Error is not null || decryptionResult.Plaintext is null
            ? $"ERROR: {decryptionResult.Error}. CipherString not decrypted: {cipherString}"
            : ProcessDecryptedPlaintext(decryptionResult.Plaintext, cipherString);
    }

    public JsonNode? DecryptAllCiphersInNode(JsonNode? node, byte[] encKey, byte[] macKey)
    {
        switch (node)
        {
            case null:
                return null;
            case JsonValue val when val.TryGetValue<string>(out string? strValue) && IsPotentiallyCipherString(strValue):
                return JsonValue.Create(DecryptCipherString(strValue, encKey, macKey));
            case JsonObject obj:
                JsonObject newObj = [];
                foreach (KeyValuePair<string, JsonNode?> prop in obj)
                {
                    newObj[prop.Key] = DecryptAllCiphersInNode(prop.Value, encKey, macKey);
                }
                return newObj;
            case JsonArray arr:
                JsonArray newArr = [];
                foreach (JsonNode? item in arr)
                {
                    newArr.Add(DecryptAllCiphersInNode(item, encKey, macKey));
                }
                return newArr;
            default:
                return node.DeepClone();
        }
    }

    private string ProcessDecryptedPlaintext(byte[] plaintext, string originalCipherString)
    {
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (DecoderFallbackException)
        {
            return AttemptFallbackDecryption(originalCipherString);
        }
    }

    private string AttemptFallbackDecryption(string cipherString)
    {
        if (_secrets.GeneratedEncryptionKey.Length == 0 || _secrets.GeneratedMacKey.Length == 0)
        {
            return $"ERROR Decrypting (UTF-8 decode failed, fallback keys unavailable): {cipherString}";
        }

        SymmetricKeyDecryptionResult fallbackResult = _protectedKeyDecryptor.DecryptSymmetricKey(cipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);

        return fallbackResult.Error is null && fallbackResult.FullKey is not null
            ? BitConverter.ToString(fallbackResult.FullKey).Replace("-", "").ToLowerInvariant()
            : $"ERROR Decrypting (UTF-8 decode failed, fallback also failed): {cipherString}";
    }

    private static bool IsValidCipherStringFormat(string cipherString)
    {
        string[] parts = cipherString.Split('.');
        return parts.Length >= 2 && int.TryParse(parts[0], out _);
    }

    private static bool IsPotentiallyCipherString(string value)
    {
        return value.Length > 2 && char.IsDigit(value[0]) && value[1] == '.' && value.Contains('|');
    }
}
```

---

### `BitwardenDecrypt\Decryptors\IProtectedKeyDecryptor.cs`

```csharp
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public interface IProtectedKeyDecryptor
{
    SymmetricKeyDecryptionResult DecryptSymmetricKey(string cipherString, byte[] masterKey, byte[] masterMacKey, bool isExportValidationKey = false);
    byte[]? DecryptRsaPrivateKeyBytes(string cipherString, byte[] encryptionKey, byte[] macKey);
}
```

---

### `BitwardenDecrypt\Decryptors\ProtectedKeyDecryptor.cs`

```csharp
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class ProtectedKeyDecryptor : IProtectedKeyDecryptor
{
    public SymmetricKeyDecryptionResult DecryptSymmetricKey(string cipherString, byte[] masterKey, byte[] masterMacKey, bool isExportValidationKey = false)
    {
        if (string.IsNullOrEmpty(cipherString))
        {
            return new(null, null, null, "CipherString is empty.");
        }

        (int encryptionType, string? error) = ParseCipherStringHeader(cipherString);

        if (error is not null)
        {
            return new(null, null, null, error);
        }

        DecryptionResult decryptionResult = CryptoService.VerifyAndDecryptAesCbc(masterKey, masterMacKey, cipherString);

        return decryptionResult.Error is not null || decryptionResult.Plaintext is null
            ? new(null, null, null, decryptionResult.Error)
            : ProcessDecryptedKey(decryptionResult.Plaintext, encryptionType, isExportValidationKey);
    }

    private static (int EncryptionType, string? Error) ParseCipherStringHeader(string cipherString)
    {
        string[] parts = cipherString.Split('.');

        if (parts.Length < 2)
        {
            return (0, "Invalid CipherString format.");
        }

        if (!int.TryParse(parts[0], out int encType))
        {
            return (0, "Invalid encryption type in CipherString.");
        }

        return (encType, null);
    }

    private static SymmetricKeyDecryptionResult ProcessDecryptedKey(byte[] cleartextBytes, int encType, bool isExportValidationKey)
    {
        if (!isExportValidationKey && encType == 2 && cleartextBytes.Length < 64)
        {
            return new(
                null,
                null,
                null,
                "Decrypted key is too short. Likely wrong password (for data.json user key).");
        }

        bool isCompositeKeyType = encType is 2 or 0;

        if (!isCompositeKeyType || cleartextBytes.Length < 64)
        {
            return new(cleartextBytes, null, null, null);
        }

        byte[] enc = [.. cleartextBytes.Take(32)];
        byte[] mac = [.. cleartextBytes.Skip(32).Take(32)];

        return new(cleartextBytes, enc, mac, null);
    }

    public byte[]? DecryptRsaPrivateKeyBytes(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        DecryptionResult result = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);

        return result.Error is not null ? null : result.Plaintext;
    }
}
```

---

### `BitwardenDecrypt\Decryptors\VaultDataDecryptor.cs`

```csharp
using BitwardenDecryptor.Core.VaultStrategies;
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class VaultDataDecryptor
{
    private readonly BitwardenSecrets _secrets;
    private readonly DecryptionContext _context;
    private readonly IProtectedKeyDecryptor _protectedKeyDecryptor;

    public VaultDataDecryptor(BitwardenSecrets secrets, DecryptionContext context, IProtectedKeyDecryptor protectedKeyDecryptor)
    {
        _secrets = secrets;
        _context = context;
        _protectedKeyDecryptor = protectedKeyDecryptor;
    }

    public JsonObject DecryptVault(JsonNode rootNode)
    {
        IVaultDecryptorStrategy strategy = CreateStrategy(rootNode);
        return strategy.Decrypt();
    }

    private IVaultDecryptorStrategy CreateStrategy(JsonNode rootNode)
    {
        VaultItemDecryptor vaultItemDecryptor = new(_secrets, _protectedKeyDecryptor);

        return _context.FileFormat switch
        {
            "EncryptedJSON" => new EncryptedJsonDecryptorStrategy(rootNode, _secrets, vaultItemDecryptor),
            "2024" => new Format2024DecryptorStrategy(rootNode, _secrets, _context, vaultItemDecryptor),
            "NEW" or "OLD" => new LegacyJsonDecryptorStrategy(rootNode, _secrets, _context, vaultItemDecryptor),
            _ => throw new NotSupportedException($"The file format '{_context.FileFormat}' is not supported.")
        };
    }
}
```

---

### `BitwardenDecrypt\Decryptors\VaultItemDecryptor.cs`

```csharp
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class VaultItemDecryptor
{
    private readonly BitwardenSecrets _secrets;
    private readonly GenericJsonDecryptor _genericDecryptor;
    private readonly IProtectedKeyDecryptor _protectedKeyDecryptor;

    public VaultItemDecryptor(BitwardenSecrets secrets, IProtectedKeyDecryptor protectedKeyDecryptor)
    {
        _secrets = secrets;
        _protectedKeyDecryptor = protectedKeyDecryptor;
        _genericDecryptor = new GenericJsonDecryptor(secrets, protectedKeyDecryptor);
    }

    public void DecryptAndStoreOrganizationKeys(JsonObject? orgKeysNode)
    {
        if (orgKeysNode is null || _secrets.RsaPrivateKeyDer is null)
        {
            return;
        }

        foreach (KeyValuePair<string, JsonNode?> kvp in orgKeysNode)
        {
            string? orgKeyCipher = kvp.Value?["key"]?.GetValue<string>() ?? kvp.Value?.GetValue<string>();

            if (orgKeyCipher is null)
            {
                continue;
            }

            byte[]? decryptedOrgKey = DecryptRsaInternal(orgKeyCipher);

            if (decryptedOrgKey is null)
            {
                continue;
            }

            _secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
        }
    }

    public string DecryptCipherString(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        return _genericDecryptor.DecryptCipherString(cipherString, encryptionKey, macKey);
    }

    public byte[]? DecryptRsaInternal(string cipherString)
    {
        if (_secrets.RsaPrivateKeyDer is null)
        {
            return null;
        }

        (byte[]? ciphertext, string? error) = ParseAndDecodeRsaCipher(cipherString);

        return error is not null 
            ? null 
            : CryptoService.DecryptRsaOaepSha1(_secrets.RsaPrivateKeyDer, ciphertext!);
    }

    public JsonNode? DecryptSend(JsonNode sendNode)
    {
        string? keyCipherString = sendNode["key"]?.GetValue<string>();

        if (keyCipherString is null)
        {
            return sendNode;
        }

        (byte[] encKey, byte[] macKey, byte[] fullKey)? derivedKeys = DecryptAndDeriveSendKeys(keyCipherString);
        if (derivedKeys is null)
        {
            sendNode["key"] = "ERROR: Failed to decrypt or derive Send key.";
            return sendNode;
        }

        if (sendNode is JsonObject obj)
        {
            obj["key"] = BitConverter.ToString(derivedKeys.Value.fullKey).Replace("-", "").ToLowerInvariant();
        }

        return _genericDecryptor.DecryptAllCiphersInNode(sendNode, derivedKeys.Value.encKey, derivedKeys.Value.macKey);
    }

    public JsonObject ProcessGroupItem(JsonNode groupItemNode)
    {
        (byte[] itemEncKey, byte[] itemMacKey) = GetDecryptionKeysForItem(groupItemNode);
        JsonNode decryptedNode = _genericDecryptor.DecryptAllCiphersInNode(groupItemNode, itemEncKey, itemMacKey)!;
        JsonObject processedNode = decryptedNode.AsObject();
        
        RemoveUserSpecificFields(processedNode);

        return processedNode;
    }

    private static (byte[]? Ciphertext, string? Error) ParseAndDecodeRsaCipher(string cipherString)
    {
        string[] parts = cipherString.Split('.');
        
        if (parts.Length < 2)
        {
            return (null, "Invalid RSA CipherString format");
        }

        string[] dataParts = parts[1].Split('|');
        
        if (dataParts.Length < 1)
        {
            return (null, "Invalid RSA CipherString data part");
        }

        try
        {
            byte[] ciphertext = Convert.FromBase64String(dataParts[0]);
            return (ciphertext, null);
        }
        catch (FormatException ex)
        {
            return (null, $"Base64 decoding failed for RSA ciphertext: {ex.Message}");
        }
    }

    private (byte[] encKey, byte[] macKey, byte[] fullKey)? DecryptAndDeriveSendKeys(string keyCipherString)
    {
        if (_secrets.GeneratedEncryptionKey.Length == 0 || _secrets.GeneratedMacKey.Length == 0)
        {
            return null;
        }

        SymmetricKeyDecryptionResult sendKeyResult = _protectedKeyDecryptor.DecryptSymmetricKey(keyCipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);

        if (sendKeyResult.Error is not null || sendKeyResult.FullKey is null)
        {
            return null;
        }

        byte[] salt = Encoding.UTF8.GetBytes("bitwarden-send");
        byte[] info = Encoding.UTF8.GetBytes("send");
        byte[] derivedSendKeyMaterial = HKDF.DeriveKey(HashAlgorithmName.SHA256, sendKeyResult.FullKey, 64, salt, info);

        byte[] sendEncKey = derivedSendKeyMaterial.Take(32).ToArray();
        byte[] sendMacKey = derivedSendKeyMaterial.Skip(32).Take(32).ToArray();

        return (sendEncKey, sendMacKey, derivedSendKeyMaterial);
    }

    private (byte[] encKey, byte[] macKey) GetDecryptionKeysForItem(JsonNode itemNode)
    {
        string? orgId = itemNode["organizationId"]?.GetValue<string>();
        (byte[] baseEncKey, byte[] baseMacKey) = GetBaseKeysForItem(orgId);

        string? individualItemKeyCipherString = itemNode["key"]?.GetValue<string>();
        
        if (string.IsNullOrEmpty(individualItemKeyCipherString))
        {
            return (baseEncKey, baseMacKey);
        }

        SymmetricKeyDecryptionResult itemKeyResult = _protectedKeyDecryptor.DecryptSymmetricKey(individualItemKeyCipherString, baseEncKey, baseMacKey);

        if (itemKeyResult.Error is null && itemKeyResult.EncKey is not null && itemKeyResult.MacKey is not null)
        {
            if (itemNode is JsonObject obj)
            {
                obj["key"] = "";
            }

            return (itemKeyResult.EncKey, itemKeyResult.MacKey);
        }
        else if (itemKeyResult.Error is not null && itemNode is JsonObject obj)
        {
            obj["key"] = $"ERROR: Could not decrypt item key. {itemKeyResult.Error}";
        }

        return (baseEncKey, baseMacKey);
    }

    private (byte[] encKey, byte[] macKey) GetBaseKeysForItem(string? orgId)
    {
        if (orgId is not null && _secrets.OrganizationKeys.TryGetValue(orgId, out byte[]? orgFullKey) && orgFullKey?.Length >= 64)
        {
            return (orgFullKey.Take(32).ToArray(), orgFullKey.Skip(32).Take(32).ToArray());
        }

        if (_secrets.GeneratedEncryptionKey.Length > 0 && _secrets.GeneratedMacKey.Length > 0)
        {
            return (_secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);
        }

        return (_secrets.StretchedEncryptionKey, _secrets.StretchedMacKey);
    }

    private static void RemoveUserSpecificFields(JsonObject processedNode)
    {
        string[] userIdKeys = ["userId", "organizationUserId"];

        foreach (string key in userIdKeys)
        {
            if (!processedNode.ContainsKey(key))
            {
                continue;
            }

            _ = processedNode.Remove(key);
        }
    }
}
```

---

### `BitwardenDecrypt\Exceptions\DecryptionException.cs`

```csharp
namespace BitwardenDecryptor.Exceptions;

public class DecryptionException : Exception
{
    public DecryptionException(string message)
        : base(message)
    {
    }

    public DecryptionException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
```

---

### `BitwardenDecrypt\Exceptions\KeyDerivationException.cs`

```csharp
namespace BitwardenDecryptor.Exceptions;

public class KeyDerivationException : Exception
{
    public KeyDerivationException()
    {
    }

    public KeyDerivationException(string message)
        : base(message)
    {
    }

    public KeyDerivationException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
```

---

### `BitwardenDecrypt\Exceptions\VaultFormatException.cs`

```csharp
namespace BitwardenDecryptor.Exceptions;

public class VaultFormatException : Exception
{
    public VaultFormatException(string message)
        : base(message)
    {
    }

    public VaultFormatException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
```

---

### `BitwardenDecrypt\Models\AccountInfo.cs`

```csharp
namespace BitwardenDecryptor.Models;

public record AccountInfo(string Uuid, string Email);
```

---

### `BitwardenDecrypt\Models\BitwardenSecrets.cs`

```csharp
namespace BitwardenDecryptor.Models;

public class BitwardenSecrets
{
    public string Email { get; set; } = string.Empty;
    public byte[] MasterPasswordBytes { get; set; } = [];
    public int KdfIterations { get; set; }
    public int? KdfMemory { get; set; }
    public int? KdfParallelism { get; set; }
    public int KdfType { get; set; }
    public string ProtectedSymmetricKeyCipherString { get; set; } = string.Empty;
    public string? ProtectedRsaPrivateKeyCipherString { get; set; }

    public byte[] MasterKey { get; set; } = [];
    public string MasterPasswordHash { get; set; } = string.Empty;

    public byte[] StretchedEncryptionKey { get; set; } = [];
    public byte[] StretchedMacKey { get; set; } = [];

    public byte[] GeneratedSymmetricKey { get; set; } = [];
    public byte[] GeneratedEncryptionKey { get; set; } = [];
    public byte[] GeneratedMacKey { get; set; } = [];

    public byte[]? RsaPrivateKeyDer { get; set; }

    public Dictionary<string, byte[]> OrganizationKeys { get; } = [];
}
```

---

### `BitwardenDecrypt\Models\DecryptionContext.cs`

```csharp
namespace BitwardenDecryptor.Models;

public record DecryptionContext(
    string FileFormat,
    string AccountUuid,
    string AccountEmail,
    bool IncludeSends
);
```

---

### `BitwardenDecrypt\Models\DecryptionResult.cs`

```csharp
namespace BitwardenDecryptor.Models;

public record DecryptionResult(byte[]? Plaintext, string? Error);
```

---

### `BitwardenDecrypt\Models\SymmetricKeyDecryptionResult.cs`

```csharp
namespace BitwardenDecryptor.Models;

public record SymmetricKeyDecryptionResult(byte[]? FullKey, byte[]? EncKey, byte[]? MacKey, string? Error);
```

---

### `BitwardenDecrypt\Services\CryptoService.cs`

```csharp
using BitwardenDecryptor.Models;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using System.Security.Cryptography;

namespace BitwardenDecryptor.Crypto;

public static class CryptoService
{
    public static byte[] DerivePbkdf2Sha256(byte[] password, byte[] salt, int iterations, int outputLength)
    {
        using Rfc2898DeriveBytes pbkdf2 = new(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(outputLength);
    }

    public static byte[] DeriveArgon2id(byte[] password, byte[] salt, int iterations, int memoryKiB, int parallelism, int outputLength)
    {
        Argon2Config config = new()
        {
            Type = Argon2Type.HybridAddressing,
            Version = Argon2Version.Nineteen,
            TimeCost = iterations,
            MemoryCost = memoryKiB,
            Lanes = parallelism,
            Threads = parallelism,
            Password = password,
            Salt = salt,
            HashLength = outputLength
        };

        using Argon2 argon2 = new(config);
        using SecureArray<byte> hashResult = argon2.Hash();
        return hashResult.Buffer;
    }

    public static byte[] HkdfExpandSha256(byte[] ikm, byte[] info, int outputLength)
    {
        return HKDF.Expand(HashAlgorithmName.SHA256, ikm, outputLength, info);
    }

    public static byte[] ComputeHmacSha256(byte[] key, byte[] data)
    {
        using HMACSHA256 hmac = new(key);
        return hmac.ComputeHash(data);
    }

    public static byte[]? DecryptAesCbc(byte[] key, byte[] iv, byte[] ciphertext, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        using Aes aes = Aes.Create();

        if (aes is null)
        {
            return null;
        }

        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = paddingMode;
        aes.Key = key;
        aes.IV = iv;

        using ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using MemoryStream msDecrypt = new(ciphertext);
        using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
        using MemoryStream msPlain = new();
        csDecrypt.CopyTo(msPlain);

        return msPlain.ToArray();
    }

    public static DecryptionResult VerifyAndDecryptAesCbc(byte[] encryptionKey, byte[] macKey, string cipherString)
    {
        string[] parts = cipherString.Split('.');

        if (parts.Length < 2)
        {
            return new DecryptionResult(null, "Invalid CipherString format (missing type or data).");
        }

        string[] dataParts = parts[1].Split('|');

        if (dataParts.Length < 3)
        {
            return new DecryptionResult(null, "Invalid CipherString format (missing IV, ciphertext, or MAC).");
        }

        byte[] iv;
        byte[] ciphertext;
        byte[] mac;

        try
        {
            iv = Convert.FromBase64String(dataParts[0]);
            ciphertext = Convert.FromBase64String(dataParts[1]);
            mac = Convert.FromBase64String(dataParts[2]);
        }
        catch (FormatException ex)
        {
            return new DecryptionResult(null, $"Base64 decoding failed: {ex.Message}");
        }

        byte[] dataToMac = [.. iv, .. ciphertext];
        byte[] calculatedMac = ComputeHmacSha256(macKey, dataToMac);

        if (!mac.SequenceEqual(calculatedMac))
        {
            return new DecryptionResult(null, "MAC mismatch.");
        }

        try
        {
            byte[]? decrypted = DecryptAesCbc(encryptionKey, iv, ciphertext);
            return new DecryptionResult(decrypted, null);
        }
        catch (CryptographicException ex)
        {
            return new DecryptionResult(null, $"Decryption failed (possibly wrong password/key or padding): {ex.Message}");
        }
    }

    public static byte[]? DecryptRsaOaepSha1(byte[] privateKeyDer, byte[] ciphertext)
    {
        try
        {
            using RSA rsa = RSA.Create();

            if (rsa is null)
            {
                return null;
            }

            try
            {
                rsa.ImportPkcs8PrivateKey(privateKeyDer, out _);
            }
            catch (CryptographicException)
            {
                try
                {
                    rsa.ImportRSAPrivateKey(privateKeyDer, out _);
                }
                catch (CryptographicException)
                {
                    return null;
                }
            }

            return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA1);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    public static byte[] Sha256Hash(byte[] data)
    {
        return SHA256.HashData(data);
    }
}
```

---

### `BitwardenDecrypt\Services\KeyDerivationService.cs`

```csharp
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using System.Text;

namespace BitwardenDecryptor.Core;

public class KeyDerivationService
{
    private readonly VaultMetadata _metadata;
    private readonly IProtectedKeyDecryptor _protectedKeyDecryptor;

    public KeyDerivationService(VaultMetadata metadata, IProtectedKeyDecryptor protectedKeyDecryptor)
    {
        _metadata = metadata;
        _protectedKeyDecryptor = protectedKeyDecryptor;
    }

    public BitwardenSecrets DeriveKeys(string password)
    {
        BitwardenSecrets secrets = InitializeSecrets(_metadata, password);
        byte[] kdfSaltInput = Encoding.UTF8.GetBytes(_metadata.KdfSalt);

        DeriveMasterKey(secrets, kdfSaltInput);
        DeriveMasterPasswordHash(secrets);
        DeriveStretchedKeys(secrets);
        DecryptAndSetSymmetricKeys(secrets, _metadata.FileFormat);
        DecryptAndSetRsaPrivateKey(secrets);

        return secrets;
    }

    private static BitwardenSecrets InitializeSecrets(VaultMetadata metadata, string password)
    {
        return new()
        {
            Email = metadata.AccountEmail ?? metadata.KdfSalt,
            MasterPasswordBytes = Encoding.UTF8.GetBytes(password),
            KdfIterations = metadata.KdfIterations,
            KdfMemory = metadata.KdfMemory,
            KdfParallelism = metadata.KdfParallelism,
            KdfType = metadata.KdfType,
            ProtectedSymmetricKeyCipherString = metadata.ProtectedSymmetricKey,
            ProtectedRsaPrivateKeyCipherString = metadata.ProtectedRsaPrivateKey
        };
    }

    private void DeriveMasterKey(BitwardenSecrets secrets, byte[] kdfSaltInput)
    {
        if (secrets.KdfType == 1) // Argon2id
        {
            DeriveMasterKeyWithArgon2id(secrets);
        }
        else // PBKDF2
        {
            DeriveMasterKeyWithPbkdf2(secrets, kdfSaltInput);
        }
    }

    private void DeriveMasterKeyWithArgon2id(BitwardenSecrets secrets)
    {
        if (!secrets.KdfMemory.HasValue || !secrets.KdfParallelism.HasValue)
        {
            throw new KeyDerivationException("KDF memory or parallelism not set for Argon2id.");
        }

        byte[] argonSalt = CryptoService.Sha256Hash(Encoding.UTF8.GetBytes(secrets.Email));
        secrets.MasterKey = CryptoService.DeriveArgon2id(
            secrets.MasterPasswordBytes,
            argonSalt,
            secrets.KdfIterations,
            secrets.KdfMemory.Value * 1024, // KDFMemory is in KiB, Argon2 expects bytes
            secrets.KdfParallelism.Value,
            32); // 32 bytes for master key
    }

    private void DeriveMasterKeyWithPbkdf2(BitwardenSecrets secrets, byte[] kdfSaltInput)
    {
        secrets.MasterKey = CryptoService.DerivePbkdf2Sha256(
           secrets.MasterPasswordBytes,
           kdfSaltInput,
           secrets.KdfIterations,
           32); // 32 bytes for master key
    }

    private void DeriveMasterPasswordHash(BitwardenSecrets secrets)
    {
        byte[] masterPasswordHashDerived = CryptoService.DerivePbkdf2Sha256(secrets.MasterKey, secrets.MasterPasswordBytes, 1, 32);
        secrets.MasterPasswordHash = Convert.ToBase64String(masterPasswordHashDerived);
    }

    private void DeriveStretchedKeys(BitwardenSecrets secrets)
    {
        secrets.StretchedEncryptionKey = CryptoService.HkdfExpandSha256(secrets.MasterKey, Encoding.UTF8.GetBytes("enc"), 32);
        secrets.StretchedMacKey = CryptoService.HkdfExpandSha256(secrets.MasterKey, Encoding.UTF8.GetBytes("mac"), 32);
    }

    private void DecryptAndSetSymmetricKeys(BitwardenSecrets secrets, string fileFormat)
    {
        bool isForExportValidation = fileFormat == "EncryptedJSON";
        SymmetricKeyDecryptionResult result = _protectedKeyDecryptor.DecryptSymmetricKey(
            secrets.ProtectedSymmetricKeyCipherString,
            secrets.StretchedEncryptionKey,
            secrets.StretchedMacKey,
            isForExportValidation);

        HandleSymmetricKeyDecryptionResult(result.Error, result.FullKey);

        // At this point, symKey is guaranteed to be non-null if HandleSymmetricKeyDecryptionResult did not throw.
        secrets.GeneratedSymmetricKey = result.FullKey!;
        secrets.GeneratedEncryptionKey = result.EncKey ?? [];
        secrets.GeneratedMacKey = result.MacKey ?? [];
    }

    private void HandleSymmetricKeyDecryptionResult(string? error, byte[]? symKey)
    {
        if (error is null && symKey is not null)
        {
            return;
        }

        string errorMessageToDisplay = error ?? "Symmetric key is null after decryption without explicit error.";
        string message = $"Failed to decrypt/validate Protected Symmetric Key or Export Validation Key. {errorMessageToDisplay}";

        if (error is not null &&
            (error.Contains("MAC mismatch", StringComparison.OrdinalIgnoreCase) ||
             error.Contains("padding", StringComparison.OrdinalIgnoreCase) ||
             error.Contains("Likely wrong password", StringComparison.OrdinalIgnoreCase)))
        {
            message += "\nThis often indicates a wrong password (either Master Password for data.json or Export Password for encrypted exports).";
        }
        else if (symKey is null && error is null)
        {
            message += "\nThis might indicate an unexpected issue with the decrypted data structure or a problem not caught by specific error checks.";
        }

        throw new KeyDerivationException(message);
    }

    private void DecryptAndSetRsaPrivateKey(BitwardenSecrets secrets)
    {
        if (string.IsNullOrEmpty(secrets.ProtectedRsaPrivateKeyCipherString))
        {
            return;
        }

        if (secrets.GeneratedEncryptionKey.Length == 0 || secrets.GeneratedMacKey.Length == 0)
        {
            throw new KeyDerivationException("Cannot decrypt RSA private key because dependent symmetric keys were not properly derived.");
        }

        secrets.RsaPrivateKeyDer = _protectedKeyDecryptor.DecryptRsaPrivateKeyBytes(
            secrets.ProtectedRsaPrivateKeyCipherString,
            secrets.GeneratedEncryptionKey,
            secrets.GeneratedMacKey);

        if (secrets.RsaPrivateKeyDer is not null)
        {
            return;
        }

        throw new KeyDerivationException("Failed to decrypt RSA Private Key.");
    }
}
```

---

### `BitwardenDecrypt\Utils\ConsolePasswordReader.cs`

```csharp
using System.Text;

namespace BitwardenDecryptor.Utils;

public static class ConsolePasswordReader
{
    public static string ReadPassword(string prompt)
    {
        Console.Write(prompt);

        StringBuilder password = new();

        while (true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey(true);

            if (keyInfo.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }

            if (keyInfo.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                password.Append(keyInfo.KeyChar);
            }
        }

        return password.ToString();
    }
}
```

---

### `BitwardenDecrypt\Core\VaultParsing\IAccountSelector.cs`

```csharp
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core.VaultParsing;

public interface IAccountSelector
{
    AccountInfo? SelectAccount(IReadOnlyList<AccountInfo> accounts, string context);
}
```

---

### `BitwardenDecrypt\Core\VaultParsing\IVaultFormatParser.cs`

```csharp
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing;

public interface IVaultFormatParser
{
    VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile);
}
```

---

### `BitwardenDecrypt\Core\VaultParsing\KdfParameters.cs`

```csharp
namespace BitwardenDecryptor.Core.VaultParsing;

internal record KdfParameters(
    string EmailOrSalt,
    int KdfIterations,
    int? KdfMemory,
    int? KdfParallelism,
    int KdfType,
    string ProtectedSymmetricKey,
    string? ProtectedRsaPrivateKey);
```

---

### `BitwardenDecrypt\Core\VaultParsing\VaultParser.cs`

```csharp
using BitwardenDecryptor.Exceptions;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing;

public class VaultParser
{
    private readonly IEnumerable<IVaultFormatParser> _parsers;

    public VaultParser(IEnumerable<IVaultFormatParser> parsers)
    {
        _parsers = parsers;
    }

    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        foreach (IVaultFormatParser parser in _parsers)
        {
            VaultMetadata? result = parser.Parse(rootNode, accountSelector, inputFile);
            if (result is not null)
            {
                return result;
            }
        }

        throw new VaultFormatException(
            "Could not determine the format of the provided JSON file or find any account data within it.\n" +
            "Please ensure this is a valid Bitwarden `data.json` export file.\n" +
            "The file may be in an unsupported format, corrupted, or not a Bitwarden export at all."
        );
    }
}
```

---

### `BitwardenDecrypt\Decryptors\VaultStrategies\EncryptedJsonDecryptorStrategy.cs`

```csharp
using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultStrategies;

public class EncryptedJsonDecryptorStrategy : IVaultDecryptorStrategy
{
    private readonly JsonNode rootNode;
    private readonly BitwardenSecrets secrets;
    private readonly VaultItemDecryptor vaultItemDecryptor;

    public EncryptedJsonDecryptorStrategy(JsonNode rootNode, BitwardenSecrets secrets, VaultItemDecryptor vaultItemDecryptor)
    {
        this.rootNode = rootNode;
        this.secrets = secrets;
        this.vaultItemDecryptor = vaultItemDecryptor;
    }

    public JsonObject Decrypt()
    {
        string? encryptedVaultData = rootNode["data"]?.GetValue<string>();

        if (string.IsNullOrEmpty(encryptedVaultData))
        {
            throw new VaultFormatException("No vault data found in EncryptedJSON export.");
        }

        string decryptedJsonPayload = vaultItemDecryptor.DecryptCipherString(encryptedVaultData, secrets.StretchedEncryptionKey, secrets.StretchedMacKey);

        if (decryptedJsonPayload.StartsWith("ERROR"))
        {
            throw new DecryptionException($"Failed to decrypt EncryptedJSON payload. {decryptedJsonPayload}");
        }

        JsonObject payloadNode = JsonNode.Parse(decryptedJsonPayload)!.AsObject();
        JsonObject decryptedEntries = [];

        foreach (KeyValuePair<string, JsonNode?> prop in payloadNode)
        {
            decryptedEntries[prop.Key] = prop.Value?.DeepClone();
        }

        return decryptedEntries;
    }
}
```

---

### `BitwardenDecrypt\Decryptors\VaultStrategies\Format2024DecryptorStrategy.cs`

```csharp
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultStrategies;

public class Format2024DecryptorStrategy(
    JsonNode rootNode,
    BitwardenSecrets secrets,
    DecryptionContext context,
    VaultItemDecryptor vaultItemDecryptor) : IVaultDecryptorStrategy
{
    public JsonObject Decrypt()
    {
        JsonObject decryptedEntries = [];

        var orgKeysNode = rootNode[$"user_{context.AccountUuid}_crypto_organizationKeys"]?.AsObject();
        vaultItemDecryptor.DecryptAndStoreOrganizationKeys(orgKeysNode);

        string[] groupsToProcess = ["folder_folders", "ciphers_ciphers", "collection_collections", "organizations_organizations"];

        foreach (string groupKey in groupsToProcess)
        {
            JsonObject? groupDataNode = rootNode[$"user_{context.AccountUuid}_{groupKey}"]?.AsObject();
            if (groupDataNode is null)
            {
                continue;
            }

            JsonArray itemsArray = [];
            foreach (KeyValuePair<string, JsonNode?> itemKvp in groupDataNode)
            {
                if (itemKvp.Value is JsonObject itemObj)
                {
                    itemsArray.Add(vaultItemDecryptor.ProcessGroupItem(itemObj.DeepClone()));
                }
                else if (itemKvp.Value is JsonArray itemArr)
                {
                    foreach (JsonNode? node in itemArr)
                    {
                        if (node is JsonObject obj)
                        {
                            itemsArray.Add(vaultItemDecryptor.ProcessGroupItem(obj.DeepClone()));
                        }
                    }
                }
            }
            string outputKey = groupKey.Replace("_folders", "s").Replace("ciphers_ciphers", "items").Replace("_collections", "s").Replace("_organizations", "s");
            decryptedEntries[outputKey] = itemsArray;
        }

        if (context.IncludeSends)
        {
            ProcessSends(decryptedEntries);
        }

        return decryptedEntries;
    }

    private void ProcessSends(JsonObject decryptedEntries)
    {
        if (rootNode[$"user_{context.AccountUuid}_encryptedSend_sendUserEncrypted"] is not JsonObject sendsDataNode)
        {
            return;
        }

        JsonArray sendsArray = [];
        foreach (KeyValuePair<string, JsonNode?> itemKvp in sendsDataNode)
        {
            if (itemKvp.Value is JsonObject itemObj)
            {
                sendsArray.Add(vaultItemDecryptor.DecryptSend(itemObj.DeepClone()));
            }
        }
        decryptedEntries["sends"] = sendsArray;
    }
}
```

---

### `BitwardenDecrypt\Decryptors\VaultStrategies\IVaultDecryptorStrategy.cs`

```csharp
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultStrategies;

public interface IVaultDecryptorStrategy
{
    JsonObject Decrypt();
}
```

---

### `BitwardenDecrypt\Decryptors\VaultStrategies\LegacyJsonDecryptorStrategy.cs`

```csharp
using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultStrategies;

public class LegacyJsonDecryptorStrategy : IVaultDecryptorStrategy
{
    private readonly JsonNode rootNode;
    private readonly DecryptionContext context;
    private readonly VaultItemDecryptor vaultItemDecryptor;

    public LegacyJsonDecryptorStrategy(
        JsonNode rootNode,
        BitwardenSecrets secrets,
        DecryptionContext context,
        VaultItemDecryptor vaultItemDecryptor)
    {
        this.rootNode = rootNode;
        this.context = context;
        this.vaultItemDecryptor = vaultItemDecryptor;
    }

    public JsonObject Decrypt()
    {
        JsonNode accountNode;
        if (context.FileFormat == "NEW")
        {
            accountNode = rootNode[context.AccountUuid!]!;
            vaultItemDecryptor.DecryptAndStoreOrganizationKeys(accountNode["keys"]?["organizationKeys"]?["encrypted"]?.AsObject());
        }
        else // OLD format
        {
            accountNode = rootNode;
            vaultItemDecryptor.DecryptAndStoreOrganizationKeys(accountNode["encOrgKeys"]?.AsObject());
        }

        if ((context.FileFormat == "NEW" ? accountNode["data"] : accountNode) is not JsonObject dataContainerNode)
        {
            throw new VaultFormatException("Data container not found in the vault JSON.");
        }

        JsonObject decryptedEntries = [];
        foreach (KeyValuePair<string, JsonNode?> groupKvp in dataContainerNode)
        {
            string groupKeyOriginal = groupKvp.Key;
            string outputKey = groupKeyOriginal.Contains('_') ? groupKeyOriginal[..groupKeyOriginal.IndexOf('_')] : groupKeyOriginal;
            outputKey = outputKey.Replace("ciphers", "items");

            if ((groupKeyOriginal == "sends" || (outputKey == "sends" && groupKeyOriginal.StartsWith("sends_"))) && !context.IncludeSends)
            {
                continue;
            }

            string[] supportedOutputKeys = ["folders", "items", "collections", "organizations", "sends"];
            if (!supportedOutputKeys.Contains(outputKey))
            {
                continue;
            }

            JsonNode? actualDataNode = groupKvp.Value;
            if (context.FileFormat == "NEW" && outputKey != "organizations" && outputKey != "sends" && groupKvp.Value?["encrypted"] is not null)
            {
                actualDataNode = groupKvp.Value["encrypted"];
            }

            if (actualDataNode is not JsonObject groupDataObj)
            {
                continue;
            }

            JsonArray itemsArray = [];
            foreach (KeyValuePair<string, JsonNode?> itemKvp in groupDataObj)
            {
                if (itemKvp.Value is JsonObject itemObj)
                {
                    itemsArray.Add(outputKey == "sends"
                        ? vaultItemDecryptor.DecryptSend(itemObj.DeepClone())
                        : vaultItemDecryptor.ProcessGroupItem(itemObj.DeepClone()));
                }
            }
            decryptedEntries[outputKey] = itemsArray;
        }

        return decryptedEntries;
    }
}
```

---

### `BitwardenDecrypt\Core\VaultParsing\FormatParsers\EncryptedJsonParser.cs`

```csharp
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class EncryptedJsonParser : IVaultFormatParser
{
    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        if (rootNode["encrypted"]?.GetValue<bool>() != true || rootNode["passwordProtected"]?.GetValue<bool>() != true)
        {
            return null;
        }

        string fileFormat = "EncryptedJSON";
        string emailOrSalt = rootNode["salt"]!.GetValue<string>();
        int kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
        int kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
        string protectedSymmKeyOrValidation = rootNode["encKeyValidation_DO_NOT_EDIT"]!.GetValue<string>();

        return new(
            fileFormat,
            emailOrSalt,
            kdfIterations,
            null,
            null,
            kdfType,
            protectedSymmKeyOrValidation,
            null);
    }
}
```

---

### `BitwardenDecrypt\Core\VaultParsing\FormatParsers\Format2024Parser.cs`

```csharp
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class Format2024Parser : IVaultFormatParser
{
    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        if (rootNode["global_account_accounts"] is not JsonObject accountsNode)
        {
            return null;
        }

        string fileFormat = "2024";
        List<AccountInfo> validAccounts = ExtractAccounts(accountsNode);

        AccountInfo? selectedAccount = accountSelector.SelectAccount(validAccounts, inputFile);

        if (selectedAccount is null)
        {
            return null;
        }

        string selectedAccountUuid = selectedAccount.Uuid;
        string selectedAccountEmail = selectedAccount.Email;

        KdfParameters kdfParams = GetKdfParameters(rootNode, selectedAccountUuid, selectedAccountEmail);

        return new(
            fileFormat,
            kdfParams.EmailOrSalt,
            kdfParams.KdfIterations,
            kdfParams.KdfMemory,
            kdfParams.KdfParallelism,
            kdfParams.KdfType,
            kdfParams.ProtectedSymmetricKey,
            kdfParams.ProtectedRsaPrivateKey,
            selectedAccountEmail,
            selectedAccountUuid);
    }

    private static List<AccountInfo> ExtractAccounts(JsonObject accountsNode)
    {
        return [.. accountsNode
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value is not null && kvp.Value.AsObject().Count != 0)
            .Select(kvp => new AccountInfo(kvp.Key, kvp.Value!["email"]!.GetValue<string>()))];
    }

    private static KdfParameters GetKdfParameters(JsonNode rootNode, string accountUuid, string accountEmail)
    {
        string emailOrSalt = accountEmail;
        JsonNode kdfConfigNode = rootNode[$"user_{accountUuid}_kdfConfig_kdfConfig"]!;
        int kdfIterations = kdfConfigNode["iterations"]!.GetValue<int>();
        int? kdfMemory = kdfConfigNode["memory"]?.GetValue<int>();
        int? kdfParallelism = kdfConfigNode["parallelism"]?.GetValue<int>();
        int kdfType = kdfConfigNode["kdfType"]!.GetValue<int>();
        string protectedSymmKey = rootNode[$"user_{accountUuid}_masterPassword_masterKeyEncryptedUserKey"]!.GetValue<string>();
        string? encPrivateKey = rootNode[$"user_{accountUuid}_crypto_privateKey"]?.GetValue<string>();

        return new(
            emailOrSalt,
            kdfIterations,
            kdfMemory,
            kdfParallelism,
            kdfType,
            protectedSymmKey,
            encPrivateKey);
    }
}
```

---

### `BitwardenDecrypt\Core\VaultParsing\FormatParsers\NewFormatParser.cs`

```csharp
using BitwardenDecryptor.Models;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class NewFormatParser : IVaultFormatParser
{
    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        List<AccountInfo> potentialNewFormatAccounts = ExtractAccounts(rootNode);

        if (potentialNewFormatAccounts.Count == 0)
        {
            return null;
        }

        string fileFormat = "NEW";

        AccountInfo? selectedAccount = accountSelector.SelectAccount(potentialNewFormatAccounts, inputFile);
        if (selectedAccount is null)
        {
            return null;
        }
        string selectedAccountUuid = selectedAccount.Uuid;
        string selectedAccountEmail = selectedAccount.Email;

        KdfParameters kdfParams = GetKdfParameters(rootNode, selectedAccountUuid, selectedAccountEmail);

        return new(
            fileFormat,
            kdfParams.EmailOrSalt,
            kdfParams.KdfIterations,
            kdfParams.KdfMemory,
            kdfParams.KdfParallelism,
            kdfParams.KdfType,
            kdfParams.ProtectedSymmetricKey,
            kdfParams.ProtectedRsaPrivateKey,
            selectedAccountEmail,
            selectedAccountUuid);
    }

    private static List<AccountInfo> ExtractAccounts(JsonNode rootNode)
    {
        return rootNode.AsObject()
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value?["profile"]?["email"] is not null)
            .Select(kvp => new AccountInfo(kvp.Key, kvp.Value!["profile"]!["email"]!.GetValue<string>()))
            .ToList();
    }

    private static KdfParameters GetKdfParameters(JsonNode rootNode, string accountUuid, string accountEmail)
    {
        JsonNode accountNode = rootNode[accountUuid]!;
        string emailOrSalt = accountEmail;
        JsonNode profileNode = accountNode["profile"]!;
        int kdfIterations = profileNode["kdfIterations"]!.GetValue<int>();
        int? kdfMemory = profileNode["kdfMemory"]?.GetValue<int>();
        int? kdfParallelism = profileNode["kdfParallelism"]?.GetValue<int>();
        int kdfType = profileNode["kdfType"]!.GetValue<int>();
        JsonNode keysNode = accountNode["keys"]!;
        string protectedSymmKey = keysNode["masterKeyEncryptedUserKey"]?.GetValue<string>() ?? keysNode["cryptoSymmetricKey"]!["encrypted"]!.GetValue<string>();
        string? encPrivateKey = keysNode["privateKey"]!["encrypted"]!.GetValue<string>();

        return new(
            emailOrSalt,
            kdfIterations,
            kdfMemory,
            kdfParallelism,
            kdfType,
            protectedSymmKey,
            encPrivateKey);
    }
}
```

---

### `BitwardenDecrypt\Core\VaultParsing\FormatParsers\OldFormatParser.cs`

```csharp
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core.VaultParsing.FormatParsers;

public class OldFormatParser : IVaultFormatParser
{
    public VaultMetadata? Parse(JsonNode rootNode, IAccountSelector accountSelector, string inputFile)
    {
        if (rootNode["userEmail"] is null)
        {
            return null;
        }

        string fileFormat = "OLD";
        string accountUuid = rootNode["userId"]?.GetValue<string>() ?? string.Empty;
        string accountEmail = rootNode["userEmail"]!.GetValue<string>();

        KdfParameters kdfParams = GetKdfParameters(rootNode, accountEmail);

        return new(
            fileFormat,
            kdfParams.EmailOrSalt,
            kdfParams.KdfIterations,
            kdfParams.KdfMemory,
            kdfParams.KdfParallelism,
            kdfParams.KdfType,
            kdfParams.ProtectedSymmetricKey,
            kdfParams.ProtectedRsaPrivateKey,
            accountEmail,
            accountUuid);
    }

    private static KdfParameters GetKdfParameters(JsonNode rootNode, string accountEmail)
    {
        string emailOrSalt = accountEmail;
        int kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
        int kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
        string protectedSymmKey = rootNode["encKey"]!.GetValue<string>();
        string? encPrivateKey = rootNode["encPrivateKey"]?.GetValue<string>();
        return new KdfParameters(emailOrSalt, kdfIterations, null, null, kdfType, protectedSymmKey, encPrivateKey);
    }
}
```

---

