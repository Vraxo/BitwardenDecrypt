using System.CommandLine;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using BitwardenDecryptor.Core.VaultParsing;
using BitwardenDecryptor.Core.VaultParsing.FormatParsers;
using BitwardenDecryptor.Exceptions;
using BitwardenDecryptor.Models;
using BitwardenDecryptor.Utils;

namespace BitwardenDecryptor.Core;

public static class Program
{
    public static int Main(string[] args)
    {
        var rootCommand = BuildCommandLine();
        return rootCommand.Invoke(args);
    }

    private static RootCommand BuildCommandLine()
    {
        var rootCommand = new RootCommand("Decrypts an encrypted Bitwarden data.json file.");

        var inputFileArgument = new Argument<string>(
            name: "inputfile",
            description: "Path to the Bitwarden data.json file.",
            getDefaultValue: () => "data.json");

        var includeSendsOption = new Option<bool>(
            name: "--includesends",
            description: "Include Sends in the output.");

        var outputFileOption = new Option<string?>(
            name: "--output",
            description: "Write decrypted output to file. Will overwrite if file exists.");

        var saveOption = new Option<bool>(
            name: "--save",
            description: "Save the decrypted output to a file with a default name (e.g., 'data.json' becomes 'data.decrypted.json'). This is ignored if --output is used.");
        saveOption.AddAlias("-s");

        rootCommand.AddArgument(inputFileArgument);
        rootCommand.AddOption(includeSendsOption);
        rootCommand.AddOption(outputFileOption);
        rootCommand.AddOption(saveOption);

        rootCommand.SetHandler(HandleDecryption,
            inputFileArgument, includeSendsOption, outputFileOption, saveOption);

        var installPathCommand = new Command("install-path", "Adds the application's directory to the PATH environment variable for the current user.");
        installPathCommand.SetHandler(HandleInstallPath);
        rootCommand.AddCommand(installPathCommand);

        var uninstallPathCommand = new Command("uninstall-path", "Removes the application's directory from the PATH environment variable for the current user.");
        uninstallPathCommand.SetHandler(HandleUninstallPath);
        rootCommand.AddCommand(uninstallPathCommand);

        return rootCommand;
    }

    private static void HandleDecryption(string inputFile, bool includeSends, string? outputFile, bool save)
    {
        try
        {
            string? finalOutputFile = DetermineOutputFile(inputFile, outputFile, save);
            RunDecryption(inputFile, includeSends, finalOutputFile);
        }
        catch (Exception ex)
        {
            HandleException(ex, inputFile);
            Environment.ExitCode = 1;
        }
    }

    private static void HandleException(Exception ex, string? inputFile = null)
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
            case VaultFormatException or KeyDerivationException or DecryptionException:
                Console.Error.WriteLine($"ERROR: {ex.Message}");
                break;
            default:
                Console.Error.WriteLine("An unexpected error occurred:");
                Console.Error.WriteLine($"ERROR: {ex.Message}");
                Console.Error.WriteLine("\nPlease report this issue if you believe it's a bug.");
                break;
        }
    }

    private static string? DetermineOutputFile(string inputFile, string? outputFile, bool save)
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

    private static void RunDecryption(string inputFile, bool includeSends, string? outputFile)
    {
        PrintOutputHeader(outputFile);

        JsonNode rootNode = ReadAndParseVaultFile(inputFile);
        VaultMetadata metadata = ParseVaultMetadata(rootNode, inputFile);
        string password = GetPasswordFromUser(metadata);

        var keyDerivationService = new KeyDerivationService(metadata);
        BitwardenSecrets secrets = keyDerivationService.DeriveKeys(password);

        JsonObject decryptedData = DecryptVaultData(rootNode, secrets, metadata, includeSends);
        string decryptedJson = SerializeDecryptedData(decryptedData);

        WriteOutput(decryptedJson, outputFile);
    }

    private static void PrintOutputHeader(string? outputFile)
    {
        Console.WriteLine();
        if (!string.IsNullOrEmpty(outputFile))
        {
            Console.WriteLine(File.Exists(outputFile)
                ? $"Saving Output To: {outputFile} (File Exists, Will Be Overwritten)\n"
                : $"Saving Output To: {outputFile}\n");
        }
    }

    private static JsonNode ReadAndParseVaultFile(string inputFile)
    {
        string jsonData = File.ReadAllText(inputFile);
        return JsonNode.Parse(jsonData)!;
    }

    private static VaultMetadata ParseVaultMetadata(JsonNode rootNode, string inputFile)
    {
        var accountSelector = new ConsoleAccountSelector();
        List<IVaultFormatParser> formatParsers =
        [
            new EncryptedJsonParser(),
            new Format2024Parser(),
            new NewFormatParser(),
            new OldFormatParser(),
        ];
        var vaultParser = new VaultParser(formatParsers);
        return vaultParser.Parse(rootNode, accountSelector, inputFile)
            ?? throw new VaultFormatException("Could not determine the format of the provided JSON file or find any account data within it.");
    }

    private static string GetPasswordFromUser(VaultMetadata metadata)
    {
        string passwordPromptDetail = metadata.FileFormat == "EncryptedJSON"
            ? $"Export Password (for salt: {metadata.KdfSalt})"
            : $"Master Password (for account: {metadata.AccountEmail})";
        return ConsolePasswordReader.ReadPassword($"Enter {passwordPromptDetail}: ");
    }

    private static JsonObject DecryptVaultData(JsonNode rootNode, BitwardenSecrets secrets, VaultMetadata metadata, bool includeSends)
    {
        var decryptionContext = new DecryptionContext(
            FileFormat: metadata.FileFormat,
            AccountUuid: metadata.AccountUuid ?? string.Empty,
            AccountEmail: metadata.AccountEmail ?? string.Empty,
            IncludeSends: includeSends
        );

        var vaultDataDecryptor = new VaultDataDecryptor(secrets, decryptionContext);
        return vaultDataDecryptor.DecryptVault(rootNode);
    }

    private static string SerializeDecryptedData(JsonObject decryptedData)
    {
        JsonObject finalOutputObject = StructureOutputJson(decryptedData);
        var jsonSerializerOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        return finalOutputObject.ToJsonString(jsonSerializerOptions);
    }

    private static void WriteOutput(string decryptedJson, string? outputFile)
    {
        if (!string.IsNullOrEmpty(outputFile))
        {
            File.WriteAllText(outputFile, decryptedJson, System.Text.Encoding.UTF8);
            Console.WriteLine($"Successfully wrote decrypted data to {outputFile}");
        }
        else
        {
            Console.WriteLine(decryptedJson);
        }
    }

    private static JsonObject StructureOutputJson(JsonObject decryptedData)
    {
        var finalOutputObject = new JsonObject();

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

    private static void HandleInstallPath()
    {
        try
        {
            string? exeDir = GetExecutableDirectory();
            if (exeDir is null) return;

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
            HandleException(ex);
            Environment.ExitCode = 1;
        }
    }

    private static void HandleUninstallPath()
    {
        try
        {
            string? exeDir = GetExecutableDirectory();
            if (exeDir is null) return;

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
            HandleException(ex);
            Environment.ExitCode = 1;
        }
    }

    private static string? GetExecutableDirectory()
    {
        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            Console.Error.WriteLine("ERROR: Could not determine the application's path.");
            Environment.ExitCode = 1;
            return null;
        }

        string? exeDir = Path.GetDirectoryName(exePath);
        if (string.IsNullOrEmpty(exeDir))
        {
            Console.Error.WriteLine("ERROR: Could not determine the application's directory.");
            Environment.ExitCode = 1;
            return null;
        }

        return exeDir;
    }
}