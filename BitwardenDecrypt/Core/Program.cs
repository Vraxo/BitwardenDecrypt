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

        rootCommand.AddArgument(inputFileArgument);
        rootCommand.AddOption(includeSendsOption);
        rootCommand.AddOption(outputFileOption);
        rootCommand.AddOption(saveOption);

        rootCommand.SetHandler((inputFile, includeSends, outputFile, save) =>
        {
            try
            {
                string? finalOutputFile = DetermineOutputFile(inputFile, outputFile, save);
                RunDecryption(inputFile, includeSends, finalOutputFile);
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine($"\nERROR: The input file '{inputFile}' was not found.");
                Console.Error.WriteLine("\nPlease check the following:");
                Console.Error.WriteLine($"  1. The file '{inputFile}' actually exists in the current directory.");
                Console.Error.WriteLine("  2. You have spelled the filename correctly.");
                Console.Error.WriteLine("  3. If the file is in a different directory, provide the full path to it.");
                Console.Error.WriteLine("     Example: bitwardendecrypt \"C:\\Users\\YourUser\\Downloads\\data.json\"");
                Environment.ExitCode = 1;
            }
            catch (JsonException ex)
            {
                Console.Error.WriteLine($"\nERROR: The file '{inputFile}' could not be read because it is not valid JSON.");
                Console.Error.WriteLine("Please ensure it is a proper, unmodified export from Bitwarden.");
                Console.Error.WriteLine($"Details: {ex.Message}");
                Environment.ExitCode = 1;
            }
            catch (VaultFormatException ex)
            {
                Console.Error.WriteLine($"\nERROR: {ex.Message}");
                Environment.ExitCode = 1;
            }
            catch (KeyDerivationException ex)
            {
                Console.Error.WriteLine($"\nERROR: {ex.Message}");
                Environment.ExitCode = 1;
            }
            catch (DecryptionException ex)
            {
                Console.Error.WriteLine($"\nERROR: {ex.Message}");
                Environment.ExitCode = 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("\nAn unexpected error occurred:");
                Console.Error.WriteLine($"ERROR: {ex.Message}");
                Console.Error.WriteLine("\nPlease report this issue if you believe it's a bug.");
                Environment.ExitCode = 1;
            }
        },
        inputFileArgument,
        includeSendsOption,
        outputFileOption,
        saveOption);

        Command installPathCommand = new("install-path", "Adds the application's directory to the PATH environment variable for the current user.");
        installPathCommand.SetHandler(InstallPath);
        rootCommand.AddCommand(installPathCommand);

        Command uninstallPathCommand = new("uninstall-path", "Removes the application's directory from the PATH environment variable for the current user.");
        uninstallPathCommand.SetHandler(UninstallPath);
        rootCommand.AddCommand(uninstallPathCommand);

        return rootCommand.Invoke(args);
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
        Console.WriteLine();

        if (!string.IsNullOrEmpty(outputFile))
        {
            Console.WriteLine(File.Exists(outputFile)
                ? $"Saving Output To: {outputFile} (File Exists, Will Be Overwritten)\n"
                : $"Saving Output To: {outputFile}\n");
        }

        string jsonData = File.ReadAllText(inputFile);
        JsonNode rootNode = JsonNode.Parse(jsonData)!;

        VaultMetadata metadata = ParseVaultFile(rootNode, inputFile);

        string passwordPromptDetail = metadata.FileFormat == "EncryptedJSON"
            ? $"Export Password (for salt: {metadata.KdfSalt})"
            : $"Master Password (for account: {metadata.AccountEmail})";
        string password = ConsolePasswordReader.ReadPassword($"Enter {passwordPromptDetail}: ");

        BitwardenSecrets secrets = KeyDerivationService.DeriveKeys(metadata, password);

        DecryptionContext decryptionContext = new(
            FileFormat: metadata.FileFormat,
            AccountUuid: metadata.AccountUuid ?? string.Empty,
            AccountEmail: metadata.AccountEmail ?? string.Empty,
            IncludeSends: includeSends
        );

        VaultDataDecryptor vaultDataDecryptor = new(secrets, decryptionContext);
        JsonObject decryptedData = vaultDataDecryptor.DecryptVault(rootNode);

        JsonObject finalOutputObject = StructureOutputJson(decryptedData);

        JsonSerializerOptions jsonSerializerOptions = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        string decryptedJson = finalOutputObject.ToJsonString(jsonSerializerOptions);

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

    private static VaultMetadata ParseVaultFile(JsonNode rootNode, string inputFile)
    {
        ConsoleAccountSelector accountSelector = new();
        List<IVaultFormatParser> formatParsers =
        [
            new EncryptedJsonParser(),
            new Format2024Parser(),
            new NewFormatParser(),
            new OldFormatParser(),
        ];
        VaultParser vaultParser = new(formatParsers);
        return vaultParser.Parse(rootNode, accountSelector, inputFile)
            ?? throw new VaultFormatException("Could not determine the format of the provided JSON file or find any account data within it.");
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

    private static void InstallPath()
    {
        try
        {
            string? exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath))
            {
                Console.Error.WriteLine("ERROR: Could not determine the application's path.");
                Environment.ExitCode = 1;
                return;
            }

            string? exeDir = Path.GetDirectoryName(exePath);
            if (string.IsNullOrEmpty(exeDir))
            {
                Console.Error.WriteLine("ERROR: Could not determine the application's directory.");
                Environment.ExitCode = 1;
                return;
            }

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
            Console.Error.WriteLine("\nAn unexpected error occurred during installation:");
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            Environment.ExitCode = 1;
        }
    }

    private static void UninstallPath()
    {
        try
        {
            string? exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath))
            {
                Console.Error.WriteLine("ERROR: Could not determine the application's path.");
                Environment.ExitCode = 1;
                return;
            }

            string? exeDir = Path.GetDirectoryName(exePath);
            if (string.IsNullOrEmpty(exeDir))
            {
                Console.Error.WriteLine("ERROR: Could not determine the application's directory.");
                Environment.ExitCode = 1;
                return;
            }

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
            Console.Error.WriteLine("\nAn unexpected error occurred during uninstallation:");
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            Environment.ExitCode = 1;
        }
    }
}