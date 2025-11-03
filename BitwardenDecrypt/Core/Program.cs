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