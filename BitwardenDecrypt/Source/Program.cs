using System;
using System.CommandLine;
using System.IO;
using BitwardenDecryptor.Core;

namespace BitwardenDecryptor;

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
                string? finalOutputFile = outputFile;
                if (save && string.IsNullOrEmpty(finalOutputFile))
                {
                    string? directory = Path.GetDirectoryName(inputFile);
                    string filenameWithoutExt = Path.GetFileNameWithoutExtension(inputFile);
                    string newFilename = $"{filenameWithoutExt}.decrypted.json";
                    finalOutputFile = string.IsNullOrEmpty(directory)
                        ? newFilename
                        : Path.Combine(directory, newFilename);
                }

                CommandLineOptions options = new()
                {
                    InputFile = inputFile,
                    IncludeSends = includeSends,
                    OutputFile = finalOutputFile
                };

                RunDecryption(options);
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

        return rootCommand.Invoke(args);
    }

    private static void RunDecryption(CommandLineOptions options)
    {
        Console.WriteLine();

        if (!string.IsNullOrEmpty(options.OutputFile))
        {
            Console.WriteLine(File.Exists(options.OutputFile)
                ? $"Saving Output To: {options.OutputFile} (File Exists, Will Be Overwritten)\n"
                : $"Saving Output To: {options.OutputFile}\n");
        }

        Core.BitwardenDecryptor decryptor = new(options);
        string? decryptedJson = decryptor.DecryptBitwardenJson();

        if (decryptedJson == null)
        {
            Console.Error.WriteLine("Decryption failed. No output generated.");
            Environment.ExitCode = 1;
            return;
        }

        if (!string.IsNullOrEmpty(options.OutputFile))
        {
            try
            {
                File.WriteAllText(options.OutputFile, decryptedJson, System.Text.Encoding.UTF8);
                Console.WriteLine($"Successfully wrote decrypted data to {options.OutputFile}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR: Writing to {options.OutputFile} - {ex.Message}");
                Environment.ExitCode = 1;
            }
        }
        else
        {
            Console.WriteLine(decryptedJson);
        }
    }
}
