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