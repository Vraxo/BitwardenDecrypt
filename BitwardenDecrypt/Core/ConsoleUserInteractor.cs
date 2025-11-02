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