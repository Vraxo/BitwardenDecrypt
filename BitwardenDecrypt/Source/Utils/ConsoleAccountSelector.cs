using System;
using System.Collections.Generic;
using BitwardenDecryptor.Core.VaultParsing;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Utils;

public class ConsoleAccountSelector : IAccountSelector
{
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
