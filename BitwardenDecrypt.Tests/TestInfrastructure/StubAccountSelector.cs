using BitwardenDecryptor.Core.VaultParsing;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Tests;

internal sealed class StubAccountSelector(int selectedIndex = 0) : IAccountSelector
{
    public IReadOnlyList<AccountInfo>? Accounts { get; private set; }

    public string? Context { get; private set; }

    public int CallCount { get; private set; }

    public AccountInfo? SelectAccount(IReadOnlyList<AccountInfo> accounts, string context)
    {
        Accounts = accounts;
        Context = context;
        CallCount++;
        return accounts.Count == 0 ? null : accounts[selectedIndex];
    }
}
