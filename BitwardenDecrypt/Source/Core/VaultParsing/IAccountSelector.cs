using System.Collections.Generic;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core.VaultParsing;

public interface IAccountSelector
{
    AccountInfo? SelectAccount(IReadOnlyList<AccountInfo> accounts, string context);
}
