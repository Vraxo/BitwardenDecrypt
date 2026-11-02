# 🔐 BitwardenDecrypt

A .NET 8 command-line tool for decrypting Bitwarden `data.json` files and password-protected encrypted JSON exports. Decryption runs locally, and the result can be printed as JSON or saved to a file.

## 📄 Supported input

- Bitwarden desktop `data.json` files using the 2024 or older supported layouts.
- Password-protected encrypted JSON exports.
- Accounts using PBKDF2-SHA256 or Argon2id key derivation.
- Folders, items, collections, organizations, and optional Sends.

If a local file contains multiple accounts, the tool prompts you to select one. Plaintext JSON exports are not supported.

## 🛠️ Build

Install the [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0), then run from the repository root:

```bash
dotnet build BitwardenDecrypt.sln
```

## 🚀 Usage

Run from the repository root:

```bash
dotnet run --project BitwardenDecrypt/BitwardenDecrypt.csproj -- [inputfile] [options]
```

`inputfile` defaults to `data.json`. Unless `--save` or `--output` is used, decrypted JSON is written to the terminal.

```bash
# Decrypt data.json and print the result
dotnet run --project BitwardenDecrypt/BitwardenDecrypt.csproj

# Save vault.json as vault.decrypted.json in the same directory
dotnet run --project BitwardenDecrypt/BitwardenDecrypt.csproj -- path/to/vault.json --save

# Choose an output file and include Sends
dotnet run --project BitwardenDecrypt/BitwardenDecrypt.csproj -- path/to/data.json --includesends --output decrypted.json
```

| Argument or option | Description |
| --- | --- |
| `inputfile` | Path to the encrypted JSON file. Defaults to `data.json`. |
| `--output <path>` | Write to the specified file, overwriting it if it exists. Takes precedence over `--save`. |
| `-s`, `--save` | Save next to the input file with a `.decrypted.json` suffix. |
| `--includesends` | Include Sends in the output. |
| `-p`, `--password <password>` | Supply the master password or export password. If omitted, a hidden prompt is shown. |

On Windows, the built executable also provides `install-path` and `uninstall-path` subcommands to add or remove its directory from the current user's `PATH`. Run them from the directory containing the executable:

```powershell
.\BitwardenDecrypt.exe install-path
.\BitwardenDecrypt.exe uninstall-path
```

Restart the terminal after changing `PATH`.

## ⚠️ Security

Decrypted output contains plaintext secrets. Protect output files and delete them when they are no longer needed.

Prefer the interactive password prompt. Passing `--password` on the command line can expose the password through shell history or process listings.
