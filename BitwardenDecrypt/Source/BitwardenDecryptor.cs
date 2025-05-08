using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using BitwardenDecryptor.Utils;
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class BitwardenDecryptor(CommandLineOptions options)
{
    private readonly CommandLineOptions _options = options;
    private readonly BitwardenSecrets _secrets = new();
    private static readonly Regex CipherStringRegex = new(@"\d\.[^,]+\|[^,]+=[^""]*", RegexOptions.Compiled);

    private void GetBitwardenSecrets(string emailOrSalt, string password, int kdfIterations, int? kdfMemory, int? kdfParallelism, int kdfType, string protectedSymmetricKeyOrValidationCipher, string? encPrivateKeyCipherString)
    {
        _secrets.Email = emailOrSalt;
        _secrets.MasterPasswordBytes = Encoding.UTF8.GetBytes(password);
        _secrets.KdfIterations = kdfIterations;
        _secrets.KdfMemory = kdfMemory;
        _secrets.KdfParallelism = kdfParallelism;
        _secrets.KdfType = kdfType;
        _secrets.ProtectedSymmetricKeyCipherString = protectedSymmetricKeyOrValidationCipher;
        _secrets.ProtectedRsaPrivateKeyCipherString = encPrivateKeyCipherString;

        byte[] kdfSaltInput;

        if (_options.FileFormat == "EncryptedJSON")
        {
            kdfSaltInput = Encoding.UTF8.GetBytes(emailOrSalt);
        }
        else
        {
            kdfSaltInput = Encoding.UTF8.GetBytes(_secrets.Email);
        }

        if (_secrets.KdfType == 1)
        {
            if (!_secrets.KdfMemory.HasValue || !_secrets.KdfParallelism.HasValue)
            {
                Console.Error.WriteLine("ERROR: KDF memory or parallelism not set for Argon2id.");
                Environment.Exit(1);
            }

            byte[] argonSalt = CryptoService.Sha256Hash(Encoding.UTF8.GetBytes(_secrets.Email));
            _secrets.MasterKey = CryptoService.DeriveArgon2id(
                _secrets.MasterPasswordBytes,
                argonSalt,
                _secrets.KdfIterations,
                _secrets.KdfMemory.Value * 1024,
                _secrets.KdfParallelism.Value,
                32);
        }
        else
        {
            _secrets.MasterKey = CryptoService.DerivePbkdf2Sha256(
               _secrets.MasterPasswordBytes,
               kdfSaltInput,
               _secrets.KdfIterations,
               32);
        }

        byte[] masterPasswordHashDerived = CryptoService.DerivePbkdf2Sha256(_secrets.MasterKey, _secrets.MasterPasswordBytes, 1, 32);
        _secrets.MasterPasswordHash = Convert.ToBase64String(masterPasswordHashDerived);

        _secrets.StretchedEncryptionKey = CryptoService.HkdfExpandSha256(_secrets.MasterKey, Encoding.UTF8.GetBytes("enc"), 32);
        _secrets.StretchedMacKey = CryptoService.HkdfExpandSha256(_secrets.MasterKey, Encoding.UTF8.GetBytes("mac"), 32);

        bool isForExportValidation = _options.FileFormat == "EncryptedJSON";
        (var symKey, var symEncKey, var symMacKey, var error) = DecryptProtectedSymmetricKey(
            _secrets.ProtectedSymmetricKeyCipherString,
            _secrets.StretchedEncryptionKey,
            _secrets.StretchedMacKey,
            isForExportValidation
            );

        if (error != null || symKey == null)
        {
            Console.Error.WriteLine($"ERROR: Failed to decrypt/validate Protected Symmetric Key or Export Validation Key. {error}");
            if (error != null && (error.Contains("MAC mismatch", StringComparison.OrdinalIgnoreCase) ||
                                  error.Contains("padding", StringComparison.OrdinalIgnoreCase) ||
                                  error.Contains("Likely wrong password", StringComparison.OrdinalIgnoreCase)))
            {
                Console.Error.WriteLine("This often indicates a wrong password (either Master Password for data.json or Export Password for encrypted exports).");
            }
            Environment.Exit(1);
        }

        _secrets.GeneratedSymmetricKey = symKey;
        _secrets.GeneratedEncryptionKey = symEncKey ?? [];
        _secrets.GeneratedMacKey = symMacKey ?? [];


        if (string.IsNullOrEmpty(_secrets.ProtectedRsaPrivateKeyCipherString))
        {
            return;
        }

        if (_secrets.GeneratedEncryptionKey.Length == 0 || _secrets.GeneratedMacKey.Length == 0)
        {
            Console.Error.WriteLine("ERROR: Cannot decrypt RSA private key because dependent symmetric keys were not properly derived.");
        }
        else
        {
            _secrets.RsaPrivateKeyDer = DecryptRSAPrivateKey(_secrets.ProtectedRsaPrivateKeyCipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);

            if (_secrets.RsaPrivateKeyDer != null)
            {
                return;
            }

            Console.Error.WriteLine("ERROR: Failed to decrypt RSA Private Key.");
        }
    }

    private static (byte[]? FullKey, byte[]? EncKey, byte[]? MacKey, string? Error) DecryptProtectedSymmetricKey(
        string cipherString, byte[] masterKey, byte[] masterMacKey, bool isExportValidationKey = false)
    {
        if (string.IsNullOrEmpty(cipherString))
        {
            return (null, null, null, "CipherString is empty.");
        }

        string[] parts = cipherString.Split('.');
        
        if (parts.Length < 2)
        {
            return (null, null, null, "Invalid CipherString format.");
        }

        if (!int.TryParse(parts[0], out int encType))
        {
            return (null, null, null, "Invalid encryption type in CipherString.");
        }

        (byte[]? cleartextBytes, string? error) = CryptoService.VerifyAndDecryptAesCbc(masterKey, masterMacKey, cipherString);

        if (error != null || cleartextBytes == null)
        {
            return (null, null, null, error);
        }

        if (!isExportValidationKey && encType == 2 && cleartextBytes.Length < 64)
        {
            return (null, null, null, "Decrypted key is too short. Likely wrong password (for data.json user key).");
        }

        if ((encType == 2 || encType == 0) && cleartextBytes.Length >= 64)
        {
            byte[] enc = cleartextBytes.Take(32).ToArray();
            byte[] mac = cleartextBytes.Skip(32).Take(32).ToArray();
            return (cleartextBytes, enc, mac, null);
        }

        return (cleartextBytes, null, null, null);
    }

    private static byte[]? DecryptRSAPrivateKey(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        (byte[]? cleartext, string? error) = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);
        
        if (error != null)
        {
            Console.Error.WriteLine($"ERROR decrypting RSA private key wrapper: {error}");
            return null;
        }

        return cleartext;
    }

    private string DecryptCipherString(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        if (string.IsNullOrEmpty(cipherString))
        {
            return string.Empty;
        }

        string[] parts = cipherString.Split('.');
        
        if (parts.Length < 2)
        {
            return $"ERROR Decrypting: Invalid CipherString format {cipherString}";
        }

        if (!int.TryParse(parts[0], out _))
        {
            return $"ERROR Decrypting: Invalid encType {cipherString}";
        }

        (byte[]? cleartextBytes, string? error) = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);

        if (error != null || cleartextBytes == null)
        {
            return $"ERROR: {error}. CipherString not decrypted: {cipherString}";
        }

        try
        {
            return Encoding.UTF8.GetString(cleartextBytes);
        }
        catch (DecoderFallbackException)
        {
            if (_secrets.GeneratedEncryptionKey.Length == 0 || _secrets.GeneratedMacKey.Length == 0)
            {
                return $"ERROR Decrypting (UTF-8 decode failed, fallback keys unavailable): {cipherString}";
            }

            (var fallbackKeyBytes, _, _, var fallbackError) = DecryptProtectedSymmetricKey(cipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);

            if (fallbackError == null && fallbackKeyBytes != null)
            {
                return BitConverter.ToString(fallbackKeyBytes).Replace("-", "").ToLowerInvariant();
            }

            return $"ERROR Decrypting (UTF-8 decode failed, fallback also failed): {cipherString}";
        }
    }

    private static byte[]? DecryptRSA(string cipherString, byte[] rsaPrivateKeyDer)
    {
        string[] parts = cipherString.Split('.');

        if (parts.Length < 2)
        {
            Console.Error.WriteLine($"Invalid RSA CipherString format: {cipherString}");
            return null;
        }

        string[] dataParts = parts[1].Split('|');

        if (dataParts.Length < 1)
        {
            Console.Error.WriteLine($"Invalid RSA CipherString data part: {cipherString}");
            return null;
        }

        byte[] ciphertext;

        try
        {
            ciphertext = Convert.FromBase64String(dataParts[0]);
        }
        catch (FormatException ex)
        {
            Console.Error.WriteLine($"Base64 decoding failed for RSA ciphertext: {ex.Message}");
            return null;
        }

        return CryptoService.DecryptRsaOaepSha1(rsaPrivateKeyDer, ciphertext);
    }

    private JsonNode? DecryptSend(JsonNode sendNode)
    {
        string? keyCipherString = sendNode["key"]?.GetValue<string>();
        
        if (keyCipherString == null)
        {
            return sendNode;
        }

        if (_secrets.GeneratedEncryptionKey.Length == 0 || _secrets.GeneratedMacKey.Length == 0)
        {
            Console.Error.WriteLine($"ERROR: Cannot decrypt Send key as user symmetric keys are not fully available.");
            sendNode["key"] = $"ERROR: Cannot decrypt Send key - user keys unavailable.";
            return sendNode;
        }

        (var sendKeyBytes, _, _, var error) = DecryptProtectedSymmetricKey(keyCipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);
        
        if (error != null || sendKeyBytes == null)
        {
            Console.Error.WriteLine($"Failed to decrypt Send key: {error}");
            sendNode["key"] = $"ERROR: Failed to decrypt Send key - {error}";
            return sendNode;
        }

        byte[] salt = Encoding.UTF8.GetBytes("bitwarden-send");
        byte[] info = Encoding.UTF8.GetBytes("send");
        byte[] derivedSendKeyMaterial = HKDF.DeriveKey(HashAlgorithmName.SHA256, sendKeyBytes, 64, salt, info);

        byte[] sendEncKey = derivedSendKeyMaterial.Take(32).ToArray();
        byte[] sendMacKey = derivedSendKeyMaterial.Skip(32).Take(32).ToArray();

        sendNode["key"] = BitConverter.ToString(derivedSendKeyMaterial).Replace("-", "").ToLowerInvariant();

        string sendJsonString = sendNode.ToJsonString();

        MatchCollection matches = CipherStringRegex.Matches(sendJsonString);
        
        foreach (Match match in matches.Reverse())
        {
            string decryptedValue = DecryptCipherString(match.Value, sendEncKey, sendMacKey);
            string jsonEscapedValue = JsonSerializer.Serialize(decryptedValue);

            if (jsonEscapedValue.Length >= 2)
            {
                jsonEscapedValue = jsonEscapedValue[1..^1];
            }

            sendJsonString = sendJsonString.Remove(match.Index, match.Length).Insert(match.Index, jsonEscapedValue);
        }

        return JsonNode.Parse(sendJsonString);
    }

    private bool CheckFileFormatVersionAndExtractParams(JsonNode rootNode, out string emailOrSalt, out int kdfIterations, out int? kdfMemory, out int? kdfParallelism, out int kdfType, out string protectedSymmKeyOrValidation, out string? encPrivateKey)
    {
        emailOrSalt = string.Empty;
        kdfIterations = 0;
        kdfMemory = null;
        kdfParallelism = null;
        kdfType = 0;
        protectedSymmKeyOrValidation = string.Empty;
        encPrivateKey = null;

        if (rootNode["encrypted"]?.GetValue<bool>() == true && rootNode["passwordProtected"]?.GetValue<bool>() == true)
        {
            _options.FileFormat = "EncryptedJSON";
            emailOrSalt = rootNode["salt"]!.GetValue<string>();
            kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
            kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
            protectedSymmKeyOrValidation = rootNode["encKeyValidation_DO_NOT_EDIT"]!.GetValue<string>();
            return true;
        }

        if (rootNode["global_account_accounts"] != null)
        {
            _options.FileFormat = "2024";
            JsonObject accountsNode = rootNode["global_account_accounts"]!.AsObject();
            List<(string uuid, string email)> validAccounts = accountsNode
                .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value != null && kvp.Value.AsObject().Count != 0)
                .Select(kvp => (uuid: kvp.Key, email: kvp.Value!["email"]!.GetValue<string>()))
                .ToList();

            if (!SelectAccount(validAccounts, out var selectedAccountUuid, out var selectedAccountEmail))
            {
                return false;
            }

            _options.AccountUuid = selectedAccountUuid;
            _options.AccountEmail = selectedAccountEmail;

            emailOrSalt = _options.AccountEmail;
            JsonNode kdfConfigNode = rootNode[$"user_{_options.AccountUuid}_kdfConfig_kdfConfig"]!;
            kdfIterations = kdfConfigNode["iterations"]!.GetValue<int>();
            kdfMemory = kdfConfigNode["memory"]?.GetValue<int>();
            kdfParallelism = kdfConfigNode["parallelism"]?.GetValue<int>();
            kdfType = kdfConfigNode["kdfType"]!.GetValue<int>();
            protectedSymmKeyOrValidation = rootNode[$"user_{_options.AccountUuid}_masterPassword_masterKeyEncryptedUserKey"]!.GetValue<string>();
            encPrivateKey = rootNode[$"user_{_options.AccountUuid}_crypto_privateKey"]?.GetValue<string>();
            return true;
        }

        List<(string uuid, string email)> potentialNewFormatAccounts = rootNode.AsObject()
            .Where(kvp => Guid.TryParse(kvp.Key, out _) && kvp.Value?["profile"]?["email"] != null)
            .Select(kvp => (uuid: kvp.Key, email: kvp.Value!["profile"]!["email"]!.GetValue<string>()))
            .ToList();

        if (potentialNewFormatAccounts.Count != 0)
        {
            _options.FileFormat = "NEW";

            if (!SelectAccount(potentialNewFormatAccounts, out var selectedAccountUuid, out var selectedAccountEmail))
            {
                return false;
            }

            _options.AccountUuid = selectedAccountUuid;
            _options.AccountEmail = selectedAccountEmail;

            JsonNode accountNode = rootNode[_options.AccountUuid]!;
            emailOrSalt = _options.AccountEmail;
            JsonNode profileNode = accountNode["profile"]!;
            kdfIterations = profileNode["kdfIterations"]!.GetValue<int>();
            kdfMemory = profileNode["kdfMemory"]?.GetValue<int>();
            kdfParallelism = profileNode["kdfParallelism"]?.GetValue<int>();
            kdfType = profileNode["kdfType"]!.GetValue<int>();

            var keysNode = accountNode["keys"]!;
            protectedSymmKeyOrValidation = keysNode["masterKeyEncryptedUserKey"]?.GetValue<string>() ?? keysNode["cryptoSymmetricKey"]!["encrypted"]!.GetValue<string>();
            encPrivateKey = keysNode["privateKey"]!["encrypted"]!.GetValue<string>();
            return true;
        }

        if (rootNode["userEmail"] != null)
        {
            _options.FileFormat = "OLD";
            _options.AccountUuid = rootNode["userId"]?.GetValue<string>() ?? string.Empty;
            _options.AccountEmail = rootNode["userEmail"]!.GetValue<string>();

            emailOrSalt = _options.AccountEmail;
            kdfIterations = rootNode["kdfIterations"]!.GetValue<int>();
            kdfType = rootNode["kdf"]?.GetValue<int>() ?? 0;
            protectedSymmKeyOrValidation = rootNode["encKey"]!.GetValue<string>();
            encPrivateKey = rootNode["encPrivateKey"]?.GetValue<string>();
            return true;
        }

        Console.Error.WriteLine("ERROR: Could not determine data file format or find account data.");
        return false;
    }

    private bool SelectAccount(List<(string uuid, string email)> accounts, out string selectedUuid, out string selectedEmail)
    {
        selectedUuid = string.Empty;
        selectedEmail = string.Empty;

        if (accounts.Count == 0)
        {
            Console.Error.WriteLine($"ERROR: No Accounts Found In {_options.InputFile}");
            return false;
        }

        if (accounts.Count == 1)
        {
            selectedUuid = accounts[0].uuid;
            selectedEmail = accounts[0].email;
            return true;
        }

        Console.WriteLine("Which Account Would You Like To Decrypt?");

        for (int i = 0; i < accounts.Count; i++)
        {
            Console.WriteLine($" {i + 1}:\t{accounts[i].email}");
        }

        int choice = 0;

        Console.WriteLine();

        while (choice < 1 || choice > accounts.Count)
        {
            Console.Write("Enter Number: ");

            if (int.TryParse(Console.ReadLine(), out choice))
            {
                continue;
            }

            choice = 0;
        }

        Console.WriteLine();

        selectedUuid = accounts[choice - 1].uuid;
        selectedEmail = accounts[choice - 1].email;

        return true;
    }

    private JsonObject ProcessGroupItem(JsonNode groupItemNode, string groupName, JsonNode? accountRootNodeForKeys = null)
    {
        string? orgId = groupItemNode["organizationId"]?.GetValue<string>();
        byte[] itemEncKey;
        byte[] itemMacKey;

        if (orgId != null && _secrets.OrganizationKeys.TryGetValue(orgId, out byte[]? orgFullKey) && orgFullKey != null && orgFullKey.Length >= 64)
        {
            itemEncKey = orgFullKey.Take(32).ToArray();
            itemMacKey = orgFullKey.Skip(32).Take(32).ToArray();
        }
        else
        {
            if (_secrets.GeneratedEncryptionKey.Length == 0 || _secrets.GeneratedMacKey.Length == 0)
            {
                Console.Error.WriteLine($"Warning: User symmetric keys not fully available for item {groupItemNode["id"]?.GetValue<string>()}. Defaulting to stretched keys; decryption may fail for some fields.");
                itemEncKey = _secrets.StretchedEncryptionKey;
                itemMacKey = _secrets.StretchedMacKey;
            }
            else
            {
                itemEncKey = _secrets.GeneratedEncryptionKey;
                itemMacKey = _secrets.GeneratedMacKey;
            }
        }

        string? individualItemKeyCipherString = groupItemNode["key"]?.GetValue<string>();
        
        if (!string.IsNullOrEmpty(individualItemKeyCipherString))
        {
            (_, var decryptedItemEncKey, var decryptedItemMacKey, var itemKeyError) = DecryptProtectedSymmetricKey(individualItemKeyCipherString, itemEncKey, itemMacKey);
            
            if (itemKeyError == null && decryptedItemEncKey != null && decryptedItemMacKey != null)
            {
                itemEncKey = decryptedItemEncKey;
                itemMacKey = decryptedItemMacKey;
                
                if (groupItemNode is JsonObject obj)
                {
                    obj["key"] = "";
                }
            }
            else if (itemKeyError != null && groupItemNode is JsonObject obj)
            {
                obj["key"] = $"ERROR: Could not decrypt item key. {itemKeyError}";
            }
        }

        string itemJsonString = groupItemNode.ToJsonString();
        MatchCollection matches = CipherStringRegex.Matches(itemJsonString);

        foreach (Match? match in matches.Reverse())
        {
            string decryptedValue = DecryptCipherString(match.Value, itemEncKey, itemMacKey);
            string jsonEscapedValue = JsonSerializer.Serialize(decryptedValue);

            if (jsonEscapedValue.Length >= 2)
            {
                jsonEscapedValue = jsonEscapedValue[1..^1];
            }

            itemJsonString = itemJsonString.Remove(match.Index, match.Length).Insert(match.Index, jsonEscapedValue);
        }

        JsonObject processedNode = JsonNode.Parse(itemJsonString)!.AsObject();

        string[] userIdKeys = ["userId", "organizationUserId"];
       
        foreach (string key in userIdKeys)
        {
            if (!processedNode.ContainsKey(key))
            {
                continue;
            }

            processedNode.Remove(key);
        }

        return processedNode;
    }

    public string? DecryptBitwardenJson()
    {
        string jsonData;

        try
        {
            jsonData = File.ReadAllText(_options.InputFile);
        }
        catch (FileNotFoundException)
        {
            Console.Error.WriteLine($"ERROR: {_options.InputFile} not found.");
            Environment.Exit(1);
            return null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ERROR: An error occurred reading: {_options.InputFile} - {ex.Message}");
            Environment.Exit(1);
            return null;
        }

        JsonNode rootNode = JsonNode.Parse(jsonData)!;

        if (!CheckFileFormatVersionAndExtractParams(rootNode,
                out string emailOrSaltParam, 
                out int kdfIterationsParam, 
                out int? kdfMemoryParam,
                out int? kdfParallelismParam, 
                out int kdfTypeParam,
                out string protectedKeyOrValidationParam, 
                out string? encPrivateKeyParam))
        {
            Environment.Exit(1);
            return null;
        }

        string passwordPromptDetail = _options.FileFormat == "EncryptedJSON"
            ? $"Export Password (for salt: {emailOrSaltParam})"
            : $"Master Password (for account: {_options.AccountEmail})"; // _options.AccountEmail set if not EncryptedJSON

        string password = ConsolePasswordReader.ReadPassword($"Enter {passwordPromptDetail}: ");

        GetBitwardenSecrets(emailOrSaltParam, password, kdfIterationsParam, kdfMemoryParam, kdfParallelismParam, kdfTypeParam, protectedKeyOrValidationParam, encPrivateKeyParam);

        JsonObject decryptedEntries = [];

        if (_options.FileFormat == "EncryptedJSON")
        {
            string? encryptedVaultData = rootNode["data"]?.GetValue<string>();
            
            if (string.IsNullOrEmpty(encryptedVaultData))
            {
                Console.Error.WriteLine("ERROR: No vault data found in EncryptedJSON export.");
                Environment.Exit(1);
            }
           
            string decryptedJsonPayload = DecryptCipherString(encryptedVaultData, _secrets.StretchedEncryptionKey, _secrets.StretchedMacKey);
            
            if (decryptedJsonPayload.StartsWith("ERROR"))
            {
                Console.Error.WriteLine($"ERROR: Failed to decrypt EncryptedJSON payload. {decryptedJsonPayload}");
                Environment.Exit(1);
            }

            JsonObject payloadNode = JsonNode.Parse(decryptedJsonPayload)!.AsObject();

            foreach (KeyValuePair<string, JsonNode?> prop in payloadNode)
            {
                decryptedEntries[prop.Key] = prop.Value?.DeepClone();
            }
        }
        else if (_options.FileFormat == "2024")
        {
            JsonObject? orgKeysNode = rootNode[$"user_{_options.AccountUuid}_crypto_organizationKeys"]?.AsObject();
            
            if (orgKeysNode != null && _secrets.RsaPrivateKeyDer != null)
            {
                foreach (KeyValuePair<string, JsonNode?> kvp in orgKeysNode)
                {
                    string? orgKeyCipher = kvp.Value?["key"]?.GetValue<string>() ?? kvp.Value?.GetValue<string>();

                    if (orgKeyCipher == null)
                    {
                        continue;
                    }

                    byte[]? decryptedOrgKey = DecryptRSA(orgKeyCipher, _secrets.RsaPrivateKeyDer);
                    if (decryptedOrgKey != null) _secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
                }
            }

            string[] groupsToProcess = 
            [
                "folder_folders",
                "ciphers_ciphers",
                "collection_collections",
                "organizations_organizations"
            ];
            
            foreach (string groupKey in groupsToProcess)
            {
                JsonObject? groupDataNode = rootNode[$"user_{_options.AccountUuid}_{groupKey}"]?.AsObject();
                
                if (groupDataNode == null)
                {
                    continue;
                }

                JsonArray itemsArray = [];

                foreach (var itemKvp in groupDataNode)
                {
                    if (itemKvp.Value is JsonObject itemObj)
                    {
                        itemsArray.Add(ProcessGroupItem(itemObj.DeepClone(), groupKey));
                    }
                    else if (itemKvp.Value is JsonArray itemArr)
                    {
                        foreach (JsonNode? node in itemArr)
                        {
                            if (node is not JsonObject obj)
                            {
                                continue;
                            }

                            itemsArray.Add(ProcessGroupItem(obj.DeepClone(), groupKey));
                        }
                    }
                }

                string outputKey = groupKey.Replace("_folders", "s").Replace("ciphers_ciphers", "items").Replace("_collections", "s").Replace("_organizations", "s");
                decryptedEntries[outputKey] = itemsArray;
            }

            if (_options.IncludeSends)
            {
                JsonObject? sendsDataNode = rootNode[$"user_{_options.AccountUuid}_encryptedSend_sendUserEncrypted"]?.AsObject();
                
                if (sendsDataNode != null)
                {
                    JsonArray sendsArray = [];

                    foreach (KeyValuePair<string, JsonNode?> itemKvp in sendsDataNode)
                    {
                        if (itemKvp.Value is not JsonObject itemObj)
                        {
                            continue;
                        }

                        sendsArray.Add(DecryptSend(itemObj.DeepClone()));
                    }

                    decryptedEntries["sends"] = sendsArray;
                }
            }
        }
        else
        {
            JsonNode accountNode;
            
            if (_options.FileFormat == "NEW")
            {
                accountNode = rootNode[_options.AccountUuid]!;
                JsonObject? orgKeysEncryptedNode = accountNode["keys"]?["organizationKeys"]?["encrypted"]?.AsObject();
                
                if (orgKeysEncryptedNode != null && _secrets.RsaPrivateKeyDer != null)
                {
                    foreach (KeyValuePair<string, JsonNode?> kvp in orgKeysEncryptedNode)
                    {
                        string? orgKeyCipher = kvp.Value?["key"]?.GetValue<string>() 
                            ?? kvp.Value?.GetValue<string>();
                        
                        if (orgKeyCipher != null)
                        {
                            byte[]? decryptedOrgKey = DecryptRSA(orgKeyCipher, _secrets.RsaPrivateKeyDer);
                            
                            if (decryptedOrgKey != null)
                            {
                                _secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
                            }
                        }
                    }
                }
            }
            else
            {
                accountNode = rootNode;
                JsonObject? encOrgKeysNode = accountNode["encOrgKeys"]?.AsObject();
                
                if (encOrgKeysNode != null && _secrets.RsaPrivateKeyDer != null)
                {
                    foreach (KeyValuePair<string, JsonNode?> kvp in encOrgKeysNode)
                    {
                        string? orgKeyCipher = kvp.Value?.GetValue<string>();

                        if (orgKeyCipher == null)
                        {
                            continue;
                        }

                        byte[]? decryptedOrgKey = DecryptRSA(orgKeyCipher, _secrets.RsaPrivateKeyDer);

                        if (decryptedOrgKey == null)
                        {
                            continue;
                        }

                        _secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
                    }
                }
            }


            if ((_options.FileFormat == "NEW" ? accountNode["data"] : accountNode) is not JsonObject dataContainerNode)
            {
                Console.Error.WriteLine("ERROR: Data container not found in JSON.");
                Environment.Exit(1);

                return null;
            }

            foreach (KeyValuePair<string, JsonNode?> groupKvp in dataContainerNode)
            {
                string groupKeyOriginal = groupKvp.Key;
                string outputKey = groupKeyOriginal.Contains('_') 
                    ? groupKeyOriginal[..groupKeyOriginal.IndexOf('_')] 
                    : groupKeyOriginal;
                outputKey = outputKey.Replace("ciphers", "items");

                if (groupKeyOriginal == "sends" && !_options.IncludeSends)
                {
                    continue;
                }

                if (outputKey == "sends" && !_options.IncludeSends && groupKeyOriginal.StartsWith("sends_"))
                {
                    continue;
                }

                string[] supportedOutputKeys = ["folders", "items", "collections", "organizations", "sends"];
                
                if (!supportedOutputKeys.Contains(outputKey))
                {
                    continue;
                }

                JsonNode? actualDataNode = groupKvp.Value;
                
                if (_options.FileFormat == "NEW" && outputKey != "organizations" && outputKey != "sends" && groupKvp.Value?["encrypted"] != null)
                {
                    actualDataNode = groupKvp.Value["encrypted"];
                }

                if (actualDataNode == null || actualDataNode is not JsonObject groupDataObj)
                {
                    continue;
                }

                JsonArray itemsArray = [];
                
                foreach (KeyValuePair<string, JsonNode?> itemKvp in groupDataObj)
                {
                    if (itemKvp.Value is not JsonObject itemObj)
                    {
                        continue;
                    }

                    if (outputKey == "sends")
                    {
                        itemsArray.Add(DecryptSend(itemObj.DeepClone()));
                    }
                    else
                    {
                        itemsArray.Add(ProcessGroupItem(itemObj.DeepClone(), outputKey, accountNode));
                    }
                }

                decryptedEntries[outputKey] = itemsArray;
            }
        }

        JsonObject finalOutputObject = [];

        if (decryptedEntries.ContainsKey("folders"))
        {
            finalOutputObject["folders"] = decryptedEntries["folders"]!.DeepClone();
        }

        foreach (KeyValuePair<string, JsonNode?> prop in decryptedEntries)
        {
            if (prop.Key == "folders" || prop.Key == "sends")
            {
                continue;
            }

            finalOutputObject[prop.Key] = prop.Value!.DeepClone();
        }

        if (decryptedEntries.ContainsKey("sends"))
        {
            finalOutputObject["sends"] = decryptedEntries["sends"]!.DeepClone();
        }

        return finalOutputObject.ToJsonString(new()
        { 
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
    }
}