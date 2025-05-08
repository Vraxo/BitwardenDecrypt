using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class VaultDataDecryptor
{
    private readonly BitwardenSecrets _secrets;
    private readonly CommandLineOptions _options;
    private static readonly Regex CipherStringRegex = new(@"\d.[^,]+|[^,]+=[^""]*", RegexOptions.Compiled);

    public VaultDataDecryptor(BitwardenSecrets secrets, CommandLineOptions options)
    {
        _secrets = secrets;
        _options = options;
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

            (var fallbackKeyBytes, _, _, var fallbackError) = ProtectedKeyDecryptor.DecryptSymmetricKey(cipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);

            if (fallbackError == null && fallbackKeyBytes != null)
            {
                return BitConverter.ToString(fallbackKeyBytes).Replace("-", "").ToLowerInvariant();
            }
            return $"ERROR Decrypting (UTF-8 decode failed, fallback also failed): {cipherString}";
        }
    }

    private static byte[]? DecryptRsaInternal(string cipherString, byte[] rsaPrivateKeyDer)
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

        (var sendKeyBytes, _, _, var error) = ProtectedKeyDecryptor.DecryptSymmetricKey(keyCipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);

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

    private JsonObject ProcessGroupItem(JsonNode groupItemNode)
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
            (_, var decryptedItemEncKey, var decryptedItemMacKey, var itemKeyError) = ProtectedKeyDecryptor.DecryptSymmetricKey(individualItemKeyCipherString, itemEncKey, itemMacKey);

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
            if (match == null) continue;
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

    public JsonObject DecryptVault(JsonNode rootNode)
    {
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
                    if (orgKeyCipher == null) continue;

                    byte[]? decryptedOrgKey = DecryptRsaInternal(orgKeyCipher, _secrets.RsaPrivateKeyDer);
                    if (decryptedOrgKey != null) _secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
                }
            }

            string[] groupsToProcess = ["folder_folders", "ciphers_ciphers", "collection_collections", "organizations_organizations"];

            foreach (string groupKey in groupsToProcess)
            {
                JsonObject? groupDataNode = rootNode[$"user_{_options.AccountUuid}_{groupKey}"]?.AsObject();
                if (groupDataNode == null) continue;

                JsonArray itemsArray = [];
                foreach (var itemKvp in groupDataNode)
                {
                    if (itemKvp.Value is JsonObject itemObj)
                    {
                        itemsArray.Add(ProcessGroupItem(itemObj.DeepClone()));
                    }
                    else if (itemKvp.Value is JsonArray itemArr)
                    {
                        foreach (JsonNode? node in itemArr)
                        {
                            if (node is not JsonObject obj)
                            {
                                continue;
                            }

                            itemsArray.Add(ProcessGroupItem(obj.DeepClone()));
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
                accountNode = rootNode[_options.AccountUuid!]!;
                JsonObject? orgKeysEncryptedNode = accountNode["keys"]?["organizationKeys"]?["encrypted"]?.AsObject();
                if (orgKeysEncryptedNode != null && _secrets.RsaPrivateKeyDer != null)
                {
                    foreach (KeyValuePair<string, JsonNode?> kvp in orgKeysEncryptedNode)
                    {
                        string? orgKeyCipher = kvp.Value?["key"]?.GetValue<string>() ?? kvp.Value?.GetValue<string>();
                        if (orgKeyCipher != null)
                        {
                            byte[]? decryptedOrgKey = DecryptRsaInternal(orgKeyCipher, _secrets.RsaPrivateKeyDer);
                            if (decryptedOrgKey != null) _secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
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
                        if (orgKeyCipher == null) continue;
                        byte[]? decryptedOrgKey = DecryptRsaInternal(orgKeyCipher, _secrets.RsaPrivateKeyDer);
                        if (decryptedOrgKey == null) continue;
                        _secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
                    }
                }
            }

            if ((_options.FileFormat == "NEW" ? accountNode["data"] : accountNode) is not JsonObject dataContainerNode)
            {
                Console.Error.WriteLine("ERROR: Data container not found in JSON.");
                Environment.Exit(1);
                return [];
            }

            foreach (KeyValuePair<string, JsonNode?> groupKvp in dataContainerNode)
            {
                string groupKeyOriginal = groupKvp.Key;
                string outputKey = groupKeyOriginal.Contains('_') ? groupKeyOriginal[..groupKeyOriginal.IndexOf('_')] : groupKeyOriginal;
                outputKey = outputKey.Replace("ciphers", "items");

                if (groupKeyOriginal == "sends" && !_options.IncludeSends) continue;
                if (outputKey == "sends" && !_options.IncludeSends && groupKeyOriginal.StartsWith("sends_")) continue;

                string[] supportedOutputKeys = ["folders", "items", "collections", "organizations", "sends"];
                if (!supportedOutputKeys.Contains(outputKey)) continue;

                JsonNode? actualDataNode = groupKvp.Value;
                if (_options.FileFormat == "NEW" && outputKey != "organizations" && outputKey != "sends" && groupKvp.Value?["encrypted"] != null)
                {
                    actualDataNode = groupKvp.Value["encrypted"];
                }

                if (actualDataNode == null || actualDataNode is not JsonObject groupDataObj) continue;

                JsonArray itemsArray = [];
                foreach (KeyValuePair<string, JsonNode?> itemKvp in groupDataObj)
                {
                    if (itemKvp.Value is not JsonObject itemObj) continue;
                    if (outputKey == "sends") itemsArray.Add(DecryptSend(itemObj.DeepClone()));
                    else itemsArray.Add(ProcessGroupItem(itemObj.DeepClone()));
                }
                decryptedEntries[outputKey] = itemsArray;
            }
        }
        return decryptedEntries;
    }
}