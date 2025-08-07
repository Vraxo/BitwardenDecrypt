using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class VaultItemDecryptor(BitwardenSecrets secrets)
{
    private static readonly Regex CipherStringRegex = new(@"\d.[^,]+|[^,]+=[^""]*", RegexOptions.Compiled);

    public string DecryptCipherString(string cipherString, byte[] encryptionKey, byte[] macKey)
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

        DecryptionResult decryptionResult = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);

        if (decryptionResult.Error != null || decryptionResult.Plaintext == null)
        {
            return $"ERROR: {decryptionResult.Error}. CipherString not decrypted: {cipherString}";
        }

        try
        {
            return Encoding.UTF8.GetString(decryptionResult.Plaintext);
        }
        catch (DecoderFallbackException)
        {
            if (secrets.GeneratedEncryptionKey.Length == 0 || secrets.GeneratedMacKey.Length == 0)
            {
                return $"ERROR Decrypting (UTF-8 decode failed, fallback keys unavailable): {cipherString}";
            }

            SymmetricKeyDecryptionResult fallbackResult = ProtectedKeyDecryptor.DecryptSymmetricKey(cipherString, secrets.GeneratedEncryptionKey, secrets.GeneratedMacKey);

            if (fallbackResult.Error is null && fallbackResult.FullKey is not null)
            {
                return BitConverter.ToString(fallbackResult.FullKey).Replace("-", "").ToLowerInvariant();
            }

            return $"ERROR Decrypting (UTF-8 decode failed, fallback also failed): {cipherString}";
        }
    }

    public byte[]? DecryptRsaInternal(string cipherString)
    {
        if (secrets.RsaPrivateKeyDer is null)
        {
            Console.Error.WriteLine($"Cannot decrypt RSA cipher string as private key is not available.");
            return null;
        }

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

        return CryptoService.DecryptRsaOaepSha1(secrets.RsaPrivateKeyDer, ciphertext);
    }

    public JsonNode? DecryptSend(JsonNode sendNode)
    {
        string? keyCipherString = sendNode["key"]?.GetValue<string>();

        if (keyCipherString is null)
        {
            return sendNode;
        }

        if (secrets.GeneratedEncryptionKey.Length == 0 || secrets.GeneratedMacKey.Length == 0)
        {
            Console.Error.WriteLine($"ERROR: Cannot decrypt Send key as user symmetric keys are not fully available.");
            sendNode["key"] = $"ERROR: Cannot decrypt Send key - user keys unavailable.";
            return sendNode;
        }

        SymmetricKeyDecryptionResult sendKeyResult = ProtectedKeyDecryptor.DecryptSymmetricKey(keyCipherString, secrets.GeneratedEncryptionKey, secrets.GeneratedMacKey);

        if (sendKeyResult.Error is not null || sendKeyResult.FullKey is null)
        {
            Console.Error.WriteLine($"Failed to decrypt Send key: {sendKeyResult.Error}");
            sendNode["key"] = $"ERROR: Failed to decrypt Send key - {sendKeyResult.Error}";
            return sendNode;
        }

        byte[] salt = Encoding.UTF8.GetBytes("bitwarden-send");
        byte[] info = Encoding.UTF8.GetBytes("send");
        byte[] derivedSendKeyMaterial = HKDF.DeriveKey(HashAlgorithmName.SHA256, sendKeyResult.FullKey, 64, salt, info);

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

    public JsonObject ProcessGroupItem(JsonNode groupItemNode)
    {
        string? orgId = groupItemNode["organizationId"]?.GetValue<string>();
        byte[] itemEncKey;
        byte[] itemMacKey;

        if (orgId != null && secrets.OrganizationKeys.TryGetValue(orgId, out byte[]? orgFullKey) && orgFullKey != null && orgFullKey.Length >= 64)
        {
            itemEncKey = orgFullKey.Take(32).ToArray();
            itemMacKey = orgFullKey.Skip(32).Take(32).ToArray();
        }
        else
        {
            if (secrets.GeneratedEncryptionKey.Length == 0 || secrets.GeneratedMacKey.Length == 0)
            {
                Console.Error.WriteLine($"Warning: User symmetric keys not fully available for item {groupItemNode["id"]?.GetValue<string>()}. Defaulting to stretched keys; decryption may fail for some fields.");
                itemEncKey = secrets.StretchedEncryptionKey;
                itemMacKey = secrets.StretchedMacKey;
            }
            else
            {
                itemEncKey = secrets.GeneratedEncryptionKey;
                itemMacKey = secrets.GeneratedMacKey;
            }
        }

        string? individualItemKeyCipherString = groupItemNode["key"]?.GetValue<string>();

        if (!string.IsNullOrEmpty(individualItemKeyCipherString))
        {
            SymmetricKeyDecryptionResult itemKeyResult = ProtectedKeyDecryptor.DecryptSymmetricKey(individualItemKeyCipherString, itemEncKey, itemMacKey);

            if (itemKeyResult.Error is null && itemKeyResult.EncKey is not null && itemKeyResult.MacKey is not null)
            {
                itemEncKey = itemKeyResult.EncKey;
                itemMacKey = itemKeyResult.MacKey;

                if (groupItemNode is JsonObject obj)
                {
                    obj["key"] = "";
                }
            }
            else if (itemKeyResult.Error is not null && groupItemNode is JsonObject obj)
            {
                obj["key"] = $"ERROR: Could not decrypt item key. {itemKeyResult.Error}";
            }
        }

        string itemJsonString = groupItemNode.ToJsonString();
        MatchCollection matches = CipherStringRegex.Matches(itemJsonString);

        foreach (Match? match in matches.Reverse())
        {
            if (match is null)
            {
                continue;
            }

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
}