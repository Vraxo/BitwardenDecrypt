using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class VaultItemDecryptor
{
    private readonly BitwardenSecrets _secrets;
    private readonly GenericJsonDecryptor _genericDecryptor;
    private readonly IProtectedKeyDecryptor _protectedKeyDecryptor;

    public VaultItemDecryptor(BitwardenSecrets secrets, IProtectedKeyDecryptor protectedKeyDecryptor)
    {
        _secrets = secrets;
        _protectedKeyDecryptor = protectedKeyDecryptor;
        _genericDecryptor = new GenericJsonDecryptor(secrets, protectedKeyDecryptor);
    }

    public void DecryptAndStoreOrganizationKeys(JsonObject? orgKeysNode)
    {
        if (orgKeysNode is null || _secrets.RsaPrivateKeyDer is null)
        {
            return;
        }

        foreach (KeyValuePair<string, JsonNode?> kvp in orgKeysNode)
        {
            string? orgKeyCipher = kvp.Value?["key"]?.GetValue<string>() ?? kvp.Value?.GetValue<string>();

            if (orgKeyCipher is null)
            {
                continue;
            }

            byte[]? decryptedOrgKey = DecryptRsaInternal(orgKeyCipher);

            if (decryptedOrgKey is null)
            {
                continue;
            }

            _secrets.OrganizationKeys[kvp.Key] = decryptedOrgKey;
        }
    }

    public string DecryptCipherString(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        return _genericDecryptor.DecryptCipherString(cipherString, encryptionKey, macKey);
    }

    public byte[]? DecryptRsaInternal(string cipherString)
    {
        if (_secrets.RsaPrivateKeyDer is null)
        {
            return null;
        }

        (byte[]? ciphertext, string? error) = ParseAndDecodeRsaCipher(cipherString);

        return error is not null 
            ? null 
            : CryptoService.DecryptRsaOaepSha1(_secrets.RsaPrivateKeyDer, ciphertext!);
    }

    public JsonNode? DecryptSend(JsonNode sendNode)
    {
        string? keyCipherString = sendNode["key"]?.GetValue<string>();

        if (keyCipherString is null)
        {
            return sendNode;
        }

        (byte[] encKey, byte[] macKey, byte[] fullKey)? derivedKeys = DecryptAndDeriveSendKeys(keyCipherString);
        if (derivedKeys is null)
        {
            sendNode["key"] = "ERROR: Failed to decrypt or derive Send key.";
            return sendNode;
        }

        if (sendNode is JsonObject obj)
        {
            obj["key"] = BitConverter.ToString(derivedKeys.Value.fullKey).Replace("-", "").ToLowerInvariant();
        }

        return _genericDecryptor.DecryptAllCiphersInNode(sendNode, derivedKeys.Value.encKey, derivedKeys.Value.macKey);
    }

    public JsonObject ProcessGroupItem(JsonNode groupItemNode)
    {
        (byte[] itemEncKey, byte[] itemMacKey) = GetDecryptionKeysForItem(groupItemNode);
        JsonNode decryptedNode = _genericDecryptor.DecryptAllCiphersInNode(groupItemNode, itemEncKey, itemMacKey)!;
        JsonObject processedNode = decryptedNode.AsObject();
        
        RemoveUserSpecificFields(processedNode);

        return processedNode;
    }

    private static (byte[]? Ciphertext, string? Error) ParseAndDecodeRsaCipher(string cipherString)
    {
        string[] parts = cipherString.Split('.');
        
        if (parts.Length < 2)
        {
            return (null, "Invalid RSA CipherString format");
        }

        string[] dataParts = parts[1].Split('|');
        
        if (dataParts.Length < 1)
        {
            return (null, "Invalid RSA CipherString data part");
        }

        try
        {
            byte[] ciphertext = Convert.FromBase64String(dataParts[0]);
            return (ciphertext, null);
        }
        catch (FormatException ex)
        {
            return (null, $"Base64 decoding failed for RSA ciphertext: {ex.Message}");
        }
    }

    private (byte[] encKey, byte[] macKey, byte[] fullKey)? DecryptAndDeriveSendKeys(string keyCipherString)
    {
        if (_secrets.GeneratedEncryptionKey.Length == 0 || _secrets.GeneratedMacKey.Length == 0)
        {
            return null;
        }

        SymmetricKeyDecryptionResult sendKeyResult = _protectedKeyDecryptor.DecryptSymmetricKey(keyCipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);

        if (sendKeyResult.Error is not null || sendKeyResult.FullKey is null)
        {
            return null;
        }

        byte[] salt = Encoding.UTF8.GetBytes("bitwarden-send");
        byte[] info = Encoding.UTF8.GetBytes("send");
        byte[] derivedSendKeyMaterial = HKDF.DeriveKey(HashAlgorithmName.SHA256, sendKeyResult.FullKey, 64, salt, info);

        byte[] sendEncKey = derivedSendKeyMaterial.Take(32).ToArray();
        byte[] sendMacKey = derivedSendKeyMaterial.Skip(32).Take(32).ToArray();

        return (sendEncKey, sendMacKey, derivedSendKeyMaterial);
    }

    private (byte[] encKey, byte[] macKey) GetDecryptionKeysForItem(JsonNode itemNode)
    {
        string? orgId = itemNode["organizationId"]?.GetValue<string>();
        (byte[] baseEncKey, byte[] baseMacKey) = GetBaseKeysForItem(orgId);

        string? individualItemKeyCipherString = itemNode["key"]?.GetValue<string>();
        
        if (string.IsNullOrEmpty(individualItemKeyCipherString))
        {
            return (baseEncKey, baseMacKey);
        }

        SymmetricKeyDecryptionResult itemKeyResult = _protectedKeyDecryptor.DecryptSymmetricKey(individualItemKeyCipherString, baseEncKey, baseMacKey);

        if (itemKeyResult.Error is null && itemKeyResult.EncKey is not null && itemKeyResult.MacKey is not null)
        {
            if (itemNode is JsonObject obj)
            {
                obj["key"] = "";
            }

            return (itemKeyResult.EncKey, itemKeyResult.MacKey);
        }
        else if (itemKeyResult.Error is not null && itemNode is JsonObject obj)
        {
            obj["key"] = $"ERROR: Could not decrypt item key. {itemKeyResult.Error}";
        }

        return (baseEncKey, baseMacKey);
    }

    private (byte[] encKey, byte[] macKey) GetBaseKeysForItem(string? orgId)
    {
        if (orgId is not null && _secrets.OrganizationKeys.TryGetValue(orgId, out byte[]? orgFullKey) && orgFullKey?.Length >= 64)
        {
            return (orgFullKey.Take(32).ToArray(), orgFullKey.Skip(32).Take(32).ToArray());
        }

        if (_secrets.GeneratedEncryptionKey.Length > 0 && _secrets.GeneratedMacKey.Length > 0)
        {
            return (_secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);
        }

        return (_secrets.StretchedEncryptionKey, _secrets.StretchedMacKey);
    }

    private static void RemoveUserSpecificFields(JsonObject processedNode)
    {
        string[] userIdKeys = ["userId", "organizationUserId"];

        foreach (string key in userIdKeys)
        {
            if (!processedNode.ContainsKey(key))
            {
                continue;
            }

            _ = processedNode.Remove(key);
        }
    }
}