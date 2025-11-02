using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;
using System.Text;
using System.Text.Json.Nodes;

namespace BitwardenDecryptor.Core;

public class GenericJsonDecryptor
{
    private readonly BitwardenSecrets _secrets;

    public GenericJsonDecryptor(BitwardenSecrets secrets)
    {
        _secrets = secrets;
    }

    public string DecryptCipherString(string cipherString, byte[] encryptionKey, byte[] macKey)
    {
        if (string.IsNullOrEmpty(cipherString))
        {
            return string.Empty;
        }

        if (!IsValidCipherStringFormat(cipherString))
        {
            return $"ERROR Decrypting: Invalid CipherString format {cipherString}";
        }

        DecryptionResult decryptionResult = CryptoService.VerifyAndDecryptAesCbc(encryptionKey, macKey, cipherString);
        if (decryptionResult.Error != null || decryptionResult.Plaintext == null)
        {
            return $"ERROR: {decryptionResult.Error}. CipherString not decrypted: {cipherString}";
        }

        return ProcessDecryptedPlaintext(decryptionResult.Plaintext, cipherString);
    }

    public JsonNode? DecryptAllCiphersInNode(JsonNode? node, byte[] encKey, byte[] macKey)
    {
        switch (node)
        {
            case null:
                return null;
            case JsonValue val when val.TryGetValue<string>(out var strValue) && IsPotentiallyCipherString(strValue):
                return JsonValue.Create(DecryptCipherString(strValue, encKey, macKey));
            case JsonObject obj:
                var newObj = new JsonObject();
                foreach (var prop in obj)
                {
                    newObj[prop.Key] = DecryptAllCiphersInNode(prop.Value, encKey, macKey);
                }
                return newObj;
            case JsonArray arr:
                var newArr = new JsonArray();
                foreach (var item in arr)
                {
                    newArr.Add(DecryptAllCiphersInNode(item, encKey, macKey));
                }
                return newArr;
            default:
                return node.DeepClone();
        }
    }

    private string ProcessDecryptedPlaintext(byte[] plaintext, string originalCipherString)
    {
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (DecoderFallbackException)
        {
            return AttemptFallbackDecryption(originalCipherString);
        }
    }

    private string AttemptFallbackDecryption(string cipherString)
    {
        if (_secrets.GeneratedEncryptionKey.Length == 0 || _secrets.GeneratedMacKey.Length == 0)
        {
            return $"ERROR Decrypting (UTF-8 decode failed, fallback keys unavailable): {cipherString}";
        }

        SymmetricKeyDecryptionResult fallbackResult = ProtectedKeyDecryptor.DecryptSymmetricKey(cipherString, _secrets.GeneratedEncryptionKey, _secrets.GeneratedMacKey);

        return fallbackResult.Error is null && fallbackResult.FullKey is not null
            ? BitConverter.ToString(fallbackResult.FullKey).Replace("-", "").ToLowerInvariant()
            : $"ERROR Decrypting (UTF-8 decode failed, fallback also failed): {cipherString}";
    }

    private static bool IsValidCipherStringFormat(string cipherString)
    {
        string[] parts = cipherString.Split('.');
        return parts.Length >= 2 && int.TryParse(parts[0], out _);
    }

    private static bool IsPotentiallyCipherString(string value)
    {
        return value.Length > 2 && char.IsDigit(value[0]) && value[1] == '.' && value.Contains('|');
    }
}