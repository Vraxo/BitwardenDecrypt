using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public interface IProtectedKeyDecryptor
{
    SymmetricKeyDecryptionResult DecryptSymmetricKey(string cipherString, byte[] masterKey, byte[] masterMacKey, bool isExportValidationKey = false);
    byte[]? DecryptRsaPrivateKeyBytes(string cipherString, byte[] encryptionKey, byte[] macKey);
}