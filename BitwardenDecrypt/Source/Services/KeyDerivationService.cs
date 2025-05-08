using System;
using System.Text;
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class KeyDerivationService
{
    public static BitwardenSecrets DeriveKeys(VaultFileParseResult parseResult, string password, string fileFormat)
    {
        var secrets = new BitwardenSecrets
        {
            Email = parseResult.EmailOrSalt,
            MasterPasswordBytes = Encoding.UTF8.GetBytes(password),
            KdfIterations = parseResult.KdfIterations,
            KdfMemory = parseResult.KdfMemory,
            KdfParallelism = parseResult.KdfParallelism,
            KdfType = parseResult.KdfType,
            ProtectedSymmetricKeyCipherString = parseResult.ProtectedSymmetricKeyOrValidation,
            ProtectedRsaPrivateKeyCipherString = parseResult.EncPrivateKeyCipher
        };

        byte[] kdfSaltInput;

        if (fileFormat == "EncryptedJSON")
        {
            kdfSaltInput = Encoding.UTF8.GetBytes(parseResult.EmailOrSalt);
        }
        else
        {
            kdfSaltInput = Encoding.UTF8.GetBytes(secrets.Email);
        }

        if (secrets.KdfType == 1)
        {
            if (!secrets.KdfMemory.HasValue || !secrets.KdfParallelism.HasValue)
            {
                Console.Error.WriteLine("ERROR: KDF memory or parallelism not set for Argon2id.");
                Environment.Exit(1);
            }

            byte[] argonSalt = CryptoService.Sha256Hash(Encoding.UTF8.GetBytes(secrets.Email));
            secrets.MasterKey = CryptoService.DeriveArgon2id(
                secrets.MasterPasswordBytes,
                argonSalt,
                secrets.KdfIterations,
                secrets.KdfMemory.Value * 1024,
                secrets.KdfParallelism.Value,
                32);
        }
        else
        {
            secrets.MasterKey = CryptoService.DerivePbkdf2Sha256(
               secrets.MasterPasswordBytes,
               kdfSaltInput,
               secrets.KdfIterations,
               32);
        }

        byte[] masterPasswordHashDerived = CryptoService.DerivePbkdf2Sha256(secrets.MasterKey, secrets.MasterPasswordBytes, 1, 32);
        secrets.MasterPasswordHash = Convert.ToBase64String(masterPasswordHashDerived);

        secrets.StretchedEncryptionKey = CryptoService.HkdfExpandSha256(secrets.MasterKey, Encoding.UTF8.GetBytes("enc"), 32);
        secrets.StretchedMacKey = CryptoService.HkdfExpandSha256(secrets.MasterKey, Encoding.UTF8.GetBytes("mac"), 32);

        bool isForExportValidation = fileFormat == "EncryptedJSON";
        (var symKey, var symEncKey, var symMacKey, var error) = ProtectedKeyDecryptor.DecryptSymmetricKey(
            secrets.ProtectedSymmetricKeyCipherString,
            secrets.StretchedEncryptionKey,
            secrets.StretchedMacKey,
            isForExportValidation);

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

        secrets.GeneratedSymmetricKey = symKey;
        secrets.GeneratedEncryptionKey = symEncKey ?? [];
        secrets.GeneratedMacKey = symMacKey ?? [];

        if (string.IsNullOrEmpty(secrets.ProtectedRsaPrivateKeyCipherString))
        {
            return secrets;
        }

        if (secrets.GeneratedEncryptionKey.Length == 0 || secrets.GeneratedMacKey.Length == 0)
        {
            Console.Error.WriteLine("ERROR: Cannot decrypt RSA private key because dependent symmetric keys were not properly derived.");
        }
        else
        {
            secrets.RsaPrivateKeyDer = ProtectedKeyDecryptor.DecryptRsaPrivateKeyBytes(secrets.ProtectedRsaPrivateKeyCipherString, secrets.GeneratedEncryptionKey, secrets.GeneratedMacKey);

            if (secrets.RsaPrivateKeyDer == null)
            {
                Console.Error.WriteLine("ERROR: Failed to decrypt RSA Private Key.");
            }
        }
        return secrets;
    }
}