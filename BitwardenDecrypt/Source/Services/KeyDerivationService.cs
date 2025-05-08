﻿using System.Text;
using BitwardenDecryptor.Crypto;
using BitwardenDecryptor.Models;

namespace BitwardenDecryptor.Core;

public class KeyDerivationService
{
    public static BitwardenSecrets DeriveKeys(VaultFileParseResult parseResult, string password, string fileFormat)
    {
        BitwardenSecrets secrets = InitializeSecrets(parseResult, password);
        byte[] kdfSaltInput = DetermineKdfSaltInput(fileFormat, parseResult, secrets.Email);

        DeriveMasterKey(secrets, kdfSaltInput);
        DeriveMasterPasswordHash(secrets);
        DeriveStretchedKeys(secrets);
        DecryptAndSetSymmetricKeys(secrets, fileFormat);
        DecryptAndSetRsaPrivateKey(secrets);

        return secrets;
    }

    private static BitwardenSecrets InitializeSecrets(VaultFileParseResult parseResult, string password)
    {
        return new()
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
    }

    private static byte[] DetermineKdfSaltInput(string fileFormat, VaultFileParseResult parseResult, string email)
    {
        return fileFormat == "EncryptedJSON"
            ? Encoding.UTF8.GetBytes(parseResult.EmailOrSalt)
            : Encoding.UTF8.GetBytes(email);
    }

    private static void DeriveMasterKey(BitwardenSecrets secrets, byte[] kdfSaltInput)
    {
        if (secrets.KdfType == 1) // Argon2id
        {
            DeriveMasterKeyWithArgon2id(secrets);
        }
        else // PBKDF2
        {
            DeriveMasterKeyWithPbkdf2(secrets, kdfSaltInput);
        }
    }

    private static void DeriveMasterKeyWithArgon2id(BitwardenSecrets secrets)
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
            secrets.KdfMemory.Value * 1024, // KDFMemory is in KiB, Argon2 expects bytes
            secrets.KdfParallelism.Value,
            32); // 32 bytes for master key
    }

    private static void DeriveMasterKeyWithPbkdf2(BitwardenSecrets secrets, byte[] kdfSaltInput)
    {
        secrets.MasterKey = CryptoService.DerivePbkdf2Sha256(
           secrets.MasterPasswordBytes,
           kdfSaltInput,
           secrets.KdfIterations,
           32); // 32 bytes for master key
    }

    private static void DeriveMasterPasswordHash(BitwardenSecrets secrets)
    {
        byte[] masterPasswordHashDerived = CryptoService.DerivePbkdf2Sha256(secrets.MasterKey, secrets.MasterPasswordBytes, 1, 32);
        secrets.MasterPasswordHash = Convert.ToBase64String(masterPasswordHashDerived);
    }

    private static void DeriveStretchedKeys(BitwardenSecrets secrets)
    {
        secrets.StretchedEncryptionKey = CryptoService.HkdfExpandSha256(secrets.MasterKey, Encoding.UTF8.GetBytes("enc"), 32);
        secrets.StretchedMacKey = CryptoService.HkdfExpandSha256(secrets.MasterKey, Encoding.UTF8.GetBytes("mac"), 32);
    }

    private static void DecryptAndSetSymmetricKeys(BitwardenSecrets secrets, string fileFormat)
    {
        bool isForExportValidation = fileFormat == "EncryptedJSON";
        (byte[]? symKey, byte[]? symEncKey, byte[]? symMacKey, string? error) = ProtectedKeyDecryptor.DecryptSymmetricKey(
            secrets.ProtectedSymmetricKeyCipherString,
            secrets.StretchedEncryptionKey,
            secrets.StretchedMacKey,
            isForExportValidation);

        HandleSymmetricKeyDecryptionResult(error, symKey);

        // At this point, symKey is guaranteed to be non-null if HandleSymmetricKeyDecryptionResult did not exit.
        secrets.GeneratedSymmetricKey = symKey!;
        secrets.GeneratedEncryptionKey = symEncKey ?? [];
        secrets.GeneratedMacKey = symMacKey ?? [];
    }

    private static void HandleSymmetricKeyDecryptionResult(string? error, byte[]? symKey)
    {
        if (error != null || symKey == null)
        {
            string errorMessageToDisplay = error ?? "Symmetric key is null after decryption without explicit error.";
            Console.Error.WriteLine($"ERROR: Failed to decrypt/validate Protected Symmetric Key or Export Validation Key. {errorMessageToDisplay}");

            if (error != null &&
                (error.Contains("MAC mismatch", StringComparison.OrdinalIgnoreCase) ||
                 error.Contains("padding", StringComparison.OrdinalIgnoreCase) ||
                 error.Contains("Likely wrong password", StringComparison.OrdinalIgnoreCase)))
            {
                Console.Error.WriteLine("This often indicates a wrong password (either Master Password for data.json or Export Password for encrypted exports).");
            }
            else if (symKey == null && error == null)
            {
                Console.Error.WriteLine("This might indicate an unexpected issue with the decrypted data structure or a problem not caught by specific error checks.");
            }

            Environment.Exit(1);
        }
    }

    private static void DecryptAndSetRsaPrivateKey(BitwardenSecrets secrets)
    {
        if (string.IsNullOrEmpty(secrets.ProtectedRsaPrivateKeyCipherString))
        {
            return;
        }

        if (secrets.GeneratedEncryptionKey.Length == 0 || secrets.GeneratedMacKey.Length == 0)
        {
            Console.Error.WriteLine("ERROR: Cannot decrypt RSA private key because dependent symmetric keys were not properly derived.");
            return;
        }

        secrets.RsaPrivateKeyDer = ProtectedKeyDecryptor.DecryptRsaPrivateKeyBytes(
            secrets.ProtectedRsaPrivateKeyCipherString,
            secrets.GeneratedEncryptionKey,
            secrets.GeneratedMacKey);

        if (secrets.RsaPrivateKeyDer is null)
        {
            Console.Error.WriteLine("ERROR: Failed to decrypt RSA Private Key.");
        }
    }
}