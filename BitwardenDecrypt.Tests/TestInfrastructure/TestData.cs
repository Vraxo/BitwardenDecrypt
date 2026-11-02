namespace BitwardenDecryptor.Tests;

internal static class TestData
{
    public const string Password = "test password";
    public const string Email = "user@example.com";
    public const int Pbkdf2Iterations = 1000;

    public static byte[] Key(byte seed, int length = 32)
    {
        return [.. Enumerable.Range(0, length).Select(index => (byte)(seed + index))];
    }
}
