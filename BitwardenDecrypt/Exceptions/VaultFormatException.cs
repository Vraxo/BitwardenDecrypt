namespace BitwardenDecryptor.Exceptions;

public class VaultFormatException : Exception
{
    public VaultFormatException(string message)
        : base(message)
    {
    }

    public VaultFormatException(string message, Exception inner)
        : base(message, inner)
    {
    }
}