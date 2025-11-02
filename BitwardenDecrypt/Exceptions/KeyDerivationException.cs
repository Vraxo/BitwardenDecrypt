namespace BitwardenDecryptor.Exceptions;

public class KeyDerivationException : Exception
{
    public KeyDerivationException()
    {
    }

    public KeyDerivationException(string message)
        : base(message)
    {
    }

    public KeyDerivationException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
