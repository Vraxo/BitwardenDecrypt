namespace BitwardenDecryptor.Tests;

internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory()
    {
        DirectoryPath = Path.Combine(Path.GetTempPath(), $"BitwardenDecrypt.Tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(DirectoryPath);
    }

    public string DirectoryPath { get; }

    public string FilePath(string filename)
    {
        return Path.Combine(DirectoryPath, filename);
    }

    public void Dispose()
    {
        if (Directory.Exists(DirectoryPath))
        {
            Directory.Delete(DirectoryPath, recursive: true);
        }
    }
}
