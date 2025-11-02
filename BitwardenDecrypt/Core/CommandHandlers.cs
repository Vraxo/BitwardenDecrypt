namespace BitwardenDecryptor.Core;

public class DecryptionHandler
{
    private readonly DecryptionOrchestrator _orchestrator;
    private readonly VaultFileHandler _fileHandler;

    public DecryptionHandler(DecryptionOrchestrator orchestrator, VaultFileHandler fileHandler)
    {
        _orchestrator = orchestrator;
        _fileHandler = fileHandler;
    }

    public void Execute(string inputFile, bool includeSends, string? outputFile, bool save)
    {
        try
        {
            string? finalOutputFile = _fileHandler.DetermineOutputFile(inputFile, outputFile, save);
            _orchestrator.RunDecryption(inputFile, includeSends, finalOutputFile);
        }
        catch (Exception ex)
        {
            ConsoleExceptionHandler.Handle(ex, inputFile);
            Environment.ExitCode = 1;
        }
    }
}