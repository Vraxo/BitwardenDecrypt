namespace BitwardenDecryptor;

public class CommandLineOptions
{
    public string InputFile { get; set; } = "data.json";
    public bool IncludeSends { get; set; } = false;
    public string? OutputFile { get; set; }

    public string AccountUuid { get; set; } = string.Empty;
    public string AccountEmail { get; set; } = string.Empty;
    public string FileFormat { get; set; } = string.Empty;
}